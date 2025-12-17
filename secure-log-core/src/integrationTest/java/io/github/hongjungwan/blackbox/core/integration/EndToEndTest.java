package io.github.hongjungwan.blackbox.core.integration;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.internal.LogProcessor;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.security.LocalKeyManager;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.internal.ConsoleLogTransport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-End Integration Test
 * Tests the complete pipeline from log entry creation to Console (stdout) delivery
 */
@DisplayName("E2E 통합 테스트 (Console Output)")
class EndToEndTest {

    private Path tempDir;
    private LogProcessor processor;
    private ConsoleLogTransport transport;
    private SecureLogConfig config;
    private LogSerializer serializer;
    private ByteArrayOutputStream outputCapture;
    private PrintStream originalOut;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() throws Exception {
        tempDir = Files.createTempDirectory("e2e-test");
        outputCapture = new ByteArrayOutputStream();
        originalOut = System.out;
        objectMapper = new ObjectMapper();

        config = SecureLogConfig.builder()
                .piiMaskingEnabled(true)
                .encryptionEnabled(true)
                .integrityEnabled(true)
                .fallbackDirectory(tempDir.toString())
                .build();

        serializer = new LogSerializer();
        PrintStream captureStream = new PrintStream(outputCapture);
        transport = new ConsoleLogTransport(config, serializer, captureStream);

        PiiMasker piiMasker = new PiiMasker(config);
        LocalKeyManager keyManager = new LocalKeyManager(config);
        EnvelopeEncryption encryption = new EnvelopeEncryption(config, keyManager);
        MerkleChain merkleChain = new MerkleChain();

        processor = new LogProcessor(
                config,
                piiMasker,
                encryption,
                merkleChain,
                transport
        );
    }

    @AfterEach
    void tearDown() throws Exception {
        System.setOut(originalOut);
        if (transport != null) {
            transport.close();
        }
        if (tempDir != null) {
            Files.walk(tempDir)
                    .sorted((a, b) -> -a.compareTo(b))
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (Exception ignored) {
                        }
                    });
        }
    }

    @Nested
    @DisplayName("전체 파이프라인")
    class FullPipelineTests {

        @Test
        @DisplayName("로그 엔트리가 전체 파이프라인을 통과하여 Console로 출력되어야 한다")
        void shouldProcessAndOutputLogToConsole() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .traceId("trace-e2e-001")
                    .spanId("span-e2e-001")
                    .context(Map.of("userId", "user001", "region", "KR"))
                    .message("E2E test message")
                    .payload(Map.of("action", "login", "ip", "192.168.1.1"))
                    .build();

            // when
            processor.process(entry);

            // then
            String output = outputCapture.toString();
            assertThat(output).isNotEmpty();

            JsonNode json = objectMapper.readTree(output.trim());
            assertThat(json.has("timestamp")).isTrue();
            assertThat(json.has("level")).isTrue();
            assertThat(json.get("level").asText()).isEqualTo("INFO");
            assertThat(json.get("traceId").asText()).isEqualTo("trace-e2e-001");
            assertThat(json.get("spanId").asText()).isEqualTo("span-e2e-001");
        }

        @Test
        @DisplayName("민감정보가 마스킹된 후 출력되어야 한다")
        void shouldMaskSensitiveDataBeforeOutput() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Sensitive data test")
                    .payload(Map.of(
                            "rrn", "123456-1234567",
                            "password", "secretPassword123",
                            "credit_card", "1234-5678-9012-3456"
                    ))
                    .build();

            // when
            processor.process(entry);

            // then
            String output = outputCapture.toString();
            assertThat(output).isNotEmpty();

            // 원본 민감정보가 출력에 포함되지 않아야 함
            assertThat(output).doesNotContain("123456-1234567");
            assertThat(output).doesNotContain("secretPassword123");
            assertThat(output).doesNotContain("1234-5678-9012-3456");
        }

        @Test
        @DisplayName("무결성 필드가 추가되어야 한다")
        void shouldAddIntegrityField() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Integrity test")
                    .build();

            // when
            processor.process(entry);

            // then
            String output = outputCapture.toString();
            JsonNode json = objectMapper.readTree(output.trim());
            assertThat(json.has("integrity")).isTrue();
            assertThat(json.get("integrity").asText()).startsWith("sha256:");
        }

        @Test
        @DisplayName("암호화 필드가 추가되어야 한다")
        void shouldAddEncryptionFields() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Encryption test")
                    .payload(Map.of("secret", "data"))
                    .build();

            // when
            processor.process(entry);

            // then
            String output = outputCapture.toString();
            JsonNode json = objectMapper.readTree(output.trim());
            assertThat(json.has("encryptedDek")).isTrue();
        }
    }

    @Nested
    @DisplayName("대용량 처리")
    class HighVolumeTests {

        @Test
        @DisplayName("다수의 로그를 처리할 수 있어야 한다")
        void shouldHandleMultipleLogs() throws Exception {
            // given
            int logCount = 100;

            // when
            for (int i = 0; i < logCount; i++) {
                LogEntry entry = LogEntry.builder()
                        .timestamp(System.currentTimeMillis() + i)
                        .level("INFO")
                        .message("High volume test " + i)
                        .build();
                processor.process(entry);
            }

            // then
            String output = outputCapture.toString();
            String[] lines = output.trim().split("\n");
            assertThat(lines.length).isEqualTo(logCount);
        }
    }

    @Nested
    @DisplayName("분산 추적")
    class DistributedTracingTests {

        @Test
        @DisplayName("추적 컨텍스트가 보존되어야 한다")
        void shouldPreserveTracingContext() throws Exception {
            // given
            String traceId = "0af7651916cd43dd8448eb211c80319c";
            String spanId = "b7ad6b7169203331";

            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .traceId(traceId)
                    .spanId(spanId)
                    .message("Tracing test")
                    .build();

            // when
            processor.process(entry);

            // then
            String output = outputCapture.toString();
            JsonNode json = objectMapper.readTree(output.trim());

            assertThat(json.get("traceId").asText()).isEqualTo(traceId);
            assertThat(json.get("spanId").asText()).isEqualTo(spanId);
        }
    }

    @Nested
    @DisplayName("JSON 구조")
    class JsonStructureTests {

        @Test
        @DisplayName("출력이 유효한 JSON이어야 한다")
        void shouldOutputValidJson() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("WARN")
                    .message("JSON validation test")
                    .context(Map.of("key1", "value1", "key2", "value2"))
                    .build();

            // when
            processor.process(entry);

            // then
            String output = outputCapture.toString().trim();
            JsonNode json = objectMapper.readTree(output);  // 파싱 가능해야 함
            assertThat(json.isObject()).isTrue();
        }

        @Test
        @DisplayName("각 줄이 독립적인 JSON 객체여야 한다 (NDJSON)")
        void shouldOutputNdjsonFormat() throws Exception {
            // given & when
            for (int i = 0; i < 3; i++) {
                LogEntry entry = LogEntry.builder()
                        .timestamp(System.currentTimeMillis() + i)
                        .level("INFO")
                        .message("NDJSON test " + i)
                        .build();
                processor.process(entry);
            }

            // then
            String output = outputCapture.toString();
            String[] lines = output.trim().split("\n");
            assertThat(lines.length).isEqualTo(3);

            for (String line : lines) {
                JsonNode json = objectMapper.readTree(line);
                assertThat(json.isObject()).isTrue();
            }
        }
    }
}
