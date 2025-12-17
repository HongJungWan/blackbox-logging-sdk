package io.github.hongjungwan.blackbox.core.transport;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.ConsoleLogTransport;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ConsoleLogTransport 테스트")
class ConsoleLogTransportTest {

    @TempDir
    Path tempDir;

    private ConsoleLogTransport transport;
    private ByteArrayOutputStream outputCapture;
    private ObjectMapper objectMapper;
    private SecureLogConfig config;

    @BeforeEach
    void setUp() {
        outputCapture = new ByteArrayOutputStream();
        objectMapper = new ObjectMapper();

        config = SecureLogConfig.builder()
                .fallbackDirectory(tempDir.toString())
                .build();

        transport = new ConsoleLogTransport(
                config,
                new LogSerializer(),
                new PrintStream(outputCapture)
        );
    }

    @AfterEach
    void tearDown() {
        if (transport != null) {
            transport.close();
        }
    }

    @Nested
    @DisplayName("JSON 출력")
    class JsonOutputTests {

        @Test
        @DisplayName("LogEntry를 유효한 JSON으로 출력해야 한다")
        void shouldOutputValidJson() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test message")
                    .build();

            // when
            transport.send(entry);

            // then
            String output = outputCapture.toString().trim();
            JsonNode json = objectMapper.readTree(output);
            assertThat(json.isObject()).isTrue();
            assertThat(json.get("level").asText()).isEqualTo("INFO");
            assertThat(json.get("message").asText()).isEqualTo("Test message");
        }

        @Test
        @DisplayName("모든 필드가 JSON에 포함되어야 한다")
        void shouldIncludeAllFieldsInJson() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(1234567890L)
                    .level("WARN")
                    .traceId("trace-123")
                    .spanId("span-456")
                    .message("Full entry test")
                    .context(Map.of("key1", "value1"))
                    .payload(Map.of("data", "payload"))
                    .integrity("sha256:abc")
                    .encryptedDek("encrypted-key")
                    .build();

            // when
            transport.send(entry);

            // then
            String output = outputCapture.toString().trim();
            JsonNode json = objectMapper.readTree(output);

            assertThat(json.get("timestamp").asLong()).isEqualTo(1234567890L);
            assertThat(json.get("level").asText()).isEqualTo("WARN");
            assertThat(json.get("traceId").asText()).isEqualTo("trace-123");
            assertThat(json.get("spanId").asText()).isEqualTo("span-456");
            assertThat(json.get("message").asText()).isEqualTo("Full entry test");
            assertThat(json.get("integrity").asText()).isEqualTo("sha256:abc");
            assertThat(json.get("encryptedDek").asText()).isEqualTo("encrypted-key");
        }

        @Test
        @DisplayName("여러 엔트리를 NDJSON 형식으로 출력해야 한다")
        void shouldOutputNdjsonFormat() throws Exception {
            // given
            int count = 5;

            // when
            for (int i = 0; i < count; i++) {
                LogEntry entry = LogEntry.builder()
                        .timestamp(System.currentTimeMillis() + i)
                        .level("INFO")
                        .message("Message " + i)
                        .build();
                transport.send(entry);
            }

            // then
            String output = outputCapture.toString();
            String[] lines = output.trim().split("\n");
            assertThat(lines.length).isEqualTo(count);

            for (String line : lines) {
                JsonNode json = objectMapper.readTree(line);
                assertThat(json.isObject()).isTrue();
            }
        }
    }

    @Nested
    @DisplayName("스레드 안전성")
    class ThreadSafetyTests {

        @Test
        @DisplayName("동시 출력 시 JSON이 섞이지 않아야 한다")
        void shouldNotMixJsonOutputOnConcurrentWrites() throws Exception {
            // given
            int threadCount = 10;
            int messagesPerThread = 100;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            // when
            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < messagesPerThread; i++) {
                            LogEntry entry = LogEntry.builder()
                                    .timestamp(System.currentTimeMillis())
                                    .level("INFO")
                                    .message("Thread-" + threadId + "-Message-" + i)
                                    .build();
                            transport.send(entry);
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await(30, TimeUnit.SECONDS);
            executor.shutdown();

            // then
            String output = outputCapture.toString();
            String[] lines = output.trim().split("\n");

            // 모든 라인이 유효한 JSON이어야 함
            int validJsonCount = 0;
            for (String line : lines) {
                if (!line.isBlank()) {
                    JsonNode json = objectMapper.readTree(line);
                    assertThat(json.isObject()).isTrue();
                    validJsonCount++;
                }
            }

            assertThat(validJsonCount).isEqualTo(threadCount * messagesPerThread);
        }
    }

    @Nested
    @DisplayName("Fallback 저장")
    class FallbackTests {

        @Test
        @DisplayName("sendToFallback 호출 시 파일이 생성되어야 한다")
        void shouldCreateFallbackFile() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("ERROR")
                    .message("Fallback test")
                    .build();

            // when
            transport.sendToFallback(entry);

            // then
            long fallbackFiles = Files.list(tempDir)
                    .filter(p -> p.toString().endsWith(".zst"))
                    .count();
            assertThat(fallbackFiles).isGreaterThan(0);
        }

        @Test
        @DisplayName("여러 Fallback 파일이 고유한 이름을 가져야 한다")
        void shouldCreateUniqueFallbackFiles() throws Exception {
            // given
            int count = 5;

            // when
            for (int i = 0; i < count; i++) {
                LogEntry entry = LogEntry.builder()
                        .timestamp(System.currentTimeMillis() + i)
                        .level("ERROR")
                        .message("Fallback " + i)
                        .build();
                transport.sendToFallback(entry);
            }

            // then
            long fallbackFiles = Files.list(tempDir)
                    .filter(p -> p.toString().endsWith(".zst"))
                    .count();
            assertThat(fallbackFiles).isEqualTo(count);
        }
    }

    @Nested
    @DisplayName("메트릭")
    class MetricsTests {

        @Test
        @DisplayName("전송 카운트가 정확해야 한다")
        void shouldTrackSentCount() {
            // given
            int count = 10;

            // when
            for (int i = 0; i < count; i++) {
                LogEntry entry = LogEntry.builder()
                        .timestamp(System.currentTimeMillis())
                        .level("INFO")
                        .message("Count test " + i)
                        .build();
                transport.send(entry);
            }

            // then
            assertThat(transport.getSentCount()).isEqualTo(count);
        }

        @Test
        @DisplayName("초기 에러 카운트는 0이어야 한다")
        void shouldHaveZeroInitialErrorCount() {
            assertThat(transport.getErrorCount()).isEqualTo(0);
        }
    }
}
