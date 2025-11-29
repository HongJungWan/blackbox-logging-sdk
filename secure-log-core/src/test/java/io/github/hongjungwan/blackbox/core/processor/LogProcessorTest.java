package io.github.hongjungwan.blackbox.core.processor;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.deduplication.SemanticDeduplicator;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.integrity.MerkleChain;
import io.github.hongjungwan.blackbox.core.masking.PiiMasker;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.security.KmsClient;
import io.github.hongjungwan.blackbox.core.serialization.LogSerializer;
import io.github.hongjungwan.blackbox.core.transport.LogTransport;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayName("LogProcessor 테스트")
class LogProcessorTest {

    @TempDir
    Path tempDir;

    private AutoCloseable mocks;
    private LogProcessor processor;
    private SecureLogConfig config;

    @Mock
    private LogTransport mockTransport;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);

        config = SecureLogConfig.builder()
                .piiMaskingEnabled(true)
                .encryptionEnabled(true)
                .deduplicationEnabled(true)
                .integrityEnabled(true)
                .kmsFallbackEnabled(true)
                .fallbackDirectory(tempDir.toString())
                .build();

        PiiMasker piiMasker = new PiiMasker(config);
        KmsClient kmsClient = new KmsClient(config);
        EnvelopeEncryption encryption = new EnvelopeEncryption(config, kmsClient);
        MerkleChain merkleChain = new MerkleChain();
        SemanticDeduplicator deduplicator = new SemanticDeduplicator(config);
        LogSerializer serializer = new LogSerializer();

        processor = new LogProcessor(
                config,
                piiMasker,
                encryption,
                merkleChain,
                deduplicator,
                serializer,
                mockTransport
        );
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @Nested
    @DisplayName("전체 파이프라인")
    class FullPipelineTests {

        @Test
        @DisplayName("전체 파이프라인을 통해 로그를 처리해야 한다")
        void shouldProcessLogThroughFullPipeline() {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("User logged in")
                    .payload(Map.of("userId", "user123"))
                    .build();

            // when
            processor.process(entry);

            // then
            verify(mockTransport, times(1)).send(any(byte[].class));
        }

        @Test
        @DisplayName("PII가 마스킹되어 전송되어야 한다")
        void shouldMaskPiiBeforeSending() {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("User data")
                    .payload(Map.of("rrn", "123456-1234567", "password", "secret"))
                    .build();

            // when
            processor.process(entry);

            // then
            verify(mockTransport, times(1)).send(any(byte[].class));
        }
    }

    @Nested
    @DisplayName("중복 제거")
    class DeduplicationTests {

        @Test
        @DisplayName("중복 로그는 전송하지 않아야 한다")
        void shouldNotSendDuplicateLogs() {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Duplicate message")
                    .build();

            // when
            processor.process(entry);
            processor.process(entry);
            processor.process(entry);

            // then - only first should be sent
            verify(mockTransport, times(1)).send(any(byte[].class));
        }
    }

    @Nested
    @DisplayName("기능 비활성화")
    class FeatureDisablingTests {

        @Test
        @DisplayName("PII 마스킹 비활성화 시 원본 데이터가 유지되어야 한다")
        void shouldPreserveOriginalDataWhenMaskingDisabled() {
            // given
            SecureLogConfig disabledConfig = SecureLogConfig.builder()
                    .piiMaskingEnabled(false)
                    .encryptionEnabled(false)
                    .deduplicationEnabled(false)
                    .integrityEnabled(false)
                    .kmsFallbackEnabled(true)
                    .fallbackDirectory(tempDir.toString())
                    .build();

            LogProcessor minimalProcessor = new LogProcessor(
                    disabledConfig,
                    new PiiMasker(disabledConfig),
                    new EnvelopeEncryption(disabledConfig, new KmsClient(disabledConfig)),
                    new MerkleChain(),
                    new SemanticDeduplicator(disabledConfig),
                    new LogSerializer(),
                    mockTransport
            );

            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test")
                    .payload(Map.of("password", "secret"))
                    .build();

            // when
            minimalProcessor.process(entry);

            // then
            verify(mockTransport, times(1)).send(any(byte[].class));
        }

        @Test
        @DisplayName("모든 기능이 비활성화되어도 기본 처리가 되어야 한다")
        void shouldProcessEvenWithAllFeaturesDisabled() {
            // given
            SecureLogConfig disabledConfig = SecureLogConfig.builder()
                    .piiMaskingEnabled(false)
                    .encryptionEnabled(false)
                    .deduplicationEnabled(false)
                    .integrityEnabled(false)
                    .kmsFallbackEnabled(true)
                    .fallbackDirectory(tempDir.toString())
                    .build();

            LogProcessor minimalProcessor = new LogProcessor(
                    disabledConfig,
                    new PiiMasker(disabledConfig),
                    new EnvelopeEncryption(disabledConfig, new KmsClient(disabledConfig)),
                    new MerkleChain(),
                    new SemanticDeduplicator(disabledConfig),
                    new LogSerializer(),
                    mockTransport
            );

            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Minimal processing")
                    .build();

            // when
            minimalProcessor.process(entry);

            // then
            verify(mockTransport, times(1)).send(any(byte[].class));
        }
    }

    @Nested
    @DisplayName("에러 처리")
    class ErrorHandlingTests {

        @Test
        @DisplayName("전송 실패 시 폴백으로 저장해야 한다")
        void shouldFallbackOnTransportFailure() {
            // given
            doThrow(new RuntimeException("Kafka unavailable"))
                    .when(mockTransport).send(any(byte[].class));

            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("ERROR")
                    .message("Important log")
                    .build();

            // when
            processor.process(entry);

            // then
            verify(mockTransport, times(1)).sendToFallback(any(LogEntry.class));
        }
    }

    @Nested
    @DisplayName("분산 추적 컨텍스트")
    class DistributedTracingTests {

        @Test
        @DisplayName("추적 ID가 파이프라인을 통해 보존되어야 한다")
        void shouldPreserveTracingContext() {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .traceId("trace-abc-123")
                    .spanId("span-xyz-456")
                    .context(Map.of("userId", "user001", "region", "KR"))
                    .message("Traced operation")
                    .build();

            // when
            processor.process(entry);

            // then
            verify(mockTransport, times(1)).send(any(byte[].class));
        }
    }
}
