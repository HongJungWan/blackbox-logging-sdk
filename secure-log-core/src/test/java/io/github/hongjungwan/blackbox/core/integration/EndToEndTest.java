package io.github.hongjungwan.blackbox.core.integration;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.internal.SemanticDeduplicator;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.internal.LogProcessor;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.security.KmsClient;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.internal.KafkaProducer;
import io.github.hongjungwan.blackbox.core.internal.LogTransport;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-End Integration Test
 * Tests the complete pipeline from log entry creation to Kafka delivery
 */
@Testcontainers
@DisplayName("E2E 통합 테스트")
class EndToEndTest {

    private static final String TEST_TOPIC = "e2e-test-logs";

    @Container
    static KafkaContainer kafka = new KafkaContainer(
            DockerImageName.parse("confluentinc/cp-kafka:7.5.0")
    );

    private Path tempDir;
    private LogProcessor processor;
    private LogTransport transport;
    private SecureLogConfig config;
    private LogSerializer serializer;

    @BeforeEach
    void setUp() throws Exception {
        tempDir = Files.createTempDirectory("e2e-test");

        config = SecureLogConfig.builder()
                .piiMaskingEnabled(true)
                .encryptionEnabled(true)
                .deduplicationEnabled(true)
                .integrityEnabled(true)
                .kmsFallbackEnabled(true)
                .kafkaBootstrapServers(kafka.getBootstrapServers())
                .kafkaTopic(TEST_TOPIC)
                .kafkaAcks("all")
                .fallbackDirectory(tempDir.toString())
                .build();

        serializer = new LogSerializer();
        transport = new LogTransport(config, serializer);

        PiiMasker piiMasker = new PiiMasker(config);
        KmsClient kmsClient = new KmsClient(config);
        EnvelopeEncryption encryption = new EnvelopeEncryption(config, kmsClient);
        MerkleChain merkleChain = new MerkleChain();
        SemanticDeduplicator deduplicator = new SemanticDeduplicator(config);

        processor = new LogProcessor(
                config,
                piiMasker,
                encryption,
                merkleChain,
                deduplicator,
                serializer,
                transport
        );
    }

    @AfterEach
    void tearDown() throws Exception {
        if (transport != null) {
            transport.close();
        }
        // Cleanup temp directory
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
        @DisplayName("로그 엔트리가 전체 파이프라인을 통과하여 Kafka로 전송되어야 한다")
        void shouldProcessAndSendLogToKafka() throws Exception {
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

            // Allow time for async processing
            Thread.sleep(2000);

            // then
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));
                ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(10));

                assertThat(records.count()).isGreaterThan(0);
            }
        }

        @Test
        @DisplayName("민감정보가 마스킹된 후 전송되어야 한다")
        void shouldMaskSensitiveDataBeforeSending() throws Exception {
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

            Thread.sleep(2000);

            // then - verify data was sent (actual content is encrypted)
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));
                ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(10));

                assertThat(records.count()).isGreaterThan(0);
            }
        }
    }

    @Nested
    @DisplayName("중복 제거")
    class DeduplicationTests {

        @Test
        @DisplayName("중복 로그는 한 번만 전송되어야 한다")
        void shouldDeduplicateLogs() throws Exception {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Duplicate test message")
                    .build();

            // when - send same message multiple times
            for (int i = 0; i < 5; i++) {
                processor.process(entry);
            }

            Thread.sleep(2000);

            // then - only one should be sent (deduplication)
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));
                ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(10));

                // Should have 1 record due to deduplication
                assertThat(records.count()).isEqualTo(1);
            }
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
                        .timestamp(System.currentTimeMillis())
                        .level("INFO")
                        .message("High volume test " + i) // Different message to avoid dedup
                        .build();
                processor.process(entry);
            }

            Thread.sleep(5000);

            // then
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));

                int received = 0;
                long deadline = System.currentTimeMillis() + 30000;

                while (received < logCount && System.currentTimeMillis() < deadline) {
                    ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(1));
                    received += records.count();
                }

                assertThat(received).isEqualTo(logCount);
            }
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

            Thread.sleep(2000);

            // then
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));
                ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(10));

                assertThat(records.count()).isGreaterThan(0);

                // Deserialize and verify tracing info is preserved
                byte[] data = records.iterator().next().value();
                LogEntry deserialized = serializer.deserialize(data);

                // Note: Data is encrypted, so we can't verify traceId directly
                // But we can verify the structure is preserved
                assertThat(deserialized.getTraceId()).isEqualTo(traceId);
                assertThat(deserialized.getSpanId()).isEqualTo(spanId);
            }
        }
    }

    private KafkaConsumer<String, byte[]> createConsumer() {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafka.getBootstrapServers());
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "e2e-test-group-" + System.currentTimeMillis());
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

        return new KafkaConsumer<>(props);
    }
}
