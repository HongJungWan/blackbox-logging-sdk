package io.github.hongjungwan.blackbox.core.integration;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.transport.KafkaProducer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.Collections;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Kafka Integration Tests using Testcontainers
 */
@Testcontainers
@DisplayName("Kafka 통합 테스트")
class KafkaIntegrationTest {

    private static final String TEST_TOPIC = "test-secure-hr-logs";

    @Container
    static KafkaContainer kafka = new KafkaContainer(
            DockerImageName.parse("confluentinc/cp-kafka:7.5.0")
    );

    private KafkaProducer producer;
    private SecureLogConfig config;

    @BeforeEach
    void setUp() {
        config = SecureLogConfig.builder()
                .kafkaBootstrapServers(kafka.getBootstrapServers())
                .kafkaTopic(TEST_TOPIC)
                .kafkaAcks("all")
                .kafkaRetries(3)
                .kafkaBatchSize(16384)
                .kafkaLingerMs(1)
                .kafkaCompressionType("zstd")
                .kafkaMaxBlockMs(5000)
                .build();

        producer = new KafkaProducer(config);
    }

    @AfterEach
    void tearDown() {
        if (producer != null) {
            producer.close();
        }
    }

    @Nested
    @DisplayName("메시지 전송")
    class MessageSendingTests {

        @Test
        @DisplayName("Kafka에 메시지를 전송할 수 있어야 한다")
        void shouldSendMessageToKafka() throws Exception {
            // given
            byte[] testData = "Hello Kafka".getBytes();

            // when
            producer.send(TEST_TOPIC, testData).get(10, TimeUnit.SECONDS);

            // then - verify with consumer
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));
                ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(10));

                assertThat(records.count()).isGreaterThan(0);

                ConsumerRecord<String, byte[]> record = records.iterator().next();
                assertThat(record.value()).isEqualTo(testData);
            }
        }

        @Test
        @DisplayName("기본 토픽으로 메시지를 전송할 수 있어야 한다")
        void shouldSendToDefaultTopic() throws Exception {
            // given
            byte[] testData = "Default topic message".getBytes();

            // when
            producer.send(testData).get(10, TimeUnit.SECONDS);

            // then
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));
                ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(10));

                assertThat(records.count()).isGreaterThan(0);
            }
        }

        @Test
        @DisplayName("여러 메시지를 순차적으로 전송할 수 있어야 한다")
        void shouldSendMultipleMessages() throws Exception {
            // given
            int messageCount = 10;

            // when
            for (int i = 0; i < messageCount; i++) {
                byte[] data = ("Message " + i).getBytes();
                producer.send(TEST_TOPIC, data);
            }
            producer.flush();

            // then
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));

                int received = 0;
                long deadline = System.currentTimeMillis() + 30000;

                while (received < messageCount && System.currentTimeMillis() < deadline) {
                    ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(1));
                    received += records.count();
                }

                assertThat(received).isEqualTo(messageCount);
            }
        }
    }

    @Nested
    @DisplayName("압축 테스트")
    class CompressionTests {

        @Test
        @DisplayName("Zstd 압축된 메시지가 전송되어야 한다")
        void shouldSendZstdCompressedMessages() throws Exception {
            // given - large repetitive data that compresses well
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < 1000; i++) {
                builder.append("This is repetitive data for compression test. ");
            }
            byte[] testData = builder.toString().getBytes();

            // when
            producer.send(TEST_TOPIC, testData).get(10, TimeUnit.SECONDS);

            // then
            try (KafkaConsumer<String, byte[]> consumer = createConsumer()) {
                consumer.subscribe(Collections.singletonList(TEST_TOPIC));
                ConsumerRecords<String, byte[]> records = consumer.poll(Duration.ofSeconds(10));

                assertThat(records.count()).isGreaterThan(0);
                ConsumerRecord<String, byte[]> record = records.iterator().next();
                assertThat(record.value()).isEqualTo(testData);
            }
        }
    }

    @Nested
    @DisplayName("메트릭스")
    class MetricsTests {

        @Test
        @DisplayName("전송 카운트가 증가해야 한다")
        void shouldIncrementSentCount() throws Exception {
            // given
            byte[] testData = "Count test".getBytes();

            // when
            producer.send(TEST_TOPIC, testData).get(10, TimeUnit.SECONDS);
            producer.send(TEST_TOPIC, testData).get(10, TimeUnit.SECONDS);

            // then
            assertThat(producer.getSentCount()).isEqualTo(2);
        }
    }

    @Nested
    @DisplayName("연결 관리")
    class ConnectionManagementTests {

        @Test
        @DisplayName("close() 후 isClosed()가 true를 반환해야 한다")
        void shouldReportClosedState() {
            // given
            assertThat(producer.isClosed()).isFalse();

            // when
            producer.close();

            // then
            assertThat(producer.isClosed()).isTrue();
        }
    }

    private KafkaConsumer<String, byte[]> createConsumer() {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafka.getBootstrapServers());
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "test-group-" + System.currentTimeMillis());
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class.getName());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

        return new KafkaConsumer<>(props);
    }
}
