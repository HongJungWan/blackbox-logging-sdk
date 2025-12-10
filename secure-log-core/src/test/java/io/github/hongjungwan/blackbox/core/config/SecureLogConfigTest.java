package io.github.hongjungwan.blackbox.core.config;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SecureLogConfig 테스트")
class SecureLogConfigTest {

    @Nested
    @DisplayName("기본 설정")
    class DefaultConfigTests {

        @Test
        @DisplayName("기본 설정이 올바르게 적용되어야 한다")
        void shouldHaveCorrectDefaults() {
            // when
            SecureLogConfig config = SecureLogConfig.defaultConfig();

            // then
            assertThat(config.getMode()).isEqualTo(SecureLogConfig.LoggingMode.ASYNC);
            assertThat(config.getBufferSize()).isEqualTo(8192);
            assertThat(config.isPiiMaskingEnabled()).isTrue();
            assertThat(config.isEncryptionEnabled()).isTrue();
            assertThat(config.isIntegrityEnabled()).isTrue();
        }

        @Test
        @DisplayName("기본 PII 패턴이 포함되어야 한다")
        void shouldHaveDefaultPiiPatterns() {
            // when
            SecureLogConfig config = SecureLogConfig.defaultConfig();

            // then
            assertThat(config.getPiiPatterns()).containsExactly("rrn", "credit_card", "password", "ssn");
        }

        @Test
        @DisplayName("기본 Kafka 토픽이 설정되어야 한다")
        void shouldHaveDefaultKafkaTopic() {
            // when
            SecureLogConfig config = SecureLogConfig.defaultConfig();

            // then
            assertThat(config.getKafkaTopic()).isEqualTo("secure-hr-logs");
        }

        @Test
        @DisplayName("기본 폴백 디렉토리가 설정되어야 한다")
        void shouldHaveDefaultFallbackDirectory() {
            // when
            SecureLogConfig config = SecureLogConfig.defaultConfig();

            // then
            assertThat(config.getFallbackDirectory()).isEqualTo("logs/fallback");
        }
    }

    @Nested
    @DisplayName("Kafka 설정")
    class KafkaConfigTests {

        @Test
        @DisplayName("Kafka 기본 설정이 올바르게 적용되어야 한다")
        void shouldHaveCorrectKafkaDefaults() {
            // when
            SecureLogConfig config = SecureLogConfig.defaultConfig();

            // then
            assertThat(config.getKafkaRetries()).isEqualTo(3);
            assertThat(config.getKafkaAcks()).isEqualTo("all");
            assertThat(config.getKafkaBatchSize()).isEqualTo(16384);
            assertThat(config.getKafkaLingerMs()).isEqualTo(1);
            assertThat(config.getKafkaCompressionType()).isEqualTo("zstd");
            assertThat(config.getKafkaMaxBlockMs()).isEqualTo(5000);
            assertThat(config.getKafkaSecurityProtocol()).isEqualTo("PLAINTEXT");
        }

        @Test
        @DisplayName("Kafka 설정을 커스터마이징할 수 있어야 한다")
        void shouldAllowKafkaCustomization() {
            // when
            SecureLogConfig config = SecureLogConfig.builder()
                    .kafkaBootstrapServers("localhost:9092")
                    .kafkaTopic("custom-topic")
                    .kafkaAcks("1")
                    .kafkaBatchSize(32768)
                    .kafkaLingerMs(5)
                    .kafkaCompressionType("lz4")
                    .kafkaMaxBlockMs(10000)
                    .kafkaSecurityProtocol("SSL")
                    .build();

            // then
            assertThat(config.getKafkaBootstrapServers()).isEqualTo("localhost:9092");
            assertThat(config.getKafkaTopic()).isEqualTo("custom-topic");
            assertThat(config.getKafkaAcks()).isEqualTo("1");
            assertThat(config.getKafkaBatchSize()).isEqualTo(32768);
            assertThat(config.getKafkaLingerMs()).isEqualTo(5);
            assertThat(config.getKafkaCompressionType()).isEqualTo("lz4");
            assertThat(config.getKafkaMaxBlockMs()).isEqualTo(10000);
            assertThat(config.getKafkaSecurityProtocol()).isEqualTo("SSL");
        }
    }

    @Nested
    @DisplayName("프로덕션 설정")
    class ProductionConfigTests {

        @Test
        @DisplayName("프로덕션 설정이 올바르게 구성되어야 한다")
        void shouldCreateCorrectProductionConfig() {
            // when
            SecureLogConfig config = SecureLogConfig.productionConfig("kafka:9092");

            // then
            assertThat(config.getMode()).isEqualTo(SecureLogConfig.LoggingMode.ASYNC);
            assertThat(config.getKafkaBootstrapServers()).isEqualTo("kafka:9092");
            assertThat(config.getKafkaAcks()).isEqualTo("all");
            assertThat(config.getKafkaCompressionType()).isEqualTo("zstd");
            assertThat(config.isEncryptionEnabled()).isTrue();
            assertThat(config.isPiiMaskingEnabled()).isTrue();
            assertThat(config.isIntegrityEnabled()).isTrue();
        }
    }

    @Nested
    @DisplayName("빌더 패턴")
    class BuilderTests {

        @Test
        @DisplayName("모든 옵션을 비활성화할 수 있어야 한다")
        void shouldAllowDisablingAllOptions() {
            // when
            SecureLogConfig config = SecureLogConfig.builder()
                    .piiMaskingEnabled(false)
                    .encryptionEnabled(false)
                    .integrityEnabled(false)
                    .build();

            // then
            assertThat(config.isPiiMaskingEnabled()).isFalse();
            assertThat(config.isEncryptionEnabled()).isFalse();
            assertThat(config.isIntegrityEnabled()).isFalse();
        }

        @Test
        @DisplayName("커스텀 PII 패턴을 설정할 수 있어야 한다")
        void shouldAllowCustomPiiPatterns() {
            // when
            SecureLogConfig config = SecureLogConfig.builder()
                    .piiPatterns(List.of("custom_field", "another_field"))
                    .build();

            // then
            assertThat(config.getPiiPatterns()).containsExactly("custom_field", "another_field");
        }

        @Test
        @DisplayName("로깅 모드를 변경할 수 있어야 한다")
        void shouldAllowChangingLoggingMode() {
            // given/when
            SecureLogConfig syncConfig = SecureLogConfig.builder()
                    .mode(SecureLogConfig.LoggingMode.SYNC)
                    .build();
            SecureLogConfig fallbackConfig = SecureLogConfig.builder()
                    .mode(SecureLogConfig.LoggingMode.FALLBACK)
                    .build();

            // then
            assertThat(syncConfig.getMode()).isEqualTo(SecureLogConfig.LoggingMode.SYNC);
            assertThat(fallbackConfig.getMode()).isEqualTo(SecureLogConfig.LoggingMode.FALLBACK);
        }
    }
}
