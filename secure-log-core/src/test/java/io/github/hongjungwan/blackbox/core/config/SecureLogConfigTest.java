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
        @DisplayName("기본 폴백 디렉토리가 설정되어야 한다")
        void shouldHaveDefaultFallbackDirectory() {
            // when
            SecureLogConfig config = SecureLogConfig.defaultConfig();

            // then
            assertThat(config.getFallbackDirectory()).isEqualTo("logs/fallback");
        }
    }

    @Nested
    @DisplayName("프로덕션 설정")
    class ProductionConfigTests {

        @Test
        @DisplayName("프로덕션 설정이 올바르게 구성되어야 한다")
        void shouldCreateCorrectProductionConfig() {
            // when
            SecureLogConfig config = SecureLogConfig.productionConfig();

            // then
            assertThat(config.getMode()).isEqualTo(SecureLogConfig.LoggingMode.ASYNC);
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

        @Test
        @DisplayName("버퍼 크기와 소비자 스레드 수를 설정할 수 있어야 한다")
        void shouldAllowCustomBufferAndThreadSettings() {
            // when
            SecureLogConfig config = SecureLogConfig.builder()
                    .bufferSize(16384)
                    .consumerThreads(4)
                    .build();

            // then
            assertThat(config.getBufferSize()).isEqualTo(16384);
            assertThat(config.getConsumerThreads()).isEqualTo(4);
        }

        @Test
        @DisplayName("커스텀 폴백 디렉토리를 설정할 수 있어야 한다")
        void shouldAllowCustomFallbackDirectory() {
            // when
            SecureLogConfig config = SecureLogConfig.builder()
                    .fallbackDirectory("/custom/fallback/path")
                    .build();

            // then
            assertThat(config.getFallbackDirectory()).isEqualTo("/custom/fallback/path");
        }
    }
}
