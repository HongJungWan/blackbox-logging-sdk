package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EnvelopeEncryption 테스트")
class EnvelopeEncryptionTest {

    private EnvelopeEncryption encryption;
    private KmsClient kmsClient;

    @BeforeEach
    void setUp() {
        SecureLogConfig config = SecureLogConfig.builder()
                .kmsFallbackEnabled(true) // Use fallback KEK for testing
                .build();
        kmsClient = new KmsClient(config);
        encryption = new EnvelopeEncryption(config, kmsClient);
    }

    @Nested
    @DisplayName("암호화/복호화 라운드트립")
    class RoundTripTests {

        @Test
        @DisplayName("로그 엔트리를 암호화하고 복호화할 수 있어야 한다")
        void shouldEncryptAndDecryptEntry() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Sensitive data")
                    .payload(Map.of("secret", "value123", "amount", 1000))
                    .build();

            // when
            LogEntry encrypted = encryption.encrypt(original);
            LogEntry decrypted = encryption.decrypt(encrypted);

            // then
            assertThat(decrypted.getTimestamp()).isEqualTo(original.getTimestamp());
            assertThat(decrypted.getLevel()).isEqualTo(original.getLevel());
            assertThat(decrypted.getMessage()).isEqualTo(original.getMessage());
        }

        @Test
        @DisplayName("컨텍스트가 있는 엔트리도 처리할 수 있어야 한다")
        void shouldHandleEntryWithContext() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .traceId("trace-123")
                    .spanId("span-456")
                    .context(Map.of("userId", "user001"))
                    .message("User action")
                    .payload(Map.of("action", "login"))
                    .build();

            // when
            LogEntry encrypted = encryption.encrypt(original);
            LogEntry decrypted = encryption.decrypt(encrypted);

            // then
            assertThat(decrypted.getTraceId()).isEqualTo(original.getTraceId());
            assertThat(decrypted.getSpanId()).isEqualTo(original.getSpanId());
            assertThat(decrypted.getContext()).isEqualTo(original.getContext());
        }
    }

    @Nested
    @DisplayName("암호화 포맷")
    class EncryptionFormatTests {

        @Test
        @DisplayName("암호화된 페이로드는 Base64 인코딩되어야 한다")
        void shouldBase64EncodeEncryptedPayload() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test")
                    .payload(Map.of("data", "value"))
                    .build();

            // when
            LogEntry encrypted = encryption.encrypt(original);

            // then
            assertThat(encrypted.getPayload()).containsKey("encrypted");
            String encryptedPayload = (String) encrypted.getPayload().get("encrypted");

            // Should be valid Base64
            byte[] decoded = Base64.getDecoder().decode(encryptedPayload);
            assertThat(decoded.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("암호화된 DEK가 포함되어야 한다")
        void shouldIncludeEncryptedDek() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test")
                    .payload(Map.of("data", "value"))
                    .build();

            // when
            LogEntry encrypted = encryption.encrypt(original);

            // then
            assertThat(encrypted.getEncryptedDek()).isNotNull();
            assertThat(encrypted.getEncryptedDek()).isNotEmpty();

            // Should be valid Base64
            byte[] decoded = Base64.getDecoder().decode(encrypted.getEncryptedDek());
            assertThat(decoded.length).isGreaterThan(0);
        }
    }

    @Nested
    @DisplayName("IV 무작위성")
    class IvRandomnessTests {

        @Test
        @DisplayName("동일한 데이터를 암호화해도 다른 결과가 나와야 한다")
        void shouldProduceDifferentCiphertextsForSameData() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Same data")
                    .payload(Map.of("key", "value"))
                    .build();

            // when
            LogEntry encrypted1 = encryption.encrypt(original);
            LogEntry encrypted2 = encryption.encrypt(original);

            // then - different IV means different ciphertext
            String payload1 = (String) encrypted1.getPayload().get("encrypted");
            String payload2 = (String) encrypted2.getPayload().get("encrypted");
            assertThat(payload1).isNotEqualTo(payload2);
        }
    }

    @Nested
    @DisplayName("메타데이터 보존")
    class MetadataPreservationTests {

        @Test
        @DisplayName("암호화 시 메타데이터가 보존되어야 한다")
        void shouldPreserveMetadata() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(1234567890L)
                    .level("ERROR")
                    .traceId("trace-xyz")
                    .spanId("span-abc")
                    .context(Map.of("region", "KR"))
                    .message("Error occurred")
                    .payload(Map.of("error", "details"))
                    .integrity("sha256:existing")
                    .repeatCount(5)
                    .throwable("java.lang.Exception")
                    .build();

            // when
            LogEntry encrypted = encryption.encrypt(original);

            // then - metadata preserved
            assertThat(encrypted.getTimestamp()).isEqualTo(original.getTimestamp());
            assertThat(encrypted.getLevel()).isEqualTo(original.getLevel());
            assertThat(encrypted.getTraceId()).isEqualTo(original.getTraceId());
            assertThat(encrypted.getSpanId()).isEqualTo(original.getSpanId());
            assertThat(encrypted.getContext()).isEqualTo(original.getContext());
            assertThat(encrypted.getMessage()).isEqualTo(original.getMessage());
            assertThat(encrypted.getIntegrity()).isEqualTo(original.getIntegrity());
            assertThat(encrypted.getRepeatCount()).isEqualTo(original.getRepeatCount());
            assertThat(encrypted.getThrowable()).isEqualTo(original.getThrowable());
        }
    }

    @Nested
    @DisplayName("GCM 인증")
    class GcmAuthenticationTests {

        @Test
        @DisplayName("변조된 암호문은 복호화에 실패해야 한다")
        void shouldFailDecryptionForTamperedCiphertext() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test")
                    .payload(Map.of("data", "value"))
                    .build();

            LogEntry encrypted = encryption.encrypt(original);

            // Tamper with encrypted payload
            String encryptedPayload = (String) encrypted.getPayload().get("encrypted");
            byte[] decoded = Base64.getDecoder().decode(encryptedPayload);
            decoded[decoded.length - 1] ^= 0xFF; // Flip bits
            String tamperedPayload = Base64.getEncoder().encodeToString(decoded);

            LogEntry tampered = LogEntry.builder()
                    .timestamp(encrypted.getTimestamp())
                    .level(encrypted.getLevel())
                    .message(encrypted.getMessage())
                    .payload(Map.of("encrypted", tamperedPayload))
                    .encryptedDek(encrypted.getEncryptedDek())
                    .build();

            // when/then
            assertThatThrownBy(() -> encryption.decrypt(tampered))
                    .isInstanceOf(EnvelopeEncryption.EncryptionException.class);
        }
    }

    @Nested
    @DisplayName("null/빈 페이로드 처리")
    class NullPayloadTests {

        @Test
        @DisplayName("null 페이로드도 암호화할 수 있어야 한다")
        void shouldHandleNullPayload() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("No payload")
                    .payload(null)
                    .build();

            // when
            LogEntry encrypted = encryption.encrypt(original);

            // then
            assertThat(encrypted.getPayload()).containsKey("encrypted");
        }
    }
}
