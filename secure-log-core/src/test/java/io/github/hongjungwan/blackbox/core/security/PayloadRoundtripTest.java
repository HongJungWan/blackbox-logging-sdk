package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Payload 라운드트립 테스트")
class PayloadRoundtripTest {

    private EnvelopeEncryption encryption;

    @BeforeEach
    void setUp() {
        SecureLogConfig config = SecureLogConfig.builder()
                .build();
        LocalKeyManager keyManager = new LocalKeyManager(config);
        encryption = new EnvelopeEncryption(config, keyManager);
    }

    @Test
    @DisplayName("암호화-복호화 후 payload가 정확히 복원되어야 한다")
    void shouldRecoverPayloadAfterEncryptionDecryption() {
        // given
        Map<String, Object> originalPayload = Map.of(
            "secret", "value123",
            "amount", 1000,
            "nested", Map.of("inner", "data")
        );

        LogEntry original = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Test")
                .payload(originalPayload)
                .build();

        // when
        LogEntry encrypted = encryption.encrypt(original);
        LogEntry decrypted = encryption.decrypt(encrypted);

        // then
        System.out.println("Original payload: " + originalPayload);
        System.out.println("Decrypted payload: " + decrypted.getPayload());

        assertThat(decrypted.getPayload())
            .as("Payload should be recovered after encryption-decryption cycle")
            .isEqualTo(originalPayload);
    }
}
