package io.github.hongjungwan.blackbox.core.security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

import static org.assertj.core.api.Assertions.*;

@DisplayName("EmergencyEncryptor 테스트")
class EmergencyEncryptorTest {

    private static KeyPair keyPair;
    private static String base64PublicKey;

    @BeforeAll
    static void setupKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
        base64PublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    @Nested
    @DisplayName("생성자 테스트")
    class ConstructorTest {

        @Test
        @DisplayName("공개키로 생성할 수 있어야 한다")
        void shouldCreateWithPublicKey() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            assertThat(encryptor).isNotNull();
            assertThat(encryptor.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("Base64 인코딩된 공개키로 생성할 수 있어야 한다")
        void shouldCreateFromBase64() {
            EmergencyEncryptor encryptor = EmergencyEncryptor.fromBase64(base64PublicKey);
            assertThat(encryptor).isNotNull();
        }

        @Test
        @DisplayName("null 공개키로 생성 시 예외가 발생해야 한다")
        void shouldThrowExceptionForNullKey() {
            assertThatThrownBy(() -> new EmergencyEncryptor(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Public key must not be null");
        }

        @Test
        @DisplayName("빈 Base64 문자열로 생성 시 예외가 발생해야 한다")
        void shouldThrowExceptionForEmptyBase64() {
            assertThatThrownBy(() -> EmergencyEncryptor.fromBase64(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Base64 public key must not be null or blank");
        }

        @Test
        @DisplayName("잘못된 Base64 문자열로 생성 시 예외가 발생해야 한다")
        void shouldThrowExceptionForInvalidBase64() {
            assertThatThrownBy(() -> EmergencyEncryptor.fromBase64("invalid-key"))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("Failed to parse public key");
        }
    }

    @Nested
    @DisplayName("암호화 테스트")
    class EncryptionTest {

        @Test
        @DisplayName("텍스트를 암호화할 수 있어야 한다")
        void shouldEncryptText() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            String plainText = "민감한 개인정보";

            String encrypted = encryptor.encrypt(plainText);

            assertThat(encrypted).isNotNull();
            assertThat(encrypted).isNotEqualTo(plainText);
            assertThat(encrypted).isNotEmpty();
        }

        @Test
        @DisplayName("암호화된 텍스트는 Base64 형식이어야 한다")
        void shouldReturnBase64EncodedResult() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            String encrypted = encryptor.encrypt("test");

            assertThatCode(() -> Base64.getDecoder().decode(encrypted))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("null 입력은 null을 반환해야 한다")
        void shouldReturnNullForNullInput() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            assertThat(encryptor.encrypt(null)).isNull();
        }

        @Test
        @DisplayName("빈 문자열은 빈 문자열을 반환해야 한다")
        void shouldReturnEmptyForEmptyInput() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            assertThat(encryptor.encrypt("")).isEmpty();
        }

        @Test
        @DisplayName("암호화된 결과는 개인키로 복호화할 수 있어야 한다")
        void shouldBeDecryptableWithPrivateKey() throws Exception {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            String plainText = "복호화 테스트 데이터";

            String encrypted = encryptor.encrypt(plainText);

            // 개인키로 복호화
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            assertThat(new String(decrypted)).isEqualTo(plainText);
        }

        @Test
        @DisplayName("한글 텍스트를 암호화/복호화할 수 있어야 한다")
        void shouldHandleKoreanText() throws Exception {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            String plainText = "홍길동의 주민등록번호: 123456-1234567";

            String encrypted = encryptor.encrypt(plainText);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            assertThat(new String(decrypted, java.nio.charset.StandardCharsets.UTF_8)).isEqualTo(plainText);
        }
    }

    @Nested
    @DisplayName("비상 모드 결과 테스트")
    class EmergencyModeResultTest {

        @Test
        @DisplayName("비상 모드 결과를 생성할 수 있어야 한다")
        void shouldCreateEmergencyResult() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            String original = "123456-1234567";
            String masked = "123456-*******";

            EmergencyEncryptor.EmergencyModeResult result =
                    encryptor.createEmergencyResult(original, masked);

            assertThat(result.display()).isEqualTo(masked);
            assertThat(result.encrypted()).isNotNull();
            assertThat(result.encrypted()).isNotEqualTo(original);
        }

        @Test
        @DisplayName("비상 모드 결과를 JSON으로 변환할 수 있어야 한다")
        void shouldConvertToJson() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());

            EmergencyEncryptor.EmergencyModeResult result =
                    encryptor.createEmergencyResult("original", "masked");
            String json = result.toJson();

            assertThat(json).contains("\"display\":\"masked\"");
            assertThat(json).contains("\"encrypted\":");
        }
    }

    @Nested
    @DisplayName("활성화 상태 테스트")
    class EnabledStateTest {

        @Test
        @DisplayName("기본 상태는 비활성화여야 한다")
        void shouldBeDisabledByDefault() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());
            assertThat(encryptor.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("활성화/비활성화 상태를 변경할 수 있어야 한다")
        void shouldToggleEnabledState() {
            EmergencyEncryptor encryptor = new EmergencyEncryptor(keyPair.getPublic());

            encryptor.setEnabled(true);
            assertThat(encryptor.isEnabled()).isTrue();

            encryptor.setEnabled(false);
            assertThat(encryptor.isEnabled()).isFalse();
        }
    }
}
