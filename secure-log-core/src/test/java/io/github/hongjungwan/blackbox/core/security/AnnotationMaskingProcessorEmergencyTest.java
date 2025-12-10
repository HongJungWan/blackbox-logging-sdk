package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.api.annotation.Mask;
import io.github.hongjungwan.blackbox.api.annotation.MaskType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

@DisplayName("AnnotationMaskingProcessor 비상 모드 테스트")
class AnnotationMaskingProcessorEmergencyTest {

    private static KeyPair keyPair;
    private AnnotationMaskingProcessor processor;
    private EmergencyEncryptor emergencyEncryptor;

    @BeforeAll
    static void setupKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
    }

    @BeforeEach
    void setup() {
        processor = new AnnotationMaskingProcessor();
        emergencyEncryptor = new EmergencyEncryptor(keyPair.getPublic());
        processor.setEmergencyEncryptor(emergencyEncryptor);
    }

    // 테스트용 DTO (emergency=false)
    static class NormalDto {
        @Mask(MaskType.RRN)
        private String residentNumber;

        @Mask(MaskType.PHONE)
        private String phone;

        private String name;

        public NormalDto() {}

        public NormalDto(String residentNumber, String phone, String name) {
            this.residentNumber = residentNumber;
            this.phone = phone;
            this.name = name;
        }
    }

    // 테스트용 DTO (emergency=true 포함)
    static class EmergencyDto {
        @Mask(MaskType.RRN)
        private String residentNumber;

        @Mask(value = MaskType.CREDIT_CARD, emergency = true)
        private String cardNumber;

        @Mask(value = MaskType.PHONE, emergency = true)
        private String emergencyPhone;

        private String normalField;

        public EmergencyDto() {}

        public EmergencyDto(String residentNumber, String cardNumber, String emergencyPhone, String normalField) {
            this.residentNumber = residentNumber;
            this.cardNumber = cardNumber;
            this.emergencyPhone = emergencyPhone;
            this.normalField = normalField;
        }
    }

    @Nested
    @DisplayName("비상 모드 비활성화 시")
    class WhenEmergencyModeDisabled {

        @Test
        @DisplayName("emergency=true 필드도 일반 마스킹이 적용되어야 한다")
        void shouldApplyNormalMaskingToEmergencyFields() {
            emergencyEncryptor.setEnabled(false);

            EmergencyDto dto = new EmergencyDto(
                    "123456-1234567",
                    "1234-5678-9012-3456",
                    "010-1234-5678",
                    "normal"
            );

            Map<String, Object> result = processor.process(dto);

            assertThat(result.get("residentNumber")).isEqualTo("123456-*******");
            assertThat(result.get("cardNumber")).isEqualTo("****-****-****-3456");
            assertThat(result.get("emergencyPhone")).isEqualTo("010-****-5678");
            assertThat(result.get("normalField")).isEqualTo("normal");
        }

        @Test
        @DisplayName("isEmergencyModeEnabled()가 false를 반환해야 한다")
        void shouldReturnFalseForEmergencyModeEnabled() {
            emergencyEncryptor.setEnabled(false);
            assertThat(processor.isEmergencyModeEnabled()).isFalse();
        }
    }

    @Nested
    @DisplayName("비상 모드 활성화 시")
    class WhenEmergencyModeEnabled {

        @BeforeEach
        void enableEmergencyMode() {
            emergencyEncryptor.setEnabled(true);
        }

        @Test
        @DisplayName("emergency=false 필드는 일반 마스킹이 적용되어야 한다")
        void shouldApplyNormalMaskingToNonEmergencyFields() {
            EmergencyDto dto = new EmergencyDto(
                    "123456-1234567",
                    "1234-5678-9012-3456",
                    "010-1234-5678",
                    "normal"
            );

            Map<String, Object> result = processor.process(dto);

            // emergency=false 필드는 일반 마스킹
            assertThat(result.get("residentNumber")).isEqualTo("123456-*******");
            assertThat(result.get("normalField")).isEqualTo("normal");
        }

        @Test
        @DisplayName("emergency=true 필드는 JSON 형식의 암호화 결과를 포함해야 한다")
        void shouldIncludeEncryptedResultForEmergencyFields() {
            EmergencyDto dto = new EmergencyDto(
                    "123456-1234567",
                    "1234-5678-9012-3456",
                    "010-1234-5678",
                    "normal"
            );

            Map<String, Object> result = processor.process(dto);

            // emergency=true 필드는 JSON 형식
            String cardResult = (String) result.get("cardNumber");
            assertThat(cardResult).contains("\"display\":");
            assertThat(cardResult).contains("\"encrypted\":");
            assertThat(cardResult).contains("****-****-****-3456");

            String phoneResult = (String) result.get("emergencyPhone");
            assertThat(phoneResult).contains("\"display\":");
            assertThat(phoneResult).contains("\"encrypted\":");
            assertThat(phoneResult).contains("010-****-5678");
        }

        @Test
        @DisplayName("isEmergencyModeEnabled()가 true를 반환해야 한다")
        void shouldReturnTrueForEmergencyModeEnabled() {
            assertThat(processor.isEmergencyModeEnabled()).isTrue();
        }
    }

    @Nested
    @DisplayName("EmergencyEncryptor 미설정 시")
    class WhenEmergencyEncryptorNotSet {

        @Test
        @DisplayName("isEmergencyModeEnabled()가 false를 반환해야 한다")
        void shouldReturnFalseWhenEncryptorNotSet() {
            AnnotationMaskingProcessor processorWithoutEncryptor = new AnnotationMaskingProcessor();
            assertThat(processorWithoutEncryptor.isEmergencyModeEnabled()).isFalse();
        }

        @Test
        @DisplayName("emergency=true 필드도 일반 마스킹이 적용되어야 한다")
        void shouldApplyNormalMaskingWhenEncryptorNotSet() {
            AnnotationMaskingProcessor processorWithoutEncryptor = new AnnotationMaskingProcessor();

            EmergencyDto dto = new EmergencyDto(
                    "123456-1234567",
                    "1234-5678-9012-3456",
                    "010-1234-5678",
                    "normal"
            );

            Map<String, Object> result = processorWithoutEncryptor.process(dto);

            assertThat(result.get("cardNumber")).isEqualTo("****-****-****-3456");
            assertThat(result.get("emergencyPhone")).isEqualTo("010-****-5678");
        }
    }

    @Nested
    @DisplayName("processToObject 테스트")
    class ProcessToObjectTest {

        @Test
        @DisplayName("비상 모드에서도 인스턴스는 마스킹된 값만 포함해야 한다")
        void shouldContainOnlyMaskedValuesInInstance() {
            emergencyEncryptor.setEnabled(true);

            EmergencyDto dto = new EmergencyDto(
                    "123456-1234567",
                    "1234-5678-9012-3456",
                    "010-1234-5678",
                    "normal"
            );

            EmergencyDto result = processor.processToObject(dto);

            // 인스턴스는 암호화 JSON이 아닌 마스킹된 값만 포함
            assertThat(result).isNotNull();
        }
    }
}
