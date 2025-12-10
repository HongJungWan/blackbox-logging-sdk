package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.api.annotation.Mask;
import io.github.hongjungwan.blackbox.api.annotation.MaskType;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for annotation-based PII masking functionality.
 *
 * <p>Verifies that {@link Mask} annotations are properly processed
 * by {@link AnnotationMaskingProcessor} and integrated with {@link PiiMasker}.</p>
 */
@DisplayName("Annotation-based Masking Tests")
class AnnotationMaskingTest {

    private PiiMasker piiMasker;
    private AnnotationMaskingProcessor processor;

    @BeforeEach
    void setUp() {
        SecureLogConfig config = SecureLogConfig.builder()
                .piiPatterns(List.of("rrn", "credit_card", "password", "ssn"))
                .build();
        piiMasker = new PiiMasker(config);
        processor = new AnnotationMaskingProcessor();
    }

    // ==================== Sample DTOs for Testing ====================

    /**
     * Sample Employee DTO with various masked fields.
     */
    static class EmployeeDto {
        @Mask(MaskType.RRN)
        private String residentNumber;

        @Mask(MaskType.PHONE)
        private String phoneNumber;

        @Mask(MaskType.EMAIL)
        private String email;

        @Mask(MaskType.CREDIT_CARD)
        private String cardNumber;

        @Mask(MaskType.PASSWORD)
        private String password;

        private String name; // Not masked

        private int age; // Non-string field

        // Default constructor for processToObject
        public EmployeeDto() {}

        public EmployeeDto(String residentNumber, String phoneNumber, String email,
                          String cardNumber, String password, String name, int age) {
            this.residentNumber = residentNumber;
            this.phoneNumber = phoneNumber;
            this.email = email;
            this.cardNumber = cardNumber;
            this.password = password;
            this.name = name;
            this.age = age;
        }

        // Getters
        public String getResidentNumber() { return residentNumber; }
        public String getPhoneNumber() { return phoneNumber; }
        public String getEmail() { return email; }
        public String getCardNumber() { return cardNumber; }
        public String getPassword() { return password; }
        public String getName() { return name; }
        public int getAge() { return age; }
    }

    /**
     * DTO with SSN, Name, Address, and Account Number masking.
     */
    static class CustomerDto {
        @Mask(MaskType.SSN)
        private String ssn;

        @Mask(MaskType.NAME)
        private String fullName;

        @Mask(MaskType.ADDRESS)
        private String address;

        @Mask(MaskType.ACCOUNT_NUMBER)
        private String accountNumber;

        public CustomerDto() {}

        public CustomerDto(String ssn, String fullName, String address, String accountNumber) {
            this.ssn = ssn;
            this.fullName = fullName;
            this.address = address;
            this.accountNumber = accountNumber;
        }

        public String getSsn() { return ssn; }
        public String getFullName() { return fullName; }
        public String getAddress() { return address; }
        public String getAccountNumber() { return accountNumber; }
    }

    /**
     * DTO with method-level annotation.
     */
    static class MethodAnnotatedDto {
        private String sensitiveData;

        public MethodAnnotatedDto() {}

        public MethodAnnotatedDto(String sensitiveData) {
            this.sensitiveData = sensitiveData;
        }

        @Mask(MaskType.PASSWORD)
        public String getSensitiveData() {
            return sensitiveData;
        }
    }

    /**
     * DTO without any masked fields.
     */
    static class PlainDto {
        private String publicField;
        private int number;

        public PlainDto() {}

        public PlainDto(String publicField, int number) {
            this.publicField = publicField;
            this.number = number;
        }
    }

    // ==================== Tests ====================

    @Nested
    @DisplayName("PiiMasker.maskObject() Tests")
    class MaskObjectTests {

        @Test
        @DisplayName("Should mask all annotated fields in EmployeeDto")
        void shouldMaskAllAnnotatedFields() {
            // Given
            EmployeeDto dto = new EmployeeDto(
                    "123456-1234567",
                    "010-1234-5678",
                    "user@example.com",
                    "1234-5678-9012-3456",
                    "secretPassword",
                    "John Doe",
                    30
            );

            // When
            Map<String, Object> masked = piiMasker.maskObject(dto);

            // Then
            assertThat(masked)
                    .containsEntry("residentNumber", "123456-*******")
                    .containsEntry("phoneNumber", "010-****-5678")
                    .containsEntry("email", "u***@example.com")
                    .containsEntry("cardNumber", "****-****-****-3456")
                    .containsEntry("password", "********")
                    .containsEntry("name", "John Doe") // Not masked
                    .containsEntry("age", 30); // Non-string preserved
        }

        @Test
        @DisplayName("Should mask CustomerDto fields correctly")
        void shouldMaskCustomerDtoFields() {
            // Given
            CustomerDto dto = new CustomerDto(
                    "123-45-6789",
                    "John Doe",
                    "123 Main Street",
                    "1234567890"
            );

            // When
            Map<String, Object> masked = piiMasker.maskObject(dto);

            // Then
            assertThat(masked)
                    .containsEntry("ssn", "***-**-6789")
                    .containsEntry("fullName", "J*** D**")
                    .containsEntry("address", "*** **** ******")
                    .containsEntry("accountNumber", "******7890");
        }

        @Test
        @DisplayName("Should throw exception for null input")
        void shouldThrowExceptionForNullInput() {
            assertThatThrownBy(() -> piiMasker.maskObject(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("null");
        }

        @Test
        @DisplayName("Should handle DTO without masked fields")
        void shouldHandleDtoWithoutMaskedFields() {
            // Given
            PlainDto dto = new PlainDto("publicData", 42);

            // When
            Map<String, Object> result = piiMasker.maskObject(dto);

            // Then
            assertThat(result)
                    .containsEntry("publicField", "publicData")
                    .containsEntry("number", 42);
        }

        @Test
        @DisplayName("Should handle null field values gracefully")
        void shouldHandleNullFieldValues() {
            // Given
            EmployeeDto dto = new EmployeeDto(
                    null, null, null, null, null, null, 0
            );

            // When
            Map<String, Object> masked = piiMasker.maskObject(dto);

            // Then
            assertThat(masked)
                    .containsEntry("residentNumber", null)
                    .containsEntry("phoneNumber", null)
                    .containsEntry("email", null)
                    .containsEntry("name", null);
        }

        @Test
        @DisplayName("Should handle empty string values")
        void shouldHandleEmptyStringValues() {
            // Given
            EmployeeDto dto = new EmployeeDto(
                    "", "", "", "", "", "", 0
            );

            // When
            Map<String, Object> masked = piiMasker.maskObject(dto);

            // Then
            assertThat(masked.get("residentNumber")).isEqualTo("");
            assertThat(masked.get("email")).isEqualTo("");
        }
    }

    @Nested
    @DisplayName("PiiMasker.maskObjectToInstance() Tests")
    class MaskObjectToInstanceTests {

        @Test
        @DisplayName("Should return masked instance of same type")
        void shouldReturnMaskedInstance() {
            // Given
            EmployeeDto original = new EmployeeDto(
                    "123456-1234567",
                    "010-1234-5678",
                    "user@example.com",
                    "1234-5678-9012-3456",
                    "secret",
                    "John",
                    25
            );

            // When
            EmployeeDto masked = piiMasker.maskObjectToInstance(original);

            // Then
            assertThat(masked).isNotNull();
            assertThat(masked.getResidentNumber()).isEqualTo("123456-*******");
            assertThat(masked.getPhoneNumber()).isEqualTo("010-****-5678");
            assertThat(masked.getEmail()).isEqualTo("u***@example.com");
            assertThat(masked.getCardNumber()).isEqualTo("****-****-****-3456");
            assertThat(masked.getPassword()).isEqualTo("********");
            assertThat(masked.getName()).isEqualTo("John"); // Not masked
            assertThat(masked.getAge()).isEqualTo(25); // Preserved
        }

        @Test
        @DisplayName("Should throw exception for null input")
        void shouldThrowExceptionForNullInput() {
            assertThatThrownBy(() -> piiMasker.maskObjectToInstance(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("PiiMasker.maskValue() Tests")
    class MaskValueTests {

        @Test
        @DisplayName("Should mask RRN value directly")
        void shouldMaskRrnDirectly() {
            String result = piiMasker.maskValue("123456-1234567", MaskType.RRN);
            assertThat(result).isEqualTo("123456-*******");
        }

        @Test
        @DisplayName("Should mask phone value directly")
        void shouldMaskPhoneDirectly() {
            String result = piiMasker.maskValue("010-1234-5678", MaskType.PHONE);
            assertThat(result).isEqualTo("010-****-5678");
        }

        @Test
        @DisplayName("Should mask email value directly")
        void shouldMaskEmailDirectly() {
            String result = piiMasker.maskValue("test@domain.com", MaskType.EMAIL);
            assertThat(result).isEqualTo("t***@domain.com");
        }

        @Test
        @DisplayName("Should mask credit card value directly")
        void shouldMaskCreditCardDirectly() {
            String result = piiMasker.maskValue("1234-5678-9012-3456", MaskType.CREDIT_CARD);
            assertThat(result).isEqualTo("****-****-****-3456");
        }

        @Test
        @DisplayName("Should mask password value directly")
        void shouldMaskPasswordDirectly() {
            String result = piiMasker.maskValue("anyPassword", MaskType.PASSWORD);
            assertThat(result).isEqualTo("********");
        }

        @Test
        @DisplayName("Should mask SSN value directly")
        void shouldMaskSsnDirectly() {
            String result = piiMasker.maskValue("123-45-6789", MaskType.SSN);
            assertThat(result).isEqualTo("***-**-6789");
        }

        @Test
        @DisplayName("Should mask name value directly")
        void shouldMaskNameDirectly() {
            String result = piiMasker.maskValue("John Doe", MaskType.NAME);
            assertThat(result).isEqualTo("J*** D**");
        }

        @Test
        @DisplayName("Should mask address value directly")
        void shouldMaskAddressDirectly() {
            String result = piiMasker.maskValue("123 Main St", MaskType.ADDRESS);
            assertThat(result).isEqualTo("*** **** **");
        }

        @Test
        @DisplayName("Should mask account number value directly")
        void shouldMaskAccountNumberDirectly() {
            String result = piiMasker.maskValue("1234567890", MaskType.ACCOUNT_NUMBER);
            assertThat(result).isEqualTo("******7890");
        }

        @Test
        @DisplayName("Should return null for null input")
        void shouldReturnNullForNullInput() {
            String result = piiMasker.maskValue(null, MaskType.RRN);
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should return empty string for empty input")
        void shouldReturnEmptyForEmptyInput() {
            String result = piiMasker.maskValue("", MaskType.RRN);
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("AnnotationMaskingProcessor Direct Tests")
    class ProcessorDirectTests {

        @Test
        @DisplayName("Should cache field metadata for performance")
        void shouldCacheFieldMetadata() {
            // Given
            EmployeeDto dto1 = new EmployeeDto("111111-1111111", "010-1111-1111",
                    "a@b.com", "1111-1111-1111-1111", "pwd", "A", 1);
            EmployeeDto dto2 = new EmployeeDto("222222-2222222", "010-2222-2222",
                    "c@d.com", "2222-2222-2222-2222", "pwd", "B", 2);

            // When - Process same class twice
            Map<String, Object> result1 = processor.process(dto1);
            Map<String, Object> result2 = processor.process(dto2);

            // Then - Both should be processed correctly (cache should not affect correctness)
            assertThat(result1.get("residentNumber")).isEqualTo("111111-*******");
            assertThat(result2.get("residentNumber")).isEqualTo("222222-*******");
        }

        @Test
        @DisplayName("Should clear cache when requested")
        void shouldClearCache() {
            // Given
            EmployeeDto dto = new EmployeeDto("123456-1234567", "010-1234-5678",
                    "a@b.com", "1234-1234-1234-1234", "pwd", "A", 1);
            processor.process(dto); // Populate cache

            // When
            processor.clearCache();

            // Then - Should still work after cache clear
            Map<String, Object> result = processor.process(dto);
            assertThat(result.get("residentNumber")).isEqualTo("123456-*******");
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle short phone numbers gracefully")
        void shouldHandleShortPhoneNumbers() {
            String result = piiMasker.maskValue("1234", MaskType.PHONE);
            // Short numbers should still get some masking
            assertThat(result).contains("****");
        }

        @Test
        @DisplayName("Should handle malformed RRN gracefully")
        void shouldHandleMalformedRrn() {
            String result = piiMasker.maskValue("12345", MaskType.RRN);
            // Malformed RRN should be fully masked
            assertThat(result).isEqualTo("******");
        }

        @Test
        @DisplayName("Should handle email without @ symbol")
        void shouldHandleEmailWithoutAtSymbol() {
            String result = piiMasker.maskValue("notanemail", MaskType.EMAIL);
            assertThat(result).isEqualTo("****@****");
        }

        @Test
        @DisplayName("Should handle single character email local part")
        void shouldHandleSingleCharEmailLocalPart() {
            String result = piiMasker.maskValue("a@domain.com", MaskType.EMAIL);
            assertThat(result).isEqualTo("a***@domain.com");
        }

        @Test
        @DisplayName("Should handle very short credit card")
        void shouldHandleShortCreditCard() {
            String result = piiMasker.maskValue("123", MaskType.CREDIT_CARD);
            assertThat(result).isEqualTo("****");
        }

        @Test
        @DisplayName("Should handle single word name")
        void shouldHandleSingleWordName() {
            String result = piiMasker.maskValue("John", MaskType.NAME);
            assertThat(result).isEqualTo("J***");
        }

        @Test
        @DisplayName("Should handle short account number")
        void shouldHandleShortAccountNumber() {
            String result = piiMasker.maskValue("123", MaskType.ACCOUNT_NUMBER);
            assertThat(result).isEqualTo("****");
        }
    }

    @Nested
    @DisplayName("Phone Number Format Tests")
    class PhoneNumberFormatTests {

        @Test
        @DisplayName("Should mask Korean mobile number format")
        void shouldMaskKoreanMobileFormat() {
            assertThat(piiMasker.maskValue("010-1234-5678", MaskType.PHONE))
                    .isEqualTo("010-****-5678");
        }

        @Test
        @DisplayName("Should mask Seoul landline format")
        void shouldMaskSeoulLandlineFormat() {
            assertThat(piiMasker.maskValue("02-1234-5678", MaskType.PHONE))
                    .isEqualTo("02-****-5678");
        }

        @Test
        @DisplayName("Should mask number without dashes")
        void shouldMaskNumberWithoutDashes() {
            String result = piiMasker.maskValue("01012345678", MaskType.PHONE);
            assertThat(result).endsWith("5678");
            assertThat(result).startsWith("010");
        }
    }
}
