package io.github.hongjungwan.blackbox.core.masking;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PiiMasker 테스트")
class PiiMaskerTest {

    private PiiMasker piiMasker;

    @BeforeEach
    void setUp() {
        SecureLogConfig config = SecureLogConfig.builder()
                .piiPatterns(List.of("rrn", "credit_card", "password", "ssn"))
                .build();
        piiMasker = new PiiMasker(config);
    }

    @Nested
    @DisplayName("RRN 마스킹")
    class RrnMaskingTests {

        @Test
        @DisplayName("주민등록번호 뒷자리 7자리를 마스킹해야 한다")
        void shouldMaskLastSevenDigits() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("User created")
                    .payload(Map.of("rrn", "123456-1234567"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("rrn")).isEqualTo("123456-*******");
        }

        @Test
        @DisplayName("잘못된 형식의 주민등록번호는 완전히 마스킹해야 한다")
        void shouldFullyMaskInvalidRrn() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("User created")
                    .payload(Map.of("rrn", "invalid"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("rrn")).isEqualTo("******");
        }
    }

    @Nested
    @DisplayName("신용카드 마스킹")
    class CreditCardMaskingTests {

        @Test
        @DisplayName("카드번호 마지막 4자리만 보여야 한다")
        void shouldShowLastFourDigits() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Payment processed")
                    .payload(Map.of("credit_card", "1234-5678-9012-3456"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("credit_card")).isEqualTo("****-****-****-3456");
        }

        @Test
        @DisplayName("card 필드명도 마스킹해야 한다")
        void shouldMaskCardField() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Payment processed")
                    .payload(Map.of("card", "1234-5678-9012-3456"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("card")).isEqualTo("****-****-****-3456");
        }

        @Test
        @DisplayName("짧은 카드번호는 완전히 마스킹해야 한다")
        void shouldFullyMaskShortCardNumber() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Payment processed")
                    .payload(Map.of("credit_card", "123"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("credit_card")).isEqualTo("****");
        }
    }

    @Nested
    @DisplayName("비밀번호 마스킹")
    class PasswordMaskingTests {

        @Test
        @DisplayName("비밀번호는 완전히 마스킹해야 한다")
        void shouldCompletelyMaskPassword() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Login attempt")
                    .payload(Map.of("password", "secretPassword123!"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("password")).isEqualTo("********");
        }

        @Test
        @DisplayName("pwd 필드명도 마스킹해야 한다")
        void shouldMaskPwdField() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Login attempt")
                    .payload(Map.of("pwd", "secretPassword123!"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("pwd")).isEqualTo("********");
        }
    }

    @Nested
    @DisplayName("SSN 마스킹")
    class SsnMaskingTests {

        @Test
        @DisplayName("SSN 앞 7자리를 마스킹해야 한다")
        void shouldMaskFirstSevenChars() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Employee record")
                    .payload(Map.of("ssn", "123-45-6789"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("ssn")).isEqualTo("***-**-6789");
        }

        @Test
        @DisplayName("잘못된 형식의 SSN은 완전히 마스킹해야 한다")
        void shouldFullyMaskInvalidSsn() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Employee record")
                    .payload(Map.of("ssn", "invalid"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("ssn")).isEqualTo("***-**-****");
        }
    }

    @Nested
    @DisplayName("중첩 페이로드 처리")
    class NestedPayloadTests {

        @Test
        @DisplayName("중첩된 맵의 민감정보도 마스킹해야 한다")
        void shouldMaskNestedPayload() {
            // given
            Map<String, Object> nested = new HashMap<>();
            nested.put("rrn", "123456-1234567");
            nested.put("name", "John Doe");

            LogEntry entry = LogEntry.builder()
                    .message("Nested data")
                    .payload(Map.of("user", nested))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            @SuppressWarnings("unchecked")
            Map<String, Object> maskedNested = (Map<String, Object>) masked.getPayload().get("user");
            assertThat(maskedNested.get("rrn")).isEqualTo("123456-*******");
            assertThat(maskedNested.get("name")).isEqualTo("John Doe");
        }
    }

    @Nested
    @DisplayName("엣지 케이스")
    class EdgeCaseTests {

        @Test
        @DisplayName("null 페이로드는 그대로 반환해야 한다")
        void shouldReturnOriginalEntryForNullPayload() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("No payload")
                    .payload(null)
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload()).isNull();
        }

        @Test
        @DisplayName("빈 페이로드는 그대로 반환해야 한다")
        void shouldReturnOriginalEntryForEmptyPayload() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Empty payload")
                    .payload(Map.of())
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload()).isEmpty();
        }

        @Test
        @DisplayName("대소문자 구분 없이 필드명을 인식해야 한다")
        void shouldBeCaseInsensitive() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Mixed case")
                    .payload(Map.of("PASSWORD", "secret"))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("PASSWORD")).isEqualTo("********");
        }

        @Test
        @DisplayName("민감하지 않은 필드는 그대로 유지해야 한다")
        void shouldKeepNonSensitiveFields() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Normal data")
                    .payload(Map.of("name", "John Doe", "age", 30))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("name")).isEqualTo("John Doe");
            assertThat(masked.getPayload().get("age")).isEqualTo(30);
        }

        @Test
        @DisplayName("비문자열 값은 마스킹하지 않아야 한다")
        void shouldNotMaskNonStringValues() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Non-string password")
                    .payload(Map.of("password", 12345))
                    .build();

            // when
            LogEntry masked = piiMasker.mask(entry);

            // then
            assertThat(masked.getPayload().get("password")).isEqualTo(12345);
        }
    }
}
