package io.github.hongjungwan.blackbox.core.security;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import io.github.hongjungwan.blackbox.api.annotation.MaskType;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * PII 마스킹 처리기. 주민번호, 카드번호, 비밀번호, SSN 등 민감 정보 마스킹.
 */
@Slf4j
public class PiiMasker {

    private final SecureLogConfig config;
    private final Map<String, MaskingStrategy> strategies;
    private final AnnotationMaskingProcessor annotationProcessor;

    // 사전 컴파일된 정규식 패턴
    private static final Pattern RRN_PATTERN = Pattern.compile("\\d{6}-[1-4]\\d{6}");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\d{4}-\\d{4}-\\d{4}-\\d{4}");
    private static final Pattern SSN_PATTERN = Pattern.compile("\\d{3}-\\d{2}-\\d{4}");

    public PiiMasker(SecureLogConfig config) {
        this.config = config;
        this.strategies = initializeStrategies();
        this.annotationProcessor = new AnnotationMaskingProcessor();
    }

    private Map<String, MaskingStrategy> initializeStrategies() {
        Map<String, MaskingStrategy> map = new HashMap<>();

        for (String pattern : config.getPiiPatterns()) {
            switch (pattern.toLowerCase()) {
                case "rrn":
                    map.put("rrn", new RrnMaskingStrategy());
                    break;
                case "credit_card":
                    map.put("credit_card", new CreditCardMaskingStrategy());
                    map.put("card", new CreditCardMaskingStrategy());
                    map.put("cardNumber", new CreditCardMaskingStrategy());
                    break;
                case "password":
                    map.put("password", new PasswordMaskingStrategy());
                    map.put("pwd", new PasswordMaskingStrategy());
                    break;
                case "ssn":
                    map.put("ssn", new SsnMaskingStrategy());
                    break;
            }
        }

        return map;
    }

    /**
     * 로그 엔트리의 PII 필드 마스킹. message와 payload 모두 처리.
     */
    public LogEntry mask(LogEntry entry) {
        String maskedMessage = maskPiiInValue(entry.getMessage());

        Map<String, Object> maskedPayload = (entry.getPayload() == null || entry.getPayload().isEmpty())
                ? entry.getPayload()
                : maskMap(entry.getPayload());

        return LogEntry.builder()
                .timestamp(entry.getTimestamp())
                .level(entry.getLevel())
                .traceId(entry.getTraceId())
                .spanId(entry.getSpanId())
                .context(entry.getContext())
                .message(maskedMessage)
                .payload(maskedPayload)
                .integrity(entry.getIntegrity())
                .encryptedDek(entry.getEncryptedDek())
                .repeatCount(entry.getRepeatCount())
                .throwable(entry.getThrowable())
                .build();
    }

    /**
     * @Mask 어노테이션이 적용된 객체의 필드를 마스킹하여 Map으로 반환.
     */
    public <T> Map<String, Object> maskObject(T obj) {
        return annotationProcessor.process(obj);
    }

    /**
     * @Mask 어노테이션이 적용된 객체를 마스킹하여 동일 타입 인스턴스로 반환. 기본 생성자 필요.
     */
    public <T> T maskObjectToInstance(T obj) {
        return annotationProcessor.processToObject(obj);
    }

    /**
     * 단일 값에 지정된 MaskType 마스킹 적용.
     */
    public String maskValue(String value, MaskType type) {
        return annotationProcessor.applyMask(value, type);
    }

    /**
     * Map 내 PII 필드 재귀적 마스킹.
     * 주의: 불변성과 동시성 안전을 위해 새 Map 생성 (Zero-Allocation 예외).
     */
    private Map<String, Object> maskMap(Map<String, Object> map) {
        Map<String, Object> masked = new LinkedHashMap<>(map.size());

        // 동시 수정 방지용 복사
        List<Map.Entry<String, Object>> entries = new ArrayList<>(map.entrySet());

        for (Map.Entry<String, Object> entry : entries) {
            String key = entry.getKey();
            Object value = entry.getValue();

            MaskingStrategy strategy = null;
            if (key != null) {
                strategy = strategies.get(key.toLowerCase());
            }

            if (strategy != null && value instanceof String) {
                masked.put(key, strategy.mask((String) value));
            } else if (value instanceof String) {
                masked.put(key, maskPiiInValue((String) value));
            } else if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                masked.put(key, maskMap(nestedMap));
            } else {
                masked.put(key, value);
            }
        }

        return masked;
    }

    /**
     * 문자열 내 PII 패턴 자동 감지 후 마스킹. 주민번호, 카드번호, SSN 패턴 검사.
     */
    public String maskPiiInValue(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        String result = value;

        if (RRN_PATTERN.matcher(result).find()) {
            result = maskRrnInString(result);
        }

        if (CREDIT_CARD_PATTERN.matcher(result).find()) {
            result = maskCreditCardInString(result);
        }

        if (SSN_PATTERN.matcher(result).find()) {
            result = maskSsnInString(result);
        }

        return result;
    }

    /** 주민번호 마스킹: 123456-1234567 -> 123456-******* */
    private String maskRrnInString(String value) {
        return RRN_PATTERN.matcher(value).replaceAll(matchResult -> {
            String matched = matchResult.group();
            return matched.substring(0, 7) + "*******";
        });
    }

    /** 카드번호 마스킹: 1234-5678-9012-3456 -> ****-****-****-3456 */
    private String maskCreditCardInString(String value) {
        return CREDIT_CARD_PATTERN.matcher(value).replaceAll(matchResult -> {
            String matched = matchResult.group();
            String lastFour = matched.substring(matched.length() - 4);
            return "****-****-****-" + lastFour;
        });
    }

    /** SSN 마스킹: 123-45-6789 -> ***-**-6789 */
    private String maskSsnInString(String value) {
        return SSN_PATTERN.matcher(value).replaceAll(matchResult -> {
            String matched = matchResult.group();
            String lastFour = matched.substring(matched.length() - 4);
            return "***-**-" + lastFour;
        });
    }

    /** 마스킹 전략 인터페이스. */
    public interface MaskingStrategy {
        String mask(String value);
    }

    /** 주민번호 마스킹: 123456-1234567 -> 123456-******* */
    static class RrnMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() != 14) {
                return "******";
            }
            return value.substring(0, 7) + "*******";
        }
    }

    /** 카드번호 마스킹: 마지막 4자리만 표시, 하이픈 유지 */
    static class CreditCardMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() < 4) {
                return "****";
            }
            String lastFour = value.substring(value.length() - 4);
            StringBuilder masked = new StringBuilder();
            for (int i = 0; i < value.length() - 4; i++) {
                char c = value.charAt(i);
                masked.append(Character.isDigit(c) ? '*' : c);
            }
            masked.append(lastFour);
            return masked.toString();
        }
    }

    /** 비밀번호 마스킹: 전체 마스킹 */
    static class PasswordMaskingStrategy implements MaskingStrategy {
        private static final String MASKED = "********";

        @Override
        public String mask(String value) {
            return MASKED;
        }
    }

    /** SSN 마스킹: 123-45-6789 -> ***-**-6789 */
    static class SsnMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() != 11) {
                return "***-**-****";
            }
            String lastFour = value.substring(value.length() - 4);
            StringBuilder masked = new StringBuilder();
            for (int i = 0; i < value.length() - 4; i++) {
                char c = value.charAt(i);
                masked.append(Character.isDigit(c) ? '*' : c);
            }
            masked.append(lastFour);
            return masked.toString();
        }
    }

    /** JSON 직렬화 시 마스킹 적용하는 Jackson Serializer. */
    public static class MaskingSerializer extends StdSerializer<String> {

        private final MaskingStrategy strategy;

        public MaskingSerializer(MaskingStrategy strategy) {
            super(String.class);
            this.strategy = strategy;
        }

        @Override
        public void serialize(String value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            String masked = strategy.mask(value);
            gen.writeString(masked);
        }
    }
}
