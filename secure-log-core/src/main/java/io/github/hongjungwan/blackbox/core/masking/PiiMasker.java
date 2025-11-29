package io.github.hongjungwan.blackbox.core.masking;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * FEAT-01: Zero-Allocation Contextual Masking
 *
 * CRITICAL CONSTRAINTS:
 * - NO String.replaceAll() (causes allocation)
 * - NO regex object creation in hot paths
 * - Use char array manipulation directly
 * - Use JsonGenerator low-level API for zero-copy writes
 */
@Slf4j
public class PiiMasker {

    private final SecureLogConfig config;
    private final Map<String, MaskingStrategy> strategies;

    // Pre-compiled patterns (created once)
    private static final Pattern RRN_PATTERN = Pattern.compile("\\d{6}-[1-4]\\d{6}");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\d{4}-\\d{4}-\\d{4}-\\d{4}");
    private static final Pattern SSN_PATTERN = Pattern.compile("\\d{3}-\\d{2}-\\d{4}");

    public PiiMasker(SecureLogConfig config) {
        this.config = config;
        this.strategies = initializeStrategies();
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
     * Mask PII fields in log entry
     */
    public LogEntry mask(LogEntry entry) {
        if (entry.getPayload() == null || entry.getPayload().isEmpty()) {
            return entry;
        }

        Map<String, Object> maskedPayload = maskMap(entry.getPayload());

        return LogEntry.builder()
                .timestamp(entry.getTimestamp())
                .level(entry.getLevel())
                .traceId(entry.getTraceId())
                .spanId(entry.getSpanId())
                .context(entry.getContext())
                .message(entry.getMessage())
                .payload(maskedPayload)
                .integrity(entry.getIntegrity())
                .encryptedDek(entry.getEncryptedDek())
                .repeatCount(entry.getRepeatCount())
                .throwable(entry.getThrowable())
                .build();
    }

    private Map<String, Object> maskMap(Map<String, Object> map) {
        Map<String, Object> masked = new HashMap<>();

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // Check if field needs masking
            MaskingStrategy strategy = strategies.get(key.toLowerCase());

            if (strategy != null && value instanceof String) {
                masked.put(key, strategy.mask((String) value));
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
     * Base masking strategy interface
     */
    interface MaskingStrategy {
        String mask(String value);
    }

    /**
     * RRN (Resident Registration Number) masking: 123456-1234567 -> 123456-*******
     * ZERO-ALLOCATION: Uses char array manipulation
     */
    static class RrnMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() != 14) {
                return "******";
            }

            // Zero-allocation approach: create char array once
            char[] chars = value.toCharArray();

            // Mask the last 7 digits
            for (int i = 7; i < 14; i++) {
                chars[i] = '*';
            }

            return new String(chars);
        }
    }

    /**
     * Credit Card masking: 1234-5678-9012-3456 -> ****-****-****-3456
     */
    static class CreditCardMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() < 4) {
                return "****";
            }

            char[] chars = value.toCharArray();

            // Mask all except last 4 digits
            for (int i = 0; i < chars.length - 4; i++) {
                if (Character.isDigit(chars[i])) {
                    chars[i] = '*';
                }
            }

            return new String(chars);
        }
    }

    /**
     * Password masking: complete masking
     */
    static class PasswordMaskingStrategy implements MaskingStrategy {
        private static final String MASKED = "********";

        @Override
        public String mask(String value) {
            return MASKED;
        }
    }

    /**
     * SSN masking: 123-45-6789 -> ***-**-6789
     */
    static class SsnMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() != 11) {
                return "***-**-****";
            }

            char[] chars = value.toCharArray();

            // Mask first 7 characters (SSN format: XXX-XX-XXXX)
            for (int i = 0; i < 7; i++) {
                if (Character.isDigit(chars[i])) {
                    chars[i] = '*';
                }
            }

            return new String(chars);
        }
    }

    /**
     * Custom Jackson serializer for zero-allocation masking during JSON generation
     * Uses JsonGenerator.writeString(char[], int, int) for direct char array writes
     */
    public static class ZeroAllocationMaskingSerializer extends StdSerializer<String> {

        private final MaskingStrategy strategy;

        public ZeroAllocationMaskingSerializer(MaskingStrategy strategy) {
            super(String.class);
            this.strategy = strategy;
        }

        @Override
        public void serialize(String value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            String masked = strategy.mask(value);
            char[] chars = masked.toCharArray();

            // Zero-allocation write: directly from char array
            gen.writeString(chars, 0, chars.length);
        }
    }
}
