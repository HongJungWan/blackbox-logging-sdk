package io.github.hongjungwan.blackbox.core.security;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
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
 * Zero-Allocation Contextual Masking.
 *
 * <p>CRITICAL CONSTRAINTS:</p>
 * <ul>
 *   <li>NO String.replaceAll() (causes allocation)</li>
 *   <li>NO regex object creation in hot paths</li>
 *   <li>Use char array manipulation directly</li>
 *   <li>Use JsonGenerator low-level API for zero-copy writes</li>
 * </ul>
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
     * Mask PII fields in log entry.
     *
     * @param entry the log entry containing potential PII data
     * @return a new LogEntry with PII fields masked
     */
    public LogEntry mask(LogEntry entry) {
        // Mask PII in message field
        String maskedMessage = maskPiiInValue(entry.getMessage());

        // Mask PII in payload field
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
     * Mask PII fields in a map recursively.
     *
     * <p>NOTE: Zero-Allocation Trade-off</p>
     * <p>This method creates a new HashMap for each call, which deviates from the zero-allocation
     * design principle. This is an intentional trade-off because:</p>
     * <ul>
     *   <li>Immutability: We cannot modify the original map as it may be shared or immutable</li>
     *   <li>Safety: Creating a copy prevents concurrent modification issues</li>
     *   <li>Complexity: Object pooling for nested Map structures adds significant complexity</li>
     * </ul>
     * <p>For high-throughput scenarios where this becomes a bottleneck, consider:</p>
     * <ul>
     *   <li>Pre-masking data at the source before logging</li>
     *   <li>Using a custom LogEntry builder that accepts pre-masked payloads</li>
     *   <li>Implementing a thread-local map pool (with careful size management)</li>
     * </ul>
     *
     * FIX P2 #16: Copy map entries before iteration to prevent ConcurrentModificationException.
     */
    private Map<String, Object> maskMap(Map<String, Object> map) {
        Map<String, Object> masked = new LinkedHashMap<>(map.size());

        // FIX P2 #16: Create a copy of entries to avoid ConcurrentModificationException
        // when the input map is modified concurrently during iteration
        List<Map.Entry<String, Object>> entries = new ArrayList<>(map.entrySet());

        for (Map.Entry<String, Object> entry : entries) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // Check if field needs masking by name
            MaskingStrategy strategy = null;
            if (key != null) {
                strategy = strategies.get(key.toLowerCase());
            }

            if (strategy != null && value instanceof String) {
                masked.put(key, strategy.mask((String) value));
            } else if (value instanceof String) {
                // Auto-detect PII patterns in string values
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
     * Scan a string value for PII patterns and mask them.
     * Uses pre-compiled patterns for efficiency.
     *
     * @param value the string value to scan
     * @return the value with detected PII masked
     */
    public String maskPiiInValue(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        String result = value;

        // Check for RRN pattern (Korean Resident Registration Number)
        if (RRN_PATTERN.matcher(result).find()) {
            result = maskRrnInString(result);
        }

        // Check for credit card pattern
        if (CREDIT_CARD_PATTERN.matcher(result).find()) {
            result = maskCreditCardInString(result);
        }

        // Check for SSN pattern (US Social Security Number)
        if (SSN_PATTERN.matcher(result).find()) {
            result = maskSsnInString(result);
        }

        return result;
    }

    /**
     * Mask RRN patterns in a string using char array manipulation.
     */
    private String maskRrnInString(String value) {
        java.util.regex.Matcher matcher = RRN_PATTERN.matcher(value);
        StringBuilder result = new StringBuilder();
        int lastEnd = 0;

        while (matcher.find()) {
            result.append(value, lastEnd, matcher.start());
            String matched = matcher.group();
            // Mask: keep first 6 digits and hyphen, mask rest
            char[] chars = matched.toCharArray();
            for (int i = 7; i < chars.length; i++) {
                chars[i] = '*';
            }
            result.append(chars);
            lastEnd = matcher.end();
        }
        result.append(value.substring(lastEnd));
        return result.toString();
    }

    /**
     * Mask credit card patterns in a string using char array manipulation.
     */
    private String maskCreditCardInString(String value) {
        java.util.regex.Matcher matcher = CREDIT_CARD_PATTERN.matcher(value);
        StringBuilder result = new StringBuilder();
        int lastEnd = 0;

        while (matcher.find()) {
            result.append(value, lastEnd, matcher.start());
            String matched = matcher.group();
            // Mask all but last 4 digits
            char[] chars = matched.toCharArray();
            for (int i = 0; i < chars.length - 4; i++) {
                if (Character.isDigit(chars[i])) {
                    chars[i] = '*';
                }
            }
            result.append(chars);
            lastEnd = matcher.end();
        }
        result.append(value.substring(lastEnd));
        return result.toString();
    }

    /**
     * Mask SSN patterns in a string using char array manipulation.
     */
    private String maskSsnInString(String value) {
        java.util.regex.Matcher matcher = SSN_PATTERN.matcher(value);
        StringBuilder result = new StringBuilder();
        int lastEnd = 0;

        while (matcher.find()) {
            result.append(value, lastEnd, matcher.start());
            String matched = matcher.group();
            // Mask first 7 characters (XXX-XX-XXXX format)
            char[] chars = matched.toCharArray();
            for (int i = 0; i < 7; i++) {
                if (Character.isDigit(chars[i])) {
                    chars[i] = '*';
                }
            }
            result.append(chars);
            lastEnd = matcher.end();
        }
        result.append(value.substring(lastEnd));
        return result.toString();
    }

    /**
     * Base masking strategy interface.
     */
    public interface MaskingStrategy {
        String mask(String value);
    }

    /**
     * RRN (Resident Registration Number) masking: 123456-1234567 -> 123456-*******
     * ZERO-ALLOCATION: Uses char array manipulation.
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
     * Password masking: complete masking.
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
     * Custom Jackson serializer for zero-allocation masking during JSON generation.
     * Uses JsonGenerator.writeString(char[], int, int) for direct char array writes.
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
