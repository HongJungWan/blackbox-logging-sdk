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
 * PII (Personally Identifiable Information) Masking.
 *
 * <p>Provides masking for sensitive data fields such as:</p>
 * <ul>
 *   <li>RRN (Korean Resident Registration Number)</li>
 *   <li>Credit Card numbers</li>
 *   <li>Passwords</li>
 *   <li>SSN (US Social Security Number)</li>
 * </ul>
 *
 * <p>Uses standard String operations and regex for clarity and maintainability.</p>
 */
@Slf4j
public class PiiMasker {

    private final SecureLogConfig config;
    private final Map<String, MaskingStrategy> strategies;
    private final AnnotationMaskingProcessor annotationProcessor;

    // Pre-compiled patterns (created once)
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
     * Mask PII fields in an object using {@link io.github.hongjungwan.blackbox.api.annotation.Mask} annotations.
     *
     * <p>This method processes objects that have fields annotated with {@code @Mask} and returns
     * a Map containing all field values with sensitive ones masked according to their {@link MaskType}.</p>
     *
     * <h2>Usage Example:</h2>
     * <pre>{@code
     * public class EmployeeDto {
     *     @Mask(MaskType.RRN)
     *     private String residentNumber;
     *
     *     @Mask(MaskType.PHONE)
     *     private String phoneNumber;
     *
     *     private String name; // Not masked
     * }
     *
     * EmployeeDto dto = new EmployeeDto("123456-1234567", "010-1234-5678", "John");
     * Map<String, Object> masked = piiMasker.maskObject(dto);
     * // Result: {residentNumber=123456-*******, phoneNumber=010-****-5678, name=John}
     * }</pre>
     *
     * @param obj the object containing @Mask annotated fields
     * @param <T> the type of the object
     * @return a Map containing field names and their (potentially masked) values
     * @throws IllegalArgumentException if obj is null
     * @see io.github.hongjungwan.blackbox.api.annotation.Mask
     * @see MaskType
     */
    public <T> Map<String, Object> maskObject(T obj) {
        return annotationProcessor.process(obj);
    }

    /**
     * Mask PII fields in an object and return a new instance of the same type.
     *
     * <p>This method attempts to create a new instance of the same class with masked values.
     * It requires the class to have a no-arg constructor.</p>
     *
     * <h2>Usage Example:</h2>
     * <pre>{@code
     * EmployeeDto original = new EmployeeDto("123456-1234567", "010-1234-5678");
     * EmployeeDto masked = piiMasker.maskObjectToInstance(original);
     * }</pre>
     *
     * @param obj the object containing @Mask annotated fields
     * @param <T> the type of the object
     * @return a new instance with masked values, or null if instantiation fails
     * @throws IllegalArgumentException if obj is null
     */
    public <T> T maskObjectToInstance(T obj) {
        return annotationProcessor.processToObject(obj);
    }

    /**
     * Apply masking to a single value based on the specified MaskType.
     *
     * <p>This method provides direct access to masking without requiring annotations.</p>
     *
     * @param value the value to mask
     * @param type the type of masking to apply
     * @return the masked value, or the original value if null or empty
     */
    public String maskValue(String value, MaskType type) {
        return annotationProcessor.applyMask(value, type);
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
     * Mask RRN patterns in a string.
     * Example: 123456-1234567 -> 123456-*******
     */
    private String maskRrnInString(String value) {
        return RRN_PATTERN.matcher(value).replaceAll(matchResult -> {
            String matched = matchResult.group();
            // Keep first 7 characters (6 digits + hyphen), mask the rest
            return matched.substring(0, 7) + "*******";
        });
    }

    /**
     * Mask credit card patterns in a string.
     * Example: 1234-5678-9012-3456 -> ****-****-****-3456
     */
    private String maskCreditCardInString(String value) {
        return CREDIT_CARD_PATTERN.matcher(value).replaceAll(matchResult -> {
            String matched = matchResult.group();
            // Keep last 4 digits, mask the rest
            String lastFour = matched.substring(matched.length() - 4);
            return "****-****-****-" + lastFour;
        });
    }

    /**
     * Mask SSN patterns in a string.
     * Example: 123-45-6789 -> ***-**-6789
     */
    private String maskSsnInString(String value) {
        return SSN_PATTERN.matcher(value).replaceAll(matchResult -> {
            String matched = matchResult.group();
            // Keep last 4 digits, mask the rest
            String lastFour = matched.substring(matched.length() - 4);
            return "***-**-" + lastFour;
        });
    }

    /**
     * Base masking strategy interface.
     */
    public interface MaskingStrategy {
        String mask(String value);
    }

    /**
     * RRN (Resident Registration Number) masking: 123456-1234567 -> 123456-*******
     * Uses standard String operations for simplicity.
     */
    static class RrnMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() != 14) {
                return "******";
            }
            // Keep first 7 characters (6 digits + hyphen), mask the rest
            return value.substring(0, 7) + "*******";
        }
    }

    /**
     * Credit Card masking: 1234-5678-9012-3456 -> ****-****-****-3456
     * Uses standard String operations for simplicity.
     */
    static class CreditCardMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() < 4) {
                return "****";
            }
            // Keep last 4 characters, mask the rest with asterisks preserving hyphens
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
     * Uses standard String operations for simplicity.
     */
    static class SsnMaskingStrategy implements MaskingStrategy {
        @Override
        public String mask(String value) {
            if (value == null || value.length() != 11) {
                return "***-**-****";
            }
            // Keep last 4 characters, mask the rest with asterisks preserving hyphens
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

    /**
     * Custom Jackson serializer for masking during JSON generation.
     */
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
