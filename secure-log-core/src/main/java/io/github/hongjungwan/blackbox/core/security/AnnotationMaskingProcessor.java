package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.api.annotation.Mask;
import io.github.hongjungwan.blackbox.api.annotation.MaskType;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reflection-based processor for automatic PII masking using {@link Mask} annotations.
 *
 * <p>This processor scans objects for fields and methods annotated with {@code @Mask}
 * and applies the appropriate masking strategy based on the {@link MaskType}.</p>
 *
 * <h2>Features:</h2>
 * <ul>
 *   <li>Supports field-level and method-level annotations</li>
 *   <li>Caches reflection metadata for performance</li>
 *   <li>Thread-safe processing</li>
 *   <li>Returns masked copy as Map (preserves original object)</li>
 * </ul>
 *
 * <h2>Usage:</h2>
 * <pre>{@code
 * AnnotationMaskingProcessor processor = new AnnotationMaskingProcessor();
 * Map<String, Object> maskedData = processor.process(employeeDto);
 * }</pre>
 *
 * <h2>Performance Considerations:</h2>
 * <p>Reflection metadata is cached per class to minimize reflection overhead.
 * The cache uses {@link ConcurrentHashMap} for thread-safe access.</p>
 *
 * @since 8.0.0
 * @see Mask
 * @see MaskType
 */
@Slf4j
public class AnnotationMaskingProcessor {

    /**
     * Cache for field metadata to avoid repeated reflection calls.
     * Key: Class, Value: Map of field name to MaskType
     */
    private final ConcurrentHashMap<Class<?>, Map<String, MaskType>> fieldCache = new ConcurrentHashMap<>();

    /**
     * Cache for method metadata (getter methods annotated with @Mask).
     * Key: Class, Value: Map of property name to MaskType
     */
    private final ConcurrentHashMap<Class<?>, Map<String, MethodMaskInfo>> methodCache = new ConcurrentHashMap<>();

    /**
     * Process an object and return a Map with masked values.
     *
     * <p>This method:</p>
     * <ol>
     *   <li>Scans for @Mask annotated fields and methods</li>
     *   <li>Reads values via reflection</li>
     *   <li>Applies masking based on MaskType</li>
     *   <li>Returns a new Map containing all fields with sensitive ones masked</li>
     * </ol>
     *
     * @param obj the object to process (must not be null)
     * @param <T> the type of the object
     * @return a Map containing field names and their (potentially masked) values
     * @throws IllegalArgumentException if obj is null
     */
    public <T> Map<String, Object> process(T obj) {
        if (obj == null) {
            throw new IllegalArgumentException("Object to process must not be null");
        }

        Class<?> clazz = obj.getClass();
        Map<String, Object> result = new LinkedHashMap<>();

        // Get or compute field mask info
        Map<String, MaskType> fieldMasks = fieldCache.computeIfAbsent(clazz, this::scanFields);

        // Get or compute method mask info
        Map<String, MethodMaskInfo> methodMasks = methodCache.computeIfAbsent(clazz, this::scanMethods);

        // Process all declared fields
        for (Field field : clazz.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())) {
                continue;
            }

            String fieldName = field.getName();
            Object value = getFieldValue(obj, field);

            MaskType maskType = fieldMasks.get(fieldName);
            if (maskType != null && value instanceof String) {
                result.put(fieldName, applyMask((String) value, maskType));
            } else {
                result.put(fieldName, value);
            }
        }

        // Process annotated getter methods (for properties not backed by fields)
        for (Map.Entry<String, MethodMaskInfo> entry : methodMasks.entrySet()) {
            String propertyName = entry.getKey();
            MethodMaskInfo info = entry.getValue();

            // Skip if already processed as field
            if (result.containsKey(propertyName)) {
                continue;
            }

            Object value = invokeMethod(obj, info.method);
            if (value instanceof String) {
                result.put(propertyName, applyMask((String) value, info.maskType));
            } else {
                result.put(propertyName, value);
            }
        }

        return result;
    }

    /**
     * Process an object and return a new instance of the same type with masked values.
     *
     * <p>This method attempts to create a new instance and copy masked values.
     * If instantiation fails, it falls back to returning a Map.</p>
     *
     * @param obj the object to process
     * @param <T> the type of the object
     * @return a new instance with masked values, or null if creation fails
     */
    @SuppressWarnings("unchecked")
    public <T> T processToObject(T obj) {
        if (obj == null) {
            throw new IllegalArgumentException("Object to process must not be null");
        }

        Class<?> clazz = obj.getClass();

        try {
            // Try to create new instance using no-arg constructor
            T newInstance = (T) clazz.getDeclaredConstructor().newInstance();

            // Get mask info
            Map<String, MaskType> fieldMasks = fieldCache.computeIfAbsent(clazz, this::scanFields);

            // Copy and mask field values
            for (Field field : clazz.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || Modifier.isFinal(field.getModifiers())) {
                    continue;
                }

                field.setAccessible(true);
                String fieldName = field.getName();
                Object value = field.get(obj);

                MaskType maskType = fieldMasks.get(fieldName);
                if (maskType != null && value instanceof String) {
                    field.set(newInstance, applyMask((String) value, maskType));
                } else {
                    field.set(newInstance, value);
                }
            }

            return newInstance;
        } catch (ReflectiveOperationException e) {
            log.warn("Failed to create masked instance of {}, returning null. Error: {}",
                    clazz.getSimpleName(), e.getMessage());
            return null;
        }
    }

    /**
     * Scan a class for @Mask annotated fields.
     */
    private Map<String, MaskType> scanFields(Class<?> clazz) {
        Map<String, MaskType> masks = new LinkedHashMap<>();

        for (Field field : clazz.getDeclaredFields()) {
            Mask mask = field.getAnnotation(Mask.class);
            if (mask != null) {
                masks.put(field.getName(), mask.value());
            }
        }

        return masks;
    }

    /**
     * Scan a class for @Mask annotated getter methods.
     */
    private Map<String, MethodMaskInfo> scanMethods(Class<?> clazz) {
        Map<String, MethodMaskInfo> masks = new LinkedHashMap<>();

        for (Method method : clazz.getDeclaredMethods()) {
            Mask mask = method.getAnnotation(Mask.class);
            if (mask != null && isGetter(method)) {
                String propertyName = extractPropertyName(method);
                masks.put(propertyName, new MethodMaskInfo(method, mask.value()));
            }
        }

        return masks;
    }

    /**
     * Check if a method is a getter (get* or is*).
     */
    private boolean isGetter(Method method) {
        String name = method.getName();
        return method.getParameterCount() == 0
                && !method.getReturnType().equals(void.class)
                && (name.startsWith("get") || name.startsWith("is"));
    }

    /**
     * Extract property name from getter method name.
     */
    private String extractPropertyName(Method method) {
        String name = method.getName();
        String propertyName;

        if (name.startsWith("get") && name.length() > 3) {
            propertyName = name.substring(3);
        } else if (name.startsWith("is") && name.length() > 2) {
            propertyName = name.substring(2);
        } else {
            return name;
        }

        // Convert first character to lowercase
        return Character.toLowerCase(propertyName.charAt(0)) + propertyName.substring(1);
    }

    /**
     * Get field value using reflection.
     */
    private Object getFieldValue(Object obj, Field field) {
        try {
            field.setAccessible(true);
            return field.get(obj);
        } catch (IllegalAccessException e) {
            log.debug("Cannot access field {}: {}", field.getName(), e.getMessage());
            return null;
        }
    }

    /**
     * Invoke a method using reflection.
     */
    private Object invokeMethod(Object obj, Method method) {
        try {
            method.setAccessible(true);
            return method.invoke(obj);
        } catch (ReflectiveOperationException e) {
            log.debug("Cannot invoke method {}: {}", method.getName(), e.getMessage());
            return null;
        }
    }

    /**
     * Apply masking based on the MaskType.
     *
     * @param value the value to mask
     * @param type the type of masking to apply
     * @return the masked value
     */
    public String applyMask(String value, MaskType type) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        return switch (type) {
            case RRN -> maskRrn(value);
            case PHONE -> maskPhone(value);
            case EMAIL -> maskEmail(value);
            case CREDIT_CARD -> maskCreditCard(value);
            case PASSWORD -> maskPassword(value);
            case SSN -> maskSsn(value);
            case NAME -> maskName(value);
            case ADDRESS -> maskAddress(value);
            case ACCOUNT_NUMBER -> maskAccountNumber(value);
        };
    }

    /**
     * Mask RRN: 123456-1234567 -> 123456-*******
     */
    private String maskRrn(String value) {
        if (value.length() != 14) {
            return "******";
        }
        return value.substring(0, 7) + "*******";
    }

    /**
     * Mask phone number: 010-1234-5678 -> 010-****-5678
     * Preserves first segment and last 4 digits.
     */
    private String maskPhone(String value) {
        // Handle various formats
        String digitsOnly = value.replaceAll("[^0-9]", "");
        if (digitsOnly.length() < 7) {
            return "***-****-****";
        }

        // Find last 4 digits
        String lastFour = digitsOnly.substring(digitsOnly.length() - 4);

        // Determine first segment (area code)
        String firstSegment;
        if (digitsOnly.startsWith("010") || digitsOnly.startsWith("011") || digitsOnly.startsWith("016")
                || digitsOnly.startsWith("017") || digitsOnly.startsWith("018") || digitsOnly.startsWith("019")) {
            firstSegment = digitsOnly.substring(0, 3);
        } else if (digitsOnly.startsWith("02")) {
            firstSegment = "02";
        } else if (digitsOnly.length() >= 3) {
            firstSegment = digitsOnly.substring(0, 3);
        } else {
            firstSegment = digitsOnly;
        }

        return firstSegment + "-****-" + lastFour;
    }

    /**
     * Mask email: user@example.com -> u***@example.com
     */
    private String maskEmail(String value) {
        int atIndex = value.indexOf('@');
        if (atIndex <= 0) {
            return "****@****";
        }

        String localPart = value.substring(0, atIndex);
        String domain = value.substring(atIndex);

        if (localPart.length() <= 1) {
            return localPart + "***" + domain;
        }

        return localPart.charAt(0) + "***" + domain;
    }

    /**
     * Mask credit card: 1234-5678-9012-3456 -> ****-****-****-3456
     */
    private String maskCreditCard(String value) {
        if (value.length() < 4) {
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

    /**
     * Mask password: complete masking.
     */
    private String maskPassword(String value) {
        return "********";
    }

    /**
     * Mask SSN: 123-45-6789 -> ***-**-6789
     */
    private String maskSsn(String value) {
        if (value.length() != 11) {
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

    /**
     * Mask name: John Doe -> J*** D**
     * Preserves first character of each word.
     */
    private String maskName(String value) {
        String[] words = value.split("\\s+");
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < words.length; i++) {
            if (i > 0) {
                result.append(' ');
            }

            String word = words[i];
            if (word.isEmpty()) {
                continue;
            }

            result.append(word.charAt(0));
            for (int j = 1; j < word.length(); j++) {
                result.append('*');
            }
        }

        return result.toString();
    }

    /**
     * Mask address: 123 Main St -> *** **** **
     * Masks all characters while preserving word structure.
     */
    private String maskAddress(String value) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isWhitespace(c)) {
                result.append(c);
            } else {
                result.append('*');
            }
        }

        return result.toString();
    }

    /**
     * Mask account number: 1234567890 -> ******7890
     * Preserves last 4 digits.
     */
    private String maskAccountNumber(String value) {
        if (value.length() <= 4) {
            return "****";
        }

        String lastFour = value.substring(value.length() - 4);
        int maskLength = value.length() - 4;
        return "*".repeat(maskLength) + lastFour;
    }

    /**
     * Clear cached metadata. Useful for testing or when classes are reloaded.
     */
    public void clearCache() {
        fieldCache.clear();
        methodCache.clear();
    }

    /**
     * Internal class to hold method and mask type information.
     */
    private record MethodMaskInfo(Method method, MaskType maskType) {}
}
