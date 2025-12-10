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
 * @Mask 어노테이션 기반 자동 PII 마스킹 처리기.
 *
 * 리플렉션 메타데이터 캐싱으로 성능 최적화.
 * 비상 모드 지원: emergency=true 필드는 마스킹 대신 공개키 암호화.
 */
@Slf4j
public class AnnotationMaskingProcessor {

    // 필드 메타데이터 캐시 (Class -> 필드명 -> MaskFieldInfo)
    private final ConcurrentHashMap<Class<?>, Map<String, MaskFieldInfo>> fieldCache = new ConcurrentHashMap<>();

    // 메서드 메타데이터 캐시 (@Mask가 적용된 getter)
    private final ConcurrentHashMap<Class<?>, Map<String, MethodMaskInfo>> methodCache = new ConcurrentHashMap<>();

    // 비상 모드 암호화기 (null 가능 - 비활성화 시)
    private volatile EmergencyEncryptor emergencyEncryptor;

    /**
     * EmergencyEncryptor 설정. 비상 모드 지원을 위해 필요.
     *
     * @param encryptor 비상 모드 암호화기 (null 시 비상 모드 비활성화)
     */
    public void setEmergencyEncryptor(EmergencyEncryptor encryptor) {
        this.emergencyEncryptor = encryptor;
        log.info("EmergencyEncryptor {} for AnnotationMaskingProcessor",
                encryptor != null ? "configured" : "disabled");
    }

    /**
     * 비상 모드 활성화 여부 확인.
     */
    public boolean isEmergencyModeEnabled() {
        EmergencyEncryptor enc = emergencyEncryptor;
        return enc != null && enc.isEnabled();
    }

    /**
     * 객체의 @Mask 어노테이션 필드를 마스킹하여 Map으로 반환.
     * 비상 모드 활성화 시 emergency=true 필드는 암호화된 원본 포함.
     */
    public <T> Map<String, Object> process(T obj) {
        if (obj == null) {
            throw new IllegalArgumentException("Object to process must not be null");
        }

        Class<?> clazz = obj.getClass();
        Map<String, Object> result = new LinkedHashMap<>();

        Map<String, MaskFieldInfo> fieldMasks = fieldCache.computeIfAbsent(clazz, this::scanFields);
        Map<String, MethodMaskInfo> methodMasks = methodCache.computeIfAbsent(clazz, this::scanMethods);

        for (Field field : clazz.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())) {
                continue;
            }

            String fieldName = field.getName();
            Object value = getFieldValue(obj, field);

            MaskFieldInfo maskInfo = fieldMasks.get(fieldName);
            if (maskInfo != null && value instanceof String strValue) {
                result.put(fieldName, processFieldValue(strValue, maskInfo));
            } else {
                result.put(fieldName, value);
            }
        }

        for (Map.Entry<String, MethodMaskInfo> entry : methodMasks.entrySet()) {
            String propertyName = entry.getKey();
            MethodMaskInfo info = entry.getValue();

            if (result.containsKey(propertyName)) {
                continue;
            }

            Object value = invokeMethod(obj, info.method);
            if (value instanceof String strValue) {
                result.put(propertyName, processMethodValue(strValue, info));
            } else {
                result.put(propertyName, value);
            }
        }

        return result;
    }

    /**
     * 필드 값 처리: 일반 마스킹 또는 비상 모드 암호화.
     */
    private Object processFieldValue(String value, MaskFieldInfo maskInfo) {
        String maskedValue = applyMask(value, maskInfo.maskType);

        // 비상 모드 + emergency=true 필드
        if (isEmergencyModeEnabled() && maskInfo.emergencyEnabled) {
            return emergencyEncryptor.createEmergencyResult(value, maskedValue).toJson();
        }

        return maskedValue;
    }

    /**
     * 메서드 값 처리: 일반 마스킹 또는 비상 모드 암호화.
     */
    private Object processMethodValue(String value, MethodMaskInfo maskInfo) {
        String maskedValue = applyMask(value, maskInfo.maskType);

        // 비상 모드 + emergency=true 메서드
        if (isEmergencyModeEnabled() && maskInfo.emergencyEnabled) {
            return emergencyEncryptor.createEmergencyResult(value, maskedValue).toJson();
        }

        return maskedValue;
    }

    /**
     * 객체를 마스킹하여 동일 타입의 새 인스턴스로 반환. 실패 시 null.
     * 비상 모드 시 emergency=true 필드는 마스킹된 값 저장 (인스턴스에는 암호화 불가).
     */
    @SuppressWarnings("unchecked")
    public <T> T processToObject(T obj) {
        if (obj == null) {
            throw new IllegalArgumentException("Object to process must not be null");
        }

        Class<?> clazz = obj.getClass();

        try {
            T newInstance = (T) clazz.getDeclaredConstructor().newInstance();
            Map<String, MaskFieldInfo> fieldMasks = fieldCache.computeIfAbsent(clazz, this::scanFields);

            for (Field field : clazz.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || Modifier.isFinal(field.getModifiers())) {
                    continue;
                }

                field.setAccessible(true);
                String fieldName = field.getName();
                Object value = field.get(obj);

                MaskFieldInfo maskInfo = fieldMasks.get(fieldName);
                if (maskInfo != null && value instanceof String strValue) {
                    // 인스턴스 반환 시에는 마스킹된 값만 저장 (암호화 JSON은 Map에서만)
                    field.set(newInstance, applyMask(strValue, maskInfo.maskType));
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

    /** 클래스의 @Mask 어노테이션 필드 스캔 (emergency 속성 포함). */
    private Map<String, MaskFieldInfo> scanFields(Class<?> clazz) {
        Map<String, MaskFieldInfo> masks = new LinkedHashMap<>();

        for (Field field : clazz.getDeclaredFields()) {
            Mask mask = field.getAnnotation(Mask.class);
            if (mask != null) {
                masks.put(field.getName(), new MaskFieldInfo(mask.value(), mask.emergency()));
            }
        }

        return masks;
    }

    /** 클래스의 @Mask 어노테이션 getter 메서드 스캔 (emergency 속성 포함). */
    private Map<String, MethodMaskInfo> scanMethods(Class<?> clazz) {
        Map<String, MethodMaskInfo> masks = new LinkedHashMap<>();

        for (Method method : clazz.getDeclaredMethods()) {
            Mask mask = method.getAnnotation(Mask.class);
            if (mask != null && isGetter(method)) {
                String propertyName = extractPropertyName(method);
                masks.put(propertyName, new MethodMaskInfo(method, mask.value(), mask.emergency()));
            }
        }

        return masks;
    }

    /** getter 메서드 여부 확인 (get* 또는 is*). */
    private boolean isGetter(Method method) {
        String name = method.getName();
        return method.getParameterCount() == 0
                && !method.getReturnType().equals(void.class)
                && (name.startsWith("get") || name.startsWith("is"));
    }

    /** getter 메서드명에서 프로퍼티명 추출. */
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

        return Character.toLowerCase(propertyName.charAt(0)) + propertyName.substring(1);
    }

    /** 리플렉션으로 필드 값 조회. */
    private Object getFieldValue(Object obj, Field field) {
        try {
            field.setAccessible(true);
            return field.get(obj);
        } catch (IllegalAccessException e) {
            log.debug("Cannot access field {}: {}", field.getName(), e.getMessage());
            return null;
        }
    }

    /** 리플렉션으로 메서드 호출. */
    private Object invokeMethod(Object obj, Method method) {
        try {
            method.setAccessible(true);
            return method.invoke(obj);
        } catch (ReflectiveOperationException e) {
            log.debug("Cannot invoke method {}: {}", method.getName(), e.getMessage());
            return null;
        }
    }

    /** MaskType에 따른 마스킹 적용. */
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

    /** 주민번호 마스킹: 123456-1234567 -> 123456-******* */
    private String maskRrn(String value) {
        if (value.length() != 14) {
            return "******";
        }
        return value.substring(0, 7) + "*******";
    }

    /** 전화번호 마스킹: 010-1234-5678 -> 010-****-5678 */
    private String maskPhone(String value) {
        String digitsOnly = value.replaceAll("[^0-9]", "");
        if (digitsOnly.length() < 7) {
            return "***-****-****";
        }

        String lastFour = digitsOnly.substring(digitsOnly.length() - 4);
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

    /** 이메일 마스킹: user@example.com -> u***@example.com */
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

    /** 카드번호 마스킹: 1234-5678-9012-3456 -> ****-****-****-3456 */
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

    /** 비밀번호 마스킹: 전체 마스킹 */
    private String maskPassword(String value) {
        return "********";
    }

    /** SSN 마스킹: 123-45-6789 -> ***-**-6789 */
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

    /** 이름 마스킹: John Doe -> J*** D** (단어별 첫 글자만 표시) */
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

    /** 주소 마스킹: 단어 구조 유지하며 전체 마스킹 */
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

    /** 계좌번호 마스킹: 마지막 4자리만 표시 */
    private String maskAccountNumber(String value) {
        if (value.length() <= 4) {
            return "****";
        }

        String lastFour = value.substring(value.length() - 4);
        int maskLength = value.length() - 4;
        return "*".repeat(maskLength) + lastFour;
    }

    /** 캐시 초기화. 테스트 또는 클래스 리로드 시 사용. */
    public void clearCache() {
        fieldCache.clear();
        methodCache.clear();
    }

    /** 필드 마스킹 정보를 담는 내부 레코드. */
    private record MaskFieldInfo(MaskType maskType, boolean emergencyEnabled) {}

    /** 메서드와 마스킹 정보를 담는 내부 레코드. */
    private record MethodMaskInfo(Method method, MaskType maskType, boolean emergencyEnabled) {}
}
