package io.github.hongjungwan.blackbox.api.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * PII 마스킹 대상 필드/메서드 지정 어노테이션.
 *
 * 일반 모드: 지정된 마스킹 유형에 따라 민감 정보를 마스킹 처리.
 * 비상 모드: emergency=true인 필드는 마스킹 대신 공개키로 암호화된 원본 저장.
 *          추후 개인키로 복호화하여 원본 데이터 복구 가능.
 *
 * public class EmployeeDto {
 *     @Mask(MaskType.RRN)
 *     private String residentNumber;  // 일반: 123456-*******
 *
 *     @Mask(value = MaskType.CREDIT_CARD, emergency = true)
 *     private String cardNumber;      // 비상 모드 시 암호화된 원본 저장
 * }
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Mask {

    /** 적용할 마스킹 유형 */
    MaskType value();

    /**
     * 비상 모드 활성화 시 마스킹 대신 공개키로 암호화된 원본 저장.
     * 추후 개인키로 복호화하여 원본 데이터 복구 가능.
     * 기본값: false (일반 마스킹 모드)
     */
    boolean emergency() default false;
}
