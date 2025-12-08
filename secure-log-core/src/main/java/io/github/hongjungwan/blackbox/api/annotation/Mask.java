package io.github.hongjungwan.blackbox.api.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * PII 마스킹 대상 필드/메서드 지정 어노테이션.
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Mask {

    /** 적용할 마스킹 유형 */
    MaskType value();
}
