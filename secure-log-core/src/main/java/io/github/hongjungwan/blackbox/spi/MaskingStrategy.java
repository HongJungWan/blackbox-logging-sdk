package io.github.hongjungwan.blackbox.spi;

/**
 * PII 마스킹 전략 SPI. 커스텀 마스킹 로직 구현 시 사용.
 */
public interface MaskingStrategy {

    /** 패턴 식별자 (예: "rrn", "credit_card") */
    String getPatternName();

    /** 값 마스킹 처리 */
    String mask(String value);

    /** 필드명이 이 전략에 해당하는지 확인 */
    boolean matches(String fieldName);

    /** 우선순위 (낮을수록 먼저 적용, 기본값 500) */
    default int priority() {
        return 500;
    }
}
