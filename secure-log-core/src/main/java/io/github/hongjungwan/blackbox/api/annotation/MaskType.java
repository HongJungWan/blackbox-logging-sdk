package io.github.hongjungwan.blackbox.api.annotation;

/**
 * PII 마스킹 유형 정의. 각 유형별 마스킹 패턴 적용.
 */
public enum MaskType {

    /** 주민등록번호. 예: 123456-1234567 -> 123456-******* */
    RRN,

    /** 전화번호. 예: 010-1234-5678 -> 010-****-5678 */
    PHONE,

    /** 이메일. 예: user@example.com -> u***@example.com */
    EMAIL,

    /** 신용카드번호. 예: 1234-5678-9012-3456 -> ****-****-****-3456 */
    CREDIT_CARD,

    /** 비밀번호. 전체 마스킹. 예: anyPassword -> ******** */
    PASSWORD,

    /** 미국 SSN. 예: 123-45-6789 -> ***-**-6789 */
    SSN,

    /** 이름. 예: John Doe -> J*** D** */
    NAME,

    /** 주소. 구조 유지하며 마스킹 */
    ADDRESS,

    /** 계좌번호. 예: 1234567890 -> ******7890 */
    ACCOUNT_NUMBER
}
