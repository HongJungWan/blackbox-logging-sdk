package io.github.hongjungwan.blackbox.api.annotation;

/**
 * 감사 작업 유형 정의.
 * HR 도메인에서 발생하는 주요 작업 유형을 분류.
 */
public enum AuditAction {

    /** 데이터 생성 */
    CREATE("생성"),

    /** 데이터 조회 */
    READ("조회"),

    /** 데이터 수정 */
    UPDATE("수정"),

    /** 데이터 삭제 */
    DELETE("삭제"),

    /** 데이터 내보내기 (엑셀, PDF 등) */
    EXPORT("내보내기"),

    /** 승인 처리 */
    APPROVE("승인"),

    /** 반려 처리 */
    REJECT("반려"),

    /** 로그인 */
    LOGIN("로그인"),

    /** 로그아웃 */
    LOGOUT("로그아웃"),

    /** 권한 변경 */
    PERMISSION_CHANGE("권한변경"),

    /** 기타 작업 */
    OTHER("기타");

    private final String description;

    AuditAction(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
