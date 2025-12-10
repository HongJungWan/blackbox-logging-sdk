package io.github.hongjungwan.blackbox.starter.aop;

/**
 * 현재 사용자 정보 추출 인터페이스.
 *
 * Spring Security, 커스텀 인증 시스템 등 다양한 인증 방식을 지원하기 위한 추상화.
 * 기본 구현체로 {@link SecurityContextUserExtractor}가 제공됨.
 */
@FunctionalInterface
public interface AuditUserExtractor {

    /**
     * 현재 인증된 사용자 정보를 문자열로 추출.
     *
     * @return 사용자 식별 문자열 (예: "admin@company.com", "인사팀 홍길동")
     *         인증되지 않은 경우 "ANONYMOUS" 반환
     */
    String extractCurrentUser();
}
