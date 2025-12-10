package io.github.hongjungwan.blackbox.starter.aop;

import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import lombok.extern.slf4j.Slf4j;

/**
 * Spring Security 기반 사용자 정보 추출기.
 *
 * SecurityContextHolder에서 현재 인증된 사용자 정보를 추출.
 * Spring Security가 없는 환경에서는 LoggingContext의 userId를 사용.
 */
@Slf4j
public class SecurityContextUserExtractor implements AuditUserExtractor {

    private static final String ANONYMOUS = "ANONYMOUS";

    // Spring Security 클래스 존재 여부 (런타임 체크)
    private static final boolean SPRING_SECURITY_PRESENT = isSpringSecurityPresent();

    private static boolean isSpringSecurityPresent() {
        try {
            Class.forName("org.springframework.security.core.context.SecurityContextHolder");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    @Override
    public String extractCurrentUser() {
        // 1. Spring Security에서 추출 시도
        if (SPRING_SECURITY_PRESENT) {
            String user = extractFromSecurityContext();
            if (user != null && !user.equals(ANONYMOUS)) {
                return user;
            }
        }

        // 2. LoggingContext에서 추출 시도
        LoggingContext context = LoggingContext.current();
        String userId = context.getBaggage().get("user_id");
        if (userId != null && !userId.isEmpty()) {
            return userId;
        }

        // 3. 기본값
        return ANONYMOUS;
    }

    private String extractFromSecurityContext() {
        try {
            // 리플렉션으로 Spring Security 호출 (컴파일 의존성 없이)
            Class<?> securityContextHolderClass =
                    Class.forName("org.springframework.security.core.context.SecurityContextHolder");
            Object securityContext = securityContextHolderClass
                    .getMethod("getContext")
                    .invoke(null);

            if (securityContext == null) {
                return ANONYMOUS;
            }

            Object authentication = securityContext.getClass()
                    .getMethod("getAuthentication")
                    .invoke(securityContext);

            if (authentication == null) {
                return ANONYMOUS;
            }

            Boolean isAuthenticated = (Boolean) authentication.getClass()
                    .getMethod("isAuthenticated")
                    .invoke(authentication);

            if (!Boolean.TRUE.equals(isAuthenticated)) {
                return ANONYMOUS;
            }

            Object principal = authentication.getClass()
                    .getMethod("getPrincipal")
                    .invoke(authentication);

            if (principal == null) {
                return ANONYMOUS;
            }

            // UserDetails 인터페이스 확인
            if (isUserDetails(principal)) {
                return (String) principal.getClass()
                        .getMethod("getUsername")
                        .invoke(principal);
            }

            // Principal이 String인 경우
            if (principal instanceof String) {
                String name = (String) principal;
                return "anonymousUser".equals(name) ? ANONYMOUS : name;
            }

            // 그 외: getName() 호출
            String name = (String) authentication.getClass()
                    .getMethod("getName")
                    .invoke(authentication);

            return "anonymousUser".equals(name) ? ANONYMOUS : name;

        } catch (Exception e) {
            log.debug("Failed to extract user from SecurityContext: {}", e.getMessage());
            return ANONYMOUS;
        }
    }

    private boolean isUserDetails(Object principal) {
        try {
            Class<?> userDetailsClass =
                    Class.forName("org.springframework.security.core.userdetails.UserDetails");
            return userDetailsClass.isInstance(principal);
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}
