package io.github.hongjungwan.blackbox.starter.aop;

import io.github.hongjungwan.blackbox.api.SecureLogger;
import io.github.hongjungwan.blackbox.api.annotation.AuditAction;
import io.github.hongjungwan.blackbox.api.annotation.AuditContext;
import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import io.github.hongjungwan.blackbox.api.domain.AuditInfo;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.util.Map;
import java.util.Set;

/**
 * AOP 기반 감사 문맥 자동 주입 Aspect.
 *
 * @AuditContext 어노테이션이 적용된 메서드 실행 시 "누가(Who)", "누구의(Whom)", "왜(Why)"
 * 정보를 자동 수집하여 ThreadLocal에 저장하고 LoggingContext에 전파.
 *
 * Who 추출 우선순위:
 * - Spring Security SecurityContextHolder
 * - LoggingContext의 userId
 * - "ANONYMOUS"
 */
@Aspect
@Slf4j
public class AuditContextAspect {

    private static final ThreadLocal<AuditInfo> CONTEXT_HOLDER = new ThreadLocal<>();
    private static final ExpressionParser SPEL_PARSER = new SpelExpressionParser();

    // ID 파라미터 자동 탐색을 위한 패턴
    private static final Set<String> ID_PARAM_PATTERNS = Set.of(
            "employeeid", "userid", "targetid", "id", "memberid", "staffid"
    );

    private final SecureLogger secureLogger;
    private final AuditUserExtractor userExtractor;

    public AuditContextAspect(SecureLogger secureLogger, AuditUserExtractor userExtractor) {
        this.secureLogger = secureLogger;
        this.userExtractor = userExtractor;
    }

    /**
     * @AuditContext 어노테이션이 적용된 메서드를 감싸서 감사 문맥 주입.
     */
    @Around("@annotation(auditContext)")
    public Object captureContext(ProceedingJoinPoint joinPoint, AuditContext auditContext)
            throws Throwable {

        AuditInfo auditInfo = buildAuditInfo(joinPoint, auditContext);
        long startTime = System.currentTimeMillis();
        boolean success = true;
        Exception caughtException = null;

        try {
            // ThreadLocal에 문맥 저장
            CONTEXT_HOLDER.set(auditInfo);

            // LoggingContext에 감사 정보 전파
            propagateToLoggingContext(auditInfo);

            return joinPoint.proceed();

        } catch (Exception e) {
            success = false;
            caughtException = e;
            throw e;

        } finally {
            long duration = System.currentTimeMillis() - startTime;

            // 감사 로그 기록 (logEnabled=true인 경우)
            if (auditContext.logEnabled()) {
                logAuditEvent(auditInfo, success, duration, caughtException);
            }

            CONTEXT_HOLDER.remove();
        }
    }

    /**
     * 현재 스레드의 감사 문맥 조회.
     */
    public static AuditInfo getCurrentContext() {
        return CONTEXT_HOLDER.get();
    }

    // ========== Private Methods ==========

    private AuditInfo buildAuditInfo(ProceedingJoinPoint joinPoint, AuditContext auditContext) {
        return AuditInfo.builder()
                .who(extractWho())
                .whom(extractWhom(joinPoint, auditContext))
                .why(extractWhy(joinPoint, auditContext))
                .action(auditContext.action())
                .resourceType(auditContext.resourceType())
                .traceId(LoggingContext.current().getTraceId())
                .build();
    }

    /**
     * Who 추출: 현재 인증된 사용자 정보.
     */
    private String extractWho() {
        return userExtractor.extractCurrentUser();
    }

    /**
     * Whom 추출: 지정된 파라미터 또는 첫 번째 ID 타입 파라미터.
     */
    private String extractWhom(ProceedingJoinPoint joinPoint, AuditContext auditContext) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();

        if (paramNames == null || args == null) {
            return "UNKNOWN";
        }

        // whomParam이 지정된 경우 해당 파라미터 값 사용
        if (!auditContext.whomParam().isEmpty()) {
            for (int i = 0; i < paramNames.length; i++) {
                if (paramNames[i].equals(auditContext.whomParam()) && args[i] != null) {
                    return String.valueOf(args[i]);
                }
            }
        }

        // 자동 탐색: employeeId, userId, targetId 등의 파라미터
        for (int i = 0; i < paramNames.length; i++) {
            String normalizedName = paramNames[i].toLowerCase();
            if (ID_PARAM_PATTERNS.contains(normalizedName) && args[i] != null) {
                return String.valueOf(args[i]);
            }
        }

        // ID가 포함된 파라미터명 탐색
        for (int i = 0; i < paramNames.length; i++) {
            String normalizedName = paramNames[i].toLowerCase();
            if (normalizedName.contains("id") && args[i] != null) {
                return String.valueOf(args[i]);
            }
        }

        return "UNKNOWN";
    }

    /**
     * Why 추출: SpEL 표현식 평가 또는 기본값.
     */
    private String extractWhy(ProceedingJoinPoint joinPoint, AuditContext auditContext) {
        String whyExpression = auditContext.why();

        if (whyExpression.isEmpty()) {
            // 기본값: 메서드 이름 + 작업 유형
            return String.format("%s %s",
                    auditContext.action().getDescription(),
                    joinPoint.getSignature().getName());
        }

        // SpEL 표현식 평가 (#{...} 형식)
        if (whyExpression.contains("#{")) {
            return evaluateSpelExpression(whyExpression, joinPoint);
        }

        return whyExpression;
    }

    private String evaluateSpelExpression(String expression, ProceedingJoinPoint joinPoint) {
        try {
            StandardEvaluationContext context = new StandardEvaluationContext();

            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            String[] paramNames = signature.getParameterNames();
            Object[] args = joinPoint.getArgs();

            if (paramNames != null && args != null) {
                for (int i = 0; i < paramNames.length; i++) {
                    context.setVariable(paramNames[i], args[i]);
                }
            }

            // #{...} 패턴을 찾아서 평가
            StringBuilder result = new StringBuilder();
            int lastEnd = 0;
            int start;

            while ((start = expression.indexOf("#{", lastEnd)) != -1) {
                result.append(expression, lastEnd, start);

                int end = expression.indexOf("}", start);
                if (end == -1) {
                    break;
                }

                String spelExpr = expression.substring(start + 2, end);
                try {
                    Object value = SPEL_PARSER.parseExpression(spelExpr).getValue(context);
                    result.append(value != null ? value.toString() : "null");
                } catch (Exception e) {
                    result.append("#{").append(spelExpr).append("}");
                }

                lastEnd = end + 1;
            }

            result.append(expression.substring(lastEnd));
            return result.toString();

        } catch (Exception e) {
            log.debug("SpEL expression evaluation failed: {}", expression, e);
            return expression;
        }
    }

    private void propagateToLoggingContext(AuditInfo auditInfo) {
        // LoggingContext는 불변이므로 새 Context를 빌드하여 ThreadLocal에 설정
        Map<String, Object> attributes = auditInfo.toAttributeMap();
        LoggingContext.Builder builder = LoggingContext.current().toBuilder();

        for (Map.Entry<String, Object> entry : attributes.entrySet()) {
            if (entry.getValue() != null) {
                builder.addAttribute(entry.getKey(), entry.getValue());
            }
        }

        builder.build().makeCurrent();
    }

    private void logAuditEvent(AuditInfo auditInfo, boolean success, long durationMs, Exception exception) {
        Map<String, Object> payload = auditInfo.toLogPayload();
        payload.put("success", success);
        payload.put("durationMs", durationMs);

        if (exception != null) {
            payload.put("errorType", exception.getClass().getSimpleName());
            payload.put("errorMessage", exception.getMessage());
        }

        String message = String.format("감사: %s - %s (%s 대상)",
                auditInfo.getAction().getDescription(),
                auditInfo.getWhy(),
                auditInfo.getWhom());

        if (success) {
            secureLogger.info(message, payload);
        } else {
            secureLogger.warn(message.replace("감사:", "감사(실패):"), payload);
        }
    }
}
