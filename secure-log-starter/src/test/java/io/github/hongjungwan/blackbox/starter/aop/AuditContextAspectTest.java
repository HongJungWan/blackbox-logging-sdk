package io.github.hongjungwan.blackbox.starter.aop;

import io.github.hongjungwan.blackbox.api.SecureLogger;
import io.github.hongjungwan.blackbox.api.annotation.AuditAction;
import io.github.hongjungwan.blackbox.api.annotation.AuditContext;
import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import io.github.hongjungwan.blackbox.api.domain.AuditInfo;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * AuditContextAspect 단위 테스트.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("AuditContextAspect 테스트")
class AuditContextAspectTest {

    @Mock
    private SecureLogger secureLogger;

    @Mock
    private AuditUserExtractor userExtractor;

    @Mock
    private ProceedingJoinPoint joinPoint;

    @Mock
    private MethodSignature methodSignature;

    private AuditContextAspect aspect;

    @BeforeEach
    void setUp() {
        aspect = new AuditContextAspect(secureLogger, userExtractor);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(userExtractor.extractCurrentUser()).thenReturn("testUser");
    }

    @Nested
    @DisplayName("기본 문맥 수집")
    class BasicContextCapture {

        @Test
        @DisplayName("Who/Whom/Why 정보를 수집해야 한다")
        void shouldCaptureWhoWhomWhy() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("급여 조회", "employeeId", AuditAction.READ, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"EMP001"});
            when(methodSignature.getName()).thenReturn("getSalary");
            when(joinPoint.proceed()).thenReturn("result");

            // when
            Object result = aspect.captureContext(joinPoint, auditContext);

            // then
            assertThat(result).isEqualTo("result");

            // 감사 로그 기록 검증
            ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).info(messageCaptor.capture(), payloadCaptor.capture());

            Map<String, Object> payload = payloadCaptor.getValue();
            assertThat(payload.get("who")).isEqualTo("testUser");
            assertThat(payload.get("whom")).isEqualTo("EMP001");
            assertThat(payload.get("why")).isEqualTo("급여 조회");
            assertThat(payload.get("action")).isEqualTo("READ");
        }

        @Test
        @DisplayName("logEnabled=false 시 감사 로그를 기록하지 않아야 한다")
        void shouldNotLogWhenLogEnabledFalse() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("급여 조회", "employeeId", AuditAction.READ, "", false);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"EMP001"});
            when(methodSignature.getName()).thenReturn("getSalary");
            when(joinPoint.proceed()).thenReturn("result");

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            verify(secureLogger, never()).info(anyString(), any(Map.class));
        }
    }

    @Nested
    @DisplayName("Whom 파라미터 자동 탐색")
    class WhomAutoDetection {

        @Test
        @DisplayName("whomParam 지정 시 해당 파라미터를 사용해야 한다")
        void shouldUseSpecifiedWhomParam() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("", "targetId", AuditAction.UPDATE, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId", "targetId", "data"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"EMP001", "TARGET123", "data"});
            when(methodSignature.getName()).thenReturn("updateTarget");
            when(joinPoint.proceed()).thenReturn(null);

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).info(anyString(), payloadCaptor.capture());
            assertThat(payloadCaptor.getValue().get("whom")).isEqualTo("TARGET123");
        }

        @Test
        @DisplayName("employeeId 파라미터를 자동으로 탐색해야 한다")
        void shouldAutoDetectEmployeeId() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("", "", AuditAction.READ, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId", "year"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"EMP999", 2024});
            when(methodSignature.getName()).thenReturn("getAnnualReport");
            when(joinPoint.proceed()).thenReturn(null);

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).info(anyString(), payloadCaptor.capture());
            assertThat(payloadCaptor.getValue().get("whom")).isEqualTo("EMP999");
        }

        @Test
        @DisplayName("ID가 포함된 파라미터를 탐색해야 한다")
        void shouldDetectIdContainingParam() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("", "", AuditAction.DELETE, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"documentId", "reason"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"DOC456", "만료됨"});
            when(methodSignature.getName()).thenReturn("deleteDocument");
            when(joinPoint.proceed()).thenReturn(null);

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).info(anyString(), payloadCaptor.capture());
            assertThat(payloadCaptor.getValue().get("whom")).isEqualTo("DOC456");
        }

        @Test
        @DisplayName("파라미터가 없으면 UNKNOWN을 반환해야 한다")
        void shouldReturnUnknownWhenNoParams() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("", "", AuditAction.READ, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{});
            when(joinPoint.getArgs()).thenReturn(new Object[]{});
            when(methodSignature.getName()).thenReturn("getAllEmployees");
            when(joinPoint.proceed()).thenReturn(null);

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).info(anyString(), payloadCaptor.capture());
            assertThat(payloadCaptor.getValue().get("whom")).isEqualTo("UNKNOWN");
        }
    }

    @Nested
    @DisplayName("SpEL 표현식 평가")
    class SpelExpressionEvaluation {

        @Test
        @DisplayName("SpEL 표현식으로 why를 평가해야 한다")
        void shouldEvaluateSpelExpression() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("#{#employeeId}의 급여를 조회", "employeeId", AuditAction.READ, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"EMP001"});
            when(methodSignature.getName()).thenReturn("getSalary");
            when(joinPoint.proceed()).thenReturn(null);

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).info(anyString(), payloadCaptor.capture());
            assertThat(payloadCaptor.getValue().get("why")).isEqualTo("EMP001의 급여를 조회");
        }

        @Test
        @DisplayName("복수 SpEL 표현식을 평가해야 한다")
        void shouldEvaluateMultipleSpelExpressions() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("#{#employeeId}의 급여를 #{#reason}으로 조회", "employeeId", AuditAction.READ, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId", "reason"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"EMP001", "감사 요청"});
            when(methodSignature.getName()).thenReturn("getSalary");
            when(joinPoint.proceed()).thenReturn(null);

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).info(anyString(), payloadCaptor.capture());
            assertThat(payloadCaptor.getValue().get("why")).isEqualTo("EMP001의 급여를 감사 요청으로 조회");
        }
    }

    @Nested
    @DisplayName("예외 처리")
    class ExceptionHandling {

        @Test
        @DisplayName("예외 발생 시 warn 로그를 기록해야 한다")
        void shouldLogWarnOnException() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("급여 조회", "employeeId", AuditAction.READ, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"EMP001"});
            when(methodSignature.getName()).thenReturn("getSalary");
            RuntimeException exception = new RuntimeException("DB 연결 실패");
            when(joinPoint.proceed()).thenThrow(exception);

            // when & then
            assertThatThrownBy(() -> aspect.captureContext(joinPoint, auditContext))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("DB 연결 실패");

            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).warn(anyString(), payloadCaptor.capture());

            Map<String, Object> payload = payloadCaptor.getValue();
            assertThat(payload.get("success")).isEqualTo(false);
            assertThat(payload.get("errorType")).isEqualTo("RuntimeException");
            assertThat(payload.get("errorMessage")).isEqualTo("DB 연결 실패");
        }

        @Test
        @DisplayName("예외 발생 시에도 ThreadLocal이 정리되어야 한다")
        void shouldClearThreadLocalOnException() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("급여 조회", "employeeId", AuditAction.READ, "", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"EMP001"});
            when(methodSignature.getName()).thenReturn("getSalary");
            when(joinPoint.proceed()).thenThrow(new RuntimeException("에러"));

            // when
            try {
                aspect.captureContext(joinPoint, auditContext);
            } catch (RuntimeException ignored) {
            }

            // then
            assertThat(AuditContextAspect.getCurrentContext()).isNull();
        }
    }

    @Nested
    @DisplayName("AuditAction 유형별 테스트")
    class AuditActionTypes {

        @Test
        @DisplayName("CREATE 작업이 올바르게 기록되어야 한다")
        void shouldRecordCreateAction() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("신규 직원 등록", "", AuditAction.CREATE, "Employee", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"employeeId"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{"NEW001"});
            when(methodSignature.getName()).thenReturn("createEmployee");
            when(joinPoint.proceed()).thenReturn(null);

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            @SuppressWarnings("unchecked")
            ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
            verify(secureLogger).info(anyString(), payloadCaptor.capture());
            assertThat(payloadCaptor.getValue().get("action")).isEqualTo("CREATE");
            assertThat(payloadCaptor.getValue().get("resourceType")).isEqualTo("Employee");
        }

        @Test
        @DisplayName("EXPORT 작업이 올바르게 기록되어야 한다")
        void shouldRecordExportAction() throws Throwable {
            // given
            AuditContext auditContext = createAuditContext("급여 데이터 내보내기", "", AuditAction.EXPORT, "Salary", true);
            when(methodSignature.getParameterNames()).thenReturn(new String[]{"year"});
            when(joinPoint.getArgs()).thenReturn(new Object[]{2024});
            when(methodSignature.getName()).thenReturn("exportSalaryData");
            when(joinPoint.proceed()).thenReturn(null);

            // when
            aspect.captureContext(joinPoint, auditContext);

            // then
            ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
            verify(secureLogger).info(messageCaptor.capture(), any(Map.class));
            assertThat(messageCaptor.getValue()).contains("내보내기");
        }
    }

    // ========== Helper Methods ==========

    private AuditContext createAuditContext(String why, String whomParam, AuditAction action,
                                            String resourceType, boolean logEnabled) {
        return new AuditContext() {
            @Override
            public Class<? extends java.lang.annotation.Annotation> annotationType() {
                return AuditContext.class;
            }

            @Override
            public String why() {
                return why;
            }

            @Override
            public String whomParam() {
                return whomParam;
            }

            @Override
            public AuditAction action() {
                return action;
            }

            @Override
            public String resourceType() {
                return resourceType;
            }

            @Override
            public boolean logEnabled() {
                return logEnabled;
            }
        };
    }
}
