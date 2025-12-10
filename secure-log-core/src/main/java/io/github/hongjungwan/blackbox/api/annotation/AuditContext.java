package io.github.hongjungwan.blackbox.api.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * AOP 기반 감사 문맥 자동 수집 어노테이션.
 *
 * 메서드에 적용하여 "누가(Who)", "누구의(Whom)", "왜(Why)" 정보를 자동 수집.
 * 수집된 정보는 ThreadLocal을 통해 LoggingContext에 전파되어 로그에 포함.
 *
 * @AuditContext(
 *     why = "급여 정보 조회",
 *     whomParam = "employeeId",
 *     action = AuditAction.READ
 * )
 * public EmployeeSalaryDto getSalary(String employeeId) {
 *     // 로그에 자동으로 감사 문맥 포함:
 *     // - who: 현재 인증된 사용자 (SecurityContext에서 추출)
 *     // - whom: employeeId 파라미터 값
 *     // - why: "급여 정보 조회"
 *     // - action: READ
 *     return repository.findSalary(employeeId);
 * }
 *
 * SpEL 표현식 지원 (why 속성):
 * @AuditContext(
 *     why = "#{#employeeId}의 급여 정보를 #{#reason}으로 조회",
 *     action = AuditAction.READ
 * )
 * public EmployeeSalaryDto getSalary(String employeeId, String reason) { ... }
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuditContext {

    /**
     * 작업 사유 (Why).
     * SpEL 표현식 지원: #{#paramName} 형식으로 메서드 파라미터 참조 가능.
     */
    String why() default "";

    /**
     * 대상자 파라미터 이름 (Whom).
     * 지정된 파라미터 값을 whom으로 추출.
     * 미지정 시 employeeId, userId, targetId 등을 자동 탐색.
     */
    String whomParam() default "";

    /**
     * 작업 유형 (What).
     * 기본값: READ
     */
    AuditAction action() default AuditAction.READ;

    /**
     * 리소스 타입.
     * 접근 대상 리소스의 유형을 명시 (예: "Employee", "Salary", "Department").
     */
    String resourceType() default "";

    /**
     * 감사 로그 활성화 여부.
     * false 시 문맥만 전파하고 별도 감사 로그는 생성하지 않음.
     */
    boolean logEnabled() default true;
}
