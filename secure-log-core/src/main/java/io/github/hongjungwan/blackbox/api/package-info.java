/**
 * Public API for SecureHR Logging SDK.
 *
 * <p>This package contains all public interfaces and classes that users
 * should interact with directly. Classes in this package are stable and
 * follow semantic versioning.</p>
 *
 * <h2>Main Entry Points:</h2>
 * <ul>
 *   <li>{@link io.github.hongjungwan.blackbox.api.SecureLogger} - Primary logging interface</li>
 *   <li>{@link io.github.hongjungwan.blackbox.api.context.LoggingContext} - Trace context propagation</li>
 *   <li>{@link io.github.hongjungwan.blackbox.api.config.SecureLogConfig} - SDK configuration</li>
 *   <li>{@link io.github.hongjungwan.blackbox.api.interceptor.LogInterceptor} - Custom log processing</li>
 * </ul>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * import io.github.hongjungwan.blackbox.api.*;
 * import io.github.hongjungwan.blackbox.api.context.LoggingContext;
 *
 * public class MyService {
 *     private static final SecureLogger logger = SecureLogger.getLogger(MyService.class);
 *
 *     public void processPayroll(String employeeId) {
 *         try (var scope = LoggingContext.builder()
 *                 .newTrace()
 *                 .userId(employeeId)
 *                 .operation("payroll")
 *                 .build()
 *                 .makeCurrent()) {
 *
 *             logger.info("Processing payroll", Map.of(
 *                 "employee_id", employeeId,
 *                 "rrn", "123456-1234567"  // Auto-masked
 *             ));
 *         }
 *     }
 * }
 * }</pre>
 *
 * @since 8.0.0
 */
package io.github.hongjungwan.blackbox.api;
