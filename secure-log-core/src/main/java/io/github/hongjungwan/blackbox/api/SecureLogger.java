package io.github.hongjungwan.blackbox.api;

import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.util.Map;

/**
 * Main entry point for SecureHR Logging SDK.
 *
 * <p>This is the primary API for logging secure, compliant log entries
 * with automatic PII masking, encryption, and tamper prevention.</p>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * SecureLogger logger = SecureLogger.getLogger(MyClass.class);
 *
 * // Simple logging
 * logger.info("User logged in");
 *
 * // Structured logging with payload
 * logger.info("Salary processed", Map.of(
 *     "employee_id", "emp_1001",
 *     "amount", 5000000,
 *     "rrn", "123456-1234567"  // Auto-masked
 * ));
 *
 * // With trace context
 * try (var scope = LoggingContext.builder()
 *         .newTrace()
 *         .userId("admin")
 *         .build()
 *         .makeCurrent()) {
 *     logger.info("Operation started");
 * }
 * }</pre>
 *
 * @since 8.0.0
 * @see LoggingContext
 * @see LogEntry
 */
public interface SecureLogger {

    /**
     * Get a logger for the specified class.
     *
     * @param clazz the class to create a logger for
     * @return a SecureLogger instance for the class
     */
    static SecureLogger getLogger(Class<?> clazz) {
        return SecureLoggerFactory.getLogger(clazz.getName());
    }

    /**
     * Get a logger with the specified name.
     *
     * @param name the logger name
     * @return a SecureLogger instance with the specified name
     */
    static SecureLogger getLogger(String name) {
        return SecureLoggerFactory.getLogger(name);
    }

    /**
     * Log a message at TRACE level.
     *
     * @param message the message to log
     */
    void trace(String message);

    /**
     * Log a message at TRACE level with structured payload.
     *
     * @param message the message to log
     * @param payload the key-value pairs to include in the log entry
     */
    void trace(String message, Map<String, Object> payload);

    /**
     * Log a message at DEBUG level.
     *
     * @param message the message to log
     */
    void debug(String message);

    /**
     * Log a message at DEBUG level with structured payload.
     *
     * @param message the message to log
     * @param payload the key-value pairs to include in the log entry
     */
    void debug(String message, Map<String, Object> payload);

    /**
     * Log a message at INFO level.
     *
     * @param message the message to log
     */
    void info(String message);

    /**
     * Log a message at INFO level with structured payload.
     *
     * @param message the message to log
     * @param payload the key-value pairs to include in the log entry
     */
    void info(String message, Map<String, Object> payload);

    /**
     * Log a message at WARN level.
     *
     * @param message the message to log
     */
    void warn(String message);

    /**
     * Log a message at WARN level with structured payload.
     *
     * @param message the message to log
     * @param payload the key-value pairs to include in the log entry
     */
    void warn(String message, Map<String, Object> payload);

    /**
     * Log a message at WARN level with exception.
     *
     * @param message the message to log
     * @param throwable the exception to include in the log entry
     */
    void warn(String message, Throwable throwable);

    /**
     * Log a message at ERROR level.
     *
     * @param message the message to log
     */
    void error(String message);

    /**
     * Log a message at ERROR level with structured payload.
     *
     * @param message the message to log
     * @param payload the key-value pairs to include in the log entry
     */
    void error(String message, Map<String, Object> payload);

    /**
     * Log a message at ERROR level with exception.
     *
     * @param message the message to log
     * @param throwable the exception to include in the log entry
     */
    void error(String message, Throwable throwable);

    /**
     * Log a message at ERROR level with exception and payload.
     *
     * @param message the message to log
     * @param throwable the exception to include in the log entry
     * @param payload the key-value pairs to include in the log entry
     */
    void error(String message, Throwable throwable, Map<String, Object> payload);

    /**
     * Check if TRACE level is enabled.
     *
     * @return true if TRACE level is enabled
     */
    boolean isTraceEnabled();

    /**
     * Check if DEBUG level is enabled.
     *
     * @return true if DEBUG level is enabled
     */
    boolean isDebugEnabled();

    /**
     * Check if INFO level is enabled.
     *
     * @return true if INFO level is enabled
     */
    boolean isInfoEnabled();

    /**
     * Check if WARN level is enabled.
     *
     * @return true if WARN level is enabled
     */
    boolean isWarnEnabled();

    /**
     * Check if ERROR level is enabled.
     *
     * @return true if ERROR level is enabled
     */
    boolean isErrorEnabled();

    /**
     * Get the logger name.
     *
     * @return the logger name
     */
    String getName();

    /**
     * Create a structured log builder for fluent API.
     *
     * @param level the log level (TRACE, DEBUG, INFO, WARN, ERROR)
     * @return a new LogBuilder for method chaining
     */
    default LogBuilder atLevel(String level) {
        return new LogBuilder(this, level);
    }

    /**
     * Fluent log builder for complex log entries.
     */
    class LogBuilder {
        private final SecureLogger logger;
        private final String level;
        private String message;
        private Map<String, Object> payload;
        private Throwable throwable;

        LogBuilder(SecureLogger logger, String level) {
            this.logger = logger;
            this.level = level;
        }

        /**
         * Sets the log message.
         *
         * @param message the log message to set
         * @return this builder for method chaining
         */
        public LogBuilder message(String message) {
            this.message = message;
            return this;
        }

        /**
         * Sets the structured payload data.
         *
         * @param payload the key-value pairs to include in the log entry
         * @return this builder for method chaining
         */
        public LogBuilder payload(Map<String, Object> payload) {
            this.payload = payload;
            return this;
        }

        /**
         * Sets the throwable to log.
         *
         * @param throwable the exception or error to include
         * @return this builder for method chaining
         */
        public LogBuilder throwable(Throwable throwable) {
            this.throwable = throwable;
            return this;
        }

        /**
         * Executes the log operation with the configured level, message, payload, and throwable.
         */
        public void log() {
            switch (level.toUpperCase()) {
                case "TRACE" -> {
                    if (payload != null) logger.trace(message, payload);
                    else logger.trace(message);
                }
                case "DEBUG" -> {
                    if (payload != null) logger.debug(message, payload);
                    else logger.debug(message);
                }
                case "INFO" -> {
                    if (payload != null) logger.info(message, payload);
                    else logger.info(message);
                }
                case "WARN" -> {
                    if (throwable != null) logger.warn(message, throwable);
                    else if (payload != null) logger.warn(message, payload);
                    else logger.warn(message);
                }
                case "ERROR" -> {
                    if (throwable != null && payload != null) logger.error(message, throwable, payload);
                    else if (throwable != null) logger.error(message, throwable);
                    else if (payload != null) logger.error(message, payload);
                    else logger.error(message);
                }
                default -> logger.info(message);
            }
        }
    }
}
