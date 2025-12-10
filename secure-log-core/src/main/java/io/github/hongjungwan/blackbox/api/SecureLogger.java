package io.github.hongjungwan.blackbox.api;

import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.util.Map;

/**
 * SecureHR Logging SDK의 메인 로거 인터페이스. PII 마스킹, 암호화, 무결성 검증 자동 적용.
 */
public interface SecureLogger {

    /** 클래스 기반 로거 획득 */
    static SecureLogger getLogger(Class<?> clazz) {
        return SecureLoggerFactory.getLogger(clazz.getName());
    }

    /** 이름 기반 로거 획득 */
    static SecureLogger getLogger(String name) {
        return SecureLoggerFactory.getLogger(name);
    }

    void trace(String message);

    void trace(String message, Map<String, Object> payload);

    void debug(String message);

    void debug(String message, Map<String, Object> payload);

    void info(String message);

    void info(String message, Map<String, Object> payload);

    void warn(String message);

    void warn(String message, Map<String, Object> payload);

    void warn(String message, Throwable throwable);

    void error(String message);

    void error(String message, Map<String, Object> payload);

    void error(String message, Throwable throwable);

    void error(String message, Throwable throwable, Map<String, Object> payload);

    boolean isTraceEnabled();

    boolean isDebugEnabled();

    boolean isInfoEnabled();

    boolean isWarnEnabled();

    boolean isErrorEnabled();

    String getName();

    /** Fluent API 빌더 생성 */
    default LogBuilder atLevel(String level) {
        return new LogBuilder(this, level);
    }

    /** 로그 엔트리 빌더. 메서드 체이닝 지원. */
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

        public LogBuilder message(String message) {
            this.message = message;
            return this;
        }

        public LogBuilder payload(Map<String, Object> payload) {
            this.payload = payload;
            return this;
        }

        public LogBuilder throwable(Throwable throwable) {
            this.throwable = throwable;
            return this;
        }

        /** 설정된 레벨로 로그 출력 */
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
