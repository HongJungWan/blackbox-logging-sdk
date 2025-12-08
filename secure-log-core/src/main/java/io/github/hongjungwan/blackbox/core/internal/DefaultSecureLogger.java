package io.github.hongjungwan.blackbox.core.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hongjungwan.blackbox.api.SecureLogger;
import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Map;

/**
 * SLF4J 기반 SecureLogger 구현. LoggingContext 자동 전파, payload는 MDC에 보존.
 */
@Slf4j
public class DefaultSecureLogger implements SecureLogger {

    private static final String PAYLOAD_MDC_KEY = "secure.payload";
    private static final ObjectMapper PAYLOAD_MAPPER = new ObjectMapper();

    private final Logger delegate;
    private final String name;

    public DefaultSecureLogger(String name) {
        this.name = name;
        this.delegate = LoggerFactory.getLogger(name);
    }

    @Override
    public void trace(String message) {
        withContext(() -> delegate.trace(message));
    }

    @Override
    public void trace(String message, Map<String, Object> payload) {
        withContextAndPayload(payload, () -> delegate.trace(message));
    }

    @Override
    public void debug(String message) {
        withContext(() -> delegate.debug(message));
    }

    @Override
    public void debug(String message, Map<String, Object> payload) {
        withContextAndPayload(payload, () -> delegate.debug(message));
    }

    @Override
    public void info(String message) {
        withContext(() -> delegate.info(message));
    }

    @Override
    public void info(String message, Map<String, Object> payload) {
        withContextAndPayload(payload, () -> delegate.info(message));
    }

    @Override
    public void warn(String message) {
        withContext(() -> delegate.warn(message));
    }

    @Override
    public void warn(String message, Map<String, Object> payload) {
        withContextAndPayload(payload, () -> delegate.warn(message));
    }

    @Override
    public void warn(String message, Throwable throwable) {
        withContext(() -> delegate.warn(message, throwable));
    }

    @Override
    public void error(String message) {
        withContext(() -> delegate.error(message));
    }

    @Override
    public void error(String message, Map<String, Object> payload) {
        withContextAndPayload(payload, () -> delegate.error(message));
    }

    @Override
    public void error(String message, Throwable throwable) {
        withContext(() -> delegate.error(message, throwable));
    }

    @Override
    public void error(String message, Throwable throwable, Map<String, Object> payload) {
        withContextAndPayload(payload, () -> delegate.error(message, throwable));
    }

    @Override
    public boolean isTraceEnabled() {
        return delegate.isTraceEnabled();
    }

    @Override
    public boolean isDebugEnabled() {
        return delegate.isDebugEnabled();
    }

    @Override
    public boolean isInfoEnabled() {
        return delegate.isInfoEnabled();
    }

    @Override
    public boolean isWarnEnabled() {
        return delegate.isWarnEnabled();
    }

    @Override
    public boolean isErrorEnabled() {
        return delegate.isErrorEnabled();
    }

    @Override
    public String getName() {
        return name;
    }

    private void withContext(Runnable action) {
        LoggingContext ctx = LoggingContext.current();
        Map<String, String> mdcValues = ctx.toMdc();

        try {
            mdcValues.forEach(MDC::put);
            action.run();
        } finally {
            for (String key : mdcValues.keySet()) {
                try {
                    MDC.remove(key);
                } catch (Exception e) {
                    log.warn("Failed to remove MDC key '{}': {}", key, e.getMessage());
                }
            }
        }
    }

    private void withContextAndPayload(Map<String, Object> payload, Runnable action) {
        LoggingContext ctx = LoggingContext.current();
        Map<String, String> mdcValues = ctx.toMdc();

        try {
            mdcValues.forEach(MDC::put);

            if (payload != null && !payload.isEmpty()) {
                MDC.put(PAYLOAD_MDC_KEY, convertPayloadToString(payload));
            }

            action.run();
        } finally {
            for (String key : mdcValues.keySet()) {
                try {
                    MDC.remove(key);
                } catch (Exception e) {
                    log.warn("Failed to remove MDC key '{}': {}", key, e.getMessage());
                }
            }
            try {
                MDC.remove(PAYLOAD_MDC_KEY);
            } catch (Exception e) {
                log.warn("Failed to remove MDC key '{}': {}", PAYLOAD_MDC_KEY, e.getMessage());
            }
        }
    }

    private String convertPayloadToString(Map<String, Object> payload) {
        try {
            return PAYLOAD_MAPPER.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            return payload.toString();
        }
    }
}
