package io.github.hongjungwan.blackbox.core.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hongjungwan.blackbox.api.SecureLogger;
import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Map;

/**
 * Default SecureLogger implementation using SLF4J.
 *
 * <p>Automatically integrates with LoggingContext for trace propagation.</p>
 * <p>Payload is preserved in MDC under "secure.payload" key to avoid loss during SLF4J formatting.</p>
 */
public class DefaultSecureLogger implements SecureLogger {

    private static final String PAYLOAD_MDC_KEY = "secure.payload";

    /**
     * ObjectMapper for serializing payload to JSON string.
     * Thread-safe and reusable. Matches the parsing in LogEntry.parsePayloadFromMdc().
     */
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

    /**
     * Execute with LoggingContext propagated to MDC.
     */
    private void withContext(Runnable action) {
        LoggingContext ctx = LoggingContext.current();
        Map<String, String> mdcValues = ctx.toMdc();

        try {
            // Set MDC values
            mdcValues.forEach(MDC::put);

            // Execute
            action.run();
        } finally {
            // Clear MDC values
            for (String key : mdcValues.keySet()) {
                try {
                    MDC.remove(key);
                } catch (Exception e) {
                    // Log but don't propagate
                }
            }
        }
    }

    /**
     * Execute with LoggingContext and payload propagated to MDC.
     * Payload is stored as JSON string in MDC to preserve it for downstream processing.
     */
    private void withContextAndPayload(Map<String, Object> payload, Runnable action) {
        LoggingContext ctx = LoggingContext.current();
        Map<String, String> mdcValues = ctx.toMdc();

        try {
            // Set MDC values
            mdcValues.forEach(MDC::put);

            // Store payload in MDC as JSON-like string to preserve it
            if (payload != null && !payload.isEmpty()) {
                MDC.put(PAYLOAD_MDC_KEY, convertPayloadToString(payload));
            }

            // Execute
            action.run();
        } finally {
            // Clear MDC values
            for (String key : mdcValues.keySet()) {
                try {
                    MDC.remove(key);
                } catch (Exception e) {
                    // Log but don't propagate
                }
            }
            try {
                MDC.remove(PAYLOAD_MDC_KEY);
            } catch (Exception e) {
                // Log but don't propagate
            }
        }
    }

    /**
     * Convert payload map to a JSON string for MDC storage.
     * Uses Jackson ObjectMapper for proper JSON serialization that handles
     * nested objects, arrays, and special characters correctly.
     * This ensures consistency with LogEntry.parsePayloadFromMdc().
     */
    private String convertPayloadToString(Map<String, Object> payload) {
        try {
            return PAYLOAD_MAPPER.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            // Fallback to simple toString if JSON serialization fails
            return payload.toString();
        }
    }
}
