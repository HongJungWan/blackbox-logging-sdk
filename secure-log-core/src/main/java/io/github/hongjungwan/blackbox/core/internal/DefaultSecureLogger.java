package io.github.hongjungwan.blackbox.core.internal;

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
 */
public class DefaultSecureLogger implements SecureLogger {

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
        withContext(() -> delegate.trace("{} {}", message, payload));
    }

    @Override
    public void debug(String message) {
        withContext(() -> delegate.debug(message));
    }

    @Override
    public void debug(String message, Map<String, Object> payload) {
        withContext(() -> delegate.debug("{} {}", message, payload));
    }

    @Override
    public void info(String message) {
        withContext(() -> delegate.info(message));
    }

    @Override
    public void info(String message, Map<String, Object> payload) {
        withContext(() -> delegate.info("{} {}", message, payload));
    }

    @Override
    public void warn(String message) {
        withContext(() -> delegate.warn(message));
    }

    @Override
    public void warn(String message, Map<String, Object> payload) {
        withContext(() -> delegate.warn("{} {}", message, payload));
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
        withContext(() -> delegate.error("{} {}", message, payload));
    }

    @Override
    public void error(String message, Throwable throwable) {
        withContext(() -> delegate.error(message, throwable));
    }

    @Override
    public void error(String message, Throwable throwable, Map<String, Object> payload) {
        withContext(() -> delegate.error("{} {} - {}", message, payload, throwable));
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
            mdcValues.keySet().forEach(MDC::remove);
        }
    }
}
