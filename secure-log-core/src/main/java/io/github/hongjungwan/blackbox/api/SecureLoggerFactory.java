package io.github.hongjungwan.blackbox.api;

import io.github.hongjungwan.blackbox.core.internal.DefaultSecureLogger;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Factory for creating SecureLogger instances.
 *
 * <p>Provides cached logger instances with default implementation.</p>
 *
 * @since 8.0.0
 */
public final class SecureLoggerFactory {

    private static final ConcurrentMap<String, SecureLogger> LOGGER_CACHE = new ConcurrentHashMap<>();

    private SecureLoggerFactory() {}

    /**
     * Get or create a logger with the specified name.
     *
     * @param name the logger name
     * @return a SecureLogger instance with the specified name
     */
    public static SecureLogger getLogger(String name) {
        return LOGGER_CACHE.computeIfAbsent(name, DefaultSecureLogger::new);
    }

    /**
     * Get or create a logger for the specified class.
     *
     * @param clazz the class to create a logger for
     * @return a SecureLogger instance for the class
     */
    public static SecureLogger getLogger(Class<?> clazz) {
        return getLogger(clazz.getName());
    }

    /**
     * Reset and clear the logger cache.
     */
    public static void reset() {
        LOGGER_CACHE.clear();
    }
}
