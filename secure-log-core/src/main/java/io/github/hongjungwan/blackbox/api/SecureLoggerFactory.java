package io.github.hongjungwan.blackbox.api;

import io.github.hongjungwan.blackbox.core.internal.DefaultSecureLogger;
import io.github.hongjungwan.blackbox.spi.LoggerProvider;

import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Factory for creating SecureLogger instances.
 *
 * <p>Uses ServiceLoader to discover LoggerProvider implementations,
 * falling back to the default implementation if none found.</p>
 *
 * @since 8.0.0
 */
public final class SecureLoggerFactory {

    private static final ConcurrentMap<String, SecureLogger> LOGGER_CACHE = new ConcurrentHashMap<>();
    private static volatile LoggerProvider provider;

    private SecureLoggerFactory() {}

    /**
     * Get or create a logger with the specified name.
     */
    public static SecureLogger getLogger(String name) {
        return LOGGER_CACHE.computeIfAbsent(name, SecureLoggerFactory::createLogger);
    }

    /**
     * Get or create a logger for the specified class.
     */
    public static SecureLogger getLogger(Class<?> clazz) {
        return getLogger(clazz.getName());
    }

    /**
     * Set the logger provider (for testing or custom implementations).
     */
    public static void setProvider(LoggerProvider newProvider) {
        provider = newProvider;
        LOGGER_CACHE.clear();
    }

    /**
     * Reset to default provider.
     */
    public static void reset() {
        provider = null;
        LOGGER_CACHE.clear();
    }

    private static SecureLogger createLogger(String name) {
        LoggerProvider p = getProvider();
        return p.getLogger(name);
    }

    private static LoggerProvider getProvider() {
        if (provider == null) {
            synchronized (SecureLoggerFactory.class) {
                if (provider == null) {
                    provider = loadProvider();
                }
            }
        }
        return provider;
    }

    private static LoggerProvider loadProvider() {
        // Try ServiceLoader first
        ServiceLoader<LoggerProvider> loader = ServiceLoader.load(LoggerProvider.class);
        for (LoggerProvider p : loader) {
            return p;
        }
        // Fallback to default
        return DefaultSecureLogger::new;
    }
}
