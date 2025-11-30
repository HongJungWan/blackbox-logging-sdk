package io.github.hongjungwan.blackbox.spi;

import io.github.hongjungwan.blackbox.api.SecureLogger;

/**
 * SPI for providing SecureLogger implementations.
 *
 * <p>Implement this interface to provide a custom logger implementation.
 * Register via ServiceLoader in META-INF/services/.</p>
 *
 * <h2>Implementation Example:</h2>
 * <pre>{@code
 * public class CustomLoggerProvider implements LoggerProvider {
 *     @Override
 *     public SecureLogger getLogger(String name) {
 *         return new CustomSecureLogger(name);
 *     }
 * }
 * }</pre>
 *
 * @since 8.0.0
 */
@FunctionalInterface
public interface LoggerProvider {

    /**
     * Create a logger with the specified name.
     *
     * @param name The logger name (typically class name)
     * @return A SecureLogger instance
     */
    SecureLogger getLogger(String name);
}
