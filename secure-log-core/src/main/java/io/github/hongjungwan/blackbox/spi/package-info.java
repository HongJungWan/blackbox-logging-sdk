/**
 * Service Provider Interfaces (SPI) for SecureHR Logging SDK.
 *
 * <p>This package contains interfaces for extending SDK functionality.
 * Implement these interfaces to customize:</p>
 *
 * <ul>
 *   <li>{@link io.github.hongjungwan.blackbox.spi.LoggerProvider} - Custom logger implementation</li>
 *   <li>{@link io.github.hongjungwan.blackbox.spi.MaskingStrategy} - Custom PII masking</li>
 *   <li>{@link io.github.hongjungwan.blackbox.spi.EncryptionProvider} - KMS integration</li>
 *   <li>{@link io.github.hongjungwan.blackbox.spi.TransportProvider} - Log destination</li>
 *   <li>{@link io.github.hongjungwan.blackbox.spi.IntegrityProvider} - Tamper detection</li>
 * </ul>
 *
 * <h2>Registration:</h2>
 * <p>Register implementations via ServiceLoader:</p>
 * <pre>
 * META-INF/services/io.github.hongjungwan.blackbox.spi.MaskingStrategy
 * </pre>
 *
 * @since 8.0.0
 */
package io.github.hongjungwan.blackbox.spi;
