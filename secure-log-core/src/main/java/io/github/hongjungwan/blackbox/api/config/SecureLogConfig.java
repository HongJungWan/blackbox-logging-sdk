package io.github.hongjungwan.blackbox.api.config;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

/**
 * Configuration for SecureHR Logging SDK.
 *
 * <p>Provides comprehensive configuration options for:</p>
 * <ul>
 *   <li>Logging mode (SYNC, ASYNC, FALLBACK)</li>
 *   <li>PII masking patterns</li>
 *   <li>Encryption settings (AWS KMS integration)</li>
 *   <li>Kafka transport configuration</li>
 *   <li>Resilience settings (circuit breaker, rate limiter)</li>
 * </ul>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * // Development configuration
 * SecureLogConfig config = SecureLogConfig.defaultConfig();
 *
 * // Production configuration with AWS KMS
 * SecureLogConfig config = SecureLogConfig.awsKmsProductionConfig(
 *     "arn:aws:kms:ap-northeast-2:123456789:key/xxx",
 *     "ap-northeast-2",
 *     "kafka-broker:9092"
 * );
 * }</pre>
 *
 * @since 8.0.0
 */
@Getter
@Builder
public class SecureLogConfig {

    /**
     * Operating mode: SYNC, ASYNC, FALLBACK
     */
    @Builder.Default
    private final LoggingMode mode = LoggingMode.ASYNC;

    /**
     * Ring buffer size for async logging (power of 2 recommended)
     */
    @Builder.Default
    private final int bufferSize = 8192;

    /**
     * Enable PII masking
     */
    @Builder.Default
    private final boolean piiMaskingEnabled = true;

    /**
     * PII patterns to mask (rrn, credit_card, password, ssn, etc.)
     */
    @Builder.Default
    private final List<String> piiPatterns = List.of("rrn", "credit_card", "password", "ssn");

    /**
     * Enable encryption
     */
    @Builder.Default
    private final boolean encryptionEnabled = true;

    /**
     * KMS endpoint for key management (legacy, use kmsKeyId for AWS KMS)
     */
    private final String kmsEndpoint;

    /**
     * AWS KMS Key ID or ARN
     */
    private final String kmsKeyId;

    /**
     * AWS KMS Region (e.g., ap-northeast-2)
     */
    @Builder.Default
    private final String kmsRegion = "ap-northeast-2";

    /**
     * AWS IAM Role ARN for cross-account access (optional)
     */
    private final String kmsRoleArn;

    /**
     * KMS timeout in milliseconds
     */
    @Builder.Default
    private final int kmsTimeoutMs = 2000;

    /**
     * Use embedded fallback key when KMS is unavailable (NOT for production)
     */
    @Builder.Default
    private final boolean kmsFallbackEnabled = true;

    /**
     * Kafka bootstrap servers (for production log shipping)
     */
    private final String kafkaBootstrapServers;

    /**
     * Kafka topic for logs
     */
    @Builder.Default
    private final String kafkaTopic = "secure-hr-logs";

    /**
     * Kafka retry attempts
     */
    @Builder.Default
    private final int kafkaRetries = 3;

    /**
     * Kafka acks configuration: "all", "1", "0"
     */
    @Builder.Default
    private final String kafkaAcks = "all";

    /**
     * Kafka batch size in bytes
     */
    @Builder.Default
    private final int kafkaBatchSize = 16384;

    /**
     * Kafka linger time in milliseconds
     */
    @Builder.Default
    private final int kafkaLingerMs = 1;

    /**
     * Kafka compression type: none, gzip, snappy, lz4, zstd
     */
    @Builder.Default
    private final String kafkaCompressionType = "zstd";

    /**
     * Kafka max block time in milliseconds (send() blocking time)
     */
    @Builder.Default
    private final long kafkaMaxBlockMs = 5000;

    /**
     * Kafka security protocol: PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL
     */
    @Builder.Default
    private final String kafkaSecurityProtocol = "PLAINTEXT";

    /**
     * Fallback directory for circuit breaker
     */
    @Builder.Default
    private final String fallbackDirectory = "logs/fallback";

    /**
     * Enable Merkle Tree integrity
     */
    @Builder.Default
    private final boolean integrityEnabled = true;

    /**
     * Circuit breaker failure threshold
     */
    @Builder.Default
    private final int circuitBreakerFailureThreshold = 3;

    /**
     * Rate limiter logs per second
     */
    @Builder.Default
    private final long rateLimitLogsPerSecond = 20000;

    public enum LoggingMode {
        /** Synchronous logging (blocks caller) */
        SYNC,
        /** Asynchronous logging with ring buffer */
        ASYNC,
        /** Fallback mode (disk-only, no Kafka) */
        FALLBACK
    }

    /**
     * Default configuration for development.
     */
    public static SecureLogConfig defaultConfig() {
        return SecureLogConfig.builder().build();
    }

    /**
     * Production configuration with legacy KMS endpoint.
     * @deprecated Use {@link #awsKmsProductionConfig(String, String, String)} for AWS KMS
     */
    @Deprecated
    public static SecureLogConfig productionConfig(String kmsEndpoint, String kafkaBootstrapServers) {
        return SecureLogConfig.builder()
                .mode(LoggingMode.ASYNC)
                .kmsEndpoint(kmsEndpoint)
                .kafkaBootstrapServers(kafkaBootstrapServers)
                .encryptionEnabled(true)
                .piiMaskingEnabled(true)
                .integrityEnabled(true)
                .kmsFallbackEnabled(false)
                .build();
    }

    /**
     * Production configuration with AWS KMS.
     */
    public static SecureLogConfig awsKmsProductionConfig(String kmsKeyId, String kmsRegion, String kafkaBootstrapServers) {
        return SecureLogConfig.builder()
                .mode(LoggingMode.ASYNC)
                .kmsKeyId(kmsKeyId)
                .kmsRegion(kmsRegion)
                .kafkaBootstrapServers(kafkaBootstrapServers)
                .kafkaAcks("all")
                .kafkaCompressionType("zstd")
                .encryptionEnabled(true)
                .piiMaskingEnabled(true)
                .integrityEnabled(true)
                .kmsFallbackEnabled(false)
                .build();
    }
}
