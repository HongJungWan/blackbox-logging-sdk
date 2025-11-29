package io.github.hongjungwan.blackbox.core.config;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

/**
 * Configuration for SecureHR Logging SDK
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
     * Ring buffer size for async logging
     */
    @Builder.Default
    private final int bufferSize = 8192;

    /**
     * Enable PII masking
     */
    @Builder.Default
    private final boolean piiMaskingEnabled = true;

    /**
     * PII patterns to mask (rrn, credit_card, password, etc.)
     */
    @Builder.Default
    private final List<String> piiPatterns = List.of("rrn", "credit_card", "password", "ssn");

    /**
     * Enable encryption
     */
    @Builder.Default
    private final boolean encryptionEnabled = true;

    /**
     * KMS endpoint for key management
     */
    private final String kmsEndpoint;

    /**
     * KMS timeout in milliseconds
     */
    @Builder.Default
    private final int kmsTimeoutMs = 2000;

    /**
     * Enable semantic deduplication
     */
    @Builder.Default
    private final boolean deduplicationEnabled = true;

    /**
     * Deduplication window in milliseconds
     */
    @Builder.Default
    private final long deduplicationWindowMs = 1000;

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
     * Fallback directory for circuit breaker
     */
    @Builder.Default
    private final String fallbackDirectory = "logs/fallback";

    /**
     * Enable Merkle Tree integrity
     */
    @Builder.Default
    private final boolean integrityEnabled = true;

    public enum LoggingMode {
        SYNC,
        ASYNC,
        FALLBACK
    }

    public static SecureLogConfig defaultConfig() {
        return SecureLogConfig.builder().build();
    }

    public static SecureLogConfig productionConfig(String kmsEndpoint, String kafkaBootstrapServers) {
        return SecureLogConfig.builder()
                .mode(LoggingMode.ASYNC)
                .kmsEndpoint(kmsEndpoint)
                .kafkaBootstrapServers(kafkaBootstrapServers)
                .encryptionEnabled(true)
                .piiMaskingEnabled(true)
                .integrityEnabled(true)
                .deduplicationEnabled(true)
                .build();
    }
}
