package io.github.hongjungwan.blackbox.starter;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Configuration properties for SecureHR Logging SDK
 *
 * Binds to application.yml under 'secure-hr.logging'
 */
@Data
@ConfigurationProperties(prefix = "secure-hr.logging")
public class SecureLogProperties {

    /**
     * Enable/disable SDK
     */
    private boolean enabled = true;

    /**
     * Logging mode: SYNC, ASYNC, FALLBACK
     */
    private SecureLogConfig.LoggingMode mode = SecureLogConfig.LoggingMode.ASYNC;

    /**
     * Ring buffer size for async logging
     */
    private int bufferSize = 8192;

    /**
     * PII masking configuration
     */
    private PiiMaskingProperties piiMasking = new PiiMaskingProperties();

    /**
     * Security configuration
     */
    private SecurityProperties security = new SecurityProperties();

    /**
     * Enable semantic deduplication
     */
    private boolean deduplicationEnabled = true;

    /**
     * Deduplication window in milliseconds
     */
    private long deduplicationWindowMs = 1000;

    /**
     * Kafka bootstrap servers
     */
    private String kafkaBootstrapServers;

    /**
     * Kafka topic
     */
    private String kafkaTopic = "secure-hr-logs";

    /**
     * Kafka retry attempts
     */
    private int kafkaRetries = 3;

    /**
     * Fallback directory for circuit breaker
     */
    private String fallbackDirectory = "logs/fallback";

    @Data
    public static class PiiMaskingProperties {
        private boolean enabled = true;
        private List<String> patterns = List.of("rrn", "credit_card", "password", "ssn");
    }

    @Data
    public static class SecurityProperties {
        private boolean encryptionEnabled = true;
        private boolean integrityEnabled = true;
        private String kmsEndpoint;
        private int kmsTimeoutMs = 2000;
    }
}
