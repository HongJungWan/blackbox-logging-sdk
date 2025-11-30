package io.github.hongjungwan.blackbox.starter;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
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
     * Kafka configuration
     */
    private KafkaProperties kafka = new KafkaProperties();

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
        private String kmsKeyId;
        private String kmsRegion = "ap-northeast-2";
        private String kmsRoleArn;
        private int kmsTimeoutMs = 2000;
        private boolean kmsFallbackEnabled = true;
    }

    @Data
    public static class KafkaProperties {
        private String bootstrapServers;
        private String topic = "secure-hr-logs";
        private int retries = 3;
        private String acks = "all";
        private int batchSize = 16384;
        private int lingerMs = 1;
        private String compressionType = "zstd";
        private long maxBlockMs = 5000;
        private String securityProtocol = "PLAINTEXT";
    }
}
