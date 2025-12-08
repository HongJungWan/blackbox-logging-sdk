package io.github.hongjungwan.blackbox.starter;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * SecureHR Logging SDK 설정 Properties (prefix: secure-hr.logging).
 */
@Data
@ConfigurationProperties(prefix = "secure-hr.logging")
public class SecureLogProperties {

    /** SDK 활성화 여부 */
    private boolean enabled = true;

    /** 로깅 모드: SYNC, ASYNC, FALLBACK */
    private SecureLogConfig.LoggingMode mode = SecureLogConfig.LoggingMode.ASYNC;

    /** 비동기 로깅용 Ring Buffer 크기 */
    private int bufferSize = 8192;

    /** PII 마스킹 설정 */
    private PiiMaskingProperties piiMasking = new PiiMaskingProperties();

    /** 보안 설정 */
    private SecurityProperties security = new SecurityProperties();

    /** Kafka 설정 */
    private KafkaProperties kafka = new KafkaProperties();

    /** Circuit Breaker 발동 시 Fallback 저장 디렉토리 */
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
