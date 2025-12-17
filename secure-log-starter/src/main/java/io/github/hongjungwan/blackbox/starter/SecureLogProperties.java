package io.github.hongjungwan.blackbox.starter;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * SecureHR Logging SDK 설정 Properties (prefix: secure-hr.logging).
 * Console 출력을 기본으로 사용.
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

    /** 비동기 로깅용 Consumer 스레드 수 */
    private int consumerThreads = 2;

    /** PII 마스킹 설정 */
    private PiiMaskingProperties piiMasking = new PiiMaskingProperties();

    /** 보안 설정 */
    private SecurityProperties security = new SecurityProperties();

    /** 감사(Audit) 설정 */
    private AuditProperties audit = new AuditProperties();

    /** 오류 발생 시 Fallback 저장 디렉토리 */
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

        /** 비상 모드용 RSA 공개키 (Base64 인코딩, X.509 형식) */
        private String emergencyPublicKey;
    }

    @Data
    public static class AuditProperties {
        /** @AuditContext AOP 활성화 여부 */
        private boolean enabled = true;

        /** 감사 로그 기록 활성화 여부 */
        private boolean logEnabled = true;
    }
}
