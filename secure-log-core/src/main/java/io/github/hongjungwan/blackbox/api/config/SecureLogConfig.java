package io.github.hongjungwan.blackbox.api.config;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

/**
 * SDK 설정. 로깅 모드, PII 마스킹, 암호화, Kafka, Circuit Breaker 설정 포함.
 */
@Getter
@Builder
public class SecureLogConfig {

    /** 로깅 모드: SYNC, ASYNC, FALLBACK */
    @Builder.Default
    private final LoggingMode mode = LoggingMode.ASYNC;

    /** 비동기 로깅용 버퍼 크기 (2의 제곱 권장) */
    @Builder.Default
    private final int bufferSize = 8192;

    /** PII 마스킹 활성화 */
    @Builder.Default
    private final boolean piiMaskingEnabled = true;

    /** 마스킹 대상 PII 패턴 */
    @Builder.Default
    private final List<String> piiPatterns = List.of("rrn", "credit_card", "password", "ssn");

    /** 암호화 활성화 */
    @Builder.Default
    private final boolean encryptionEnabled = true;

    /** KMS 엔드포인트 (레거시, AWS KMS는 kmsKeyId 사용) */
    private final String kmsEndpoint;

    /** AWS KMS Key ID 또는 ARN */
    private final String kmsKeyId;

    /** AWS KMS 리전 */
    @Builder.Default
    private final String kmsRegion = "ap-northeast-2";

    /** Cross-account 접근용 IAM Role ARN (선택) */
    private final String kmsRoleArn;

    /** KMS 타임아웃 (ms) */
    @Builder.Default
    private final int kmsTimeoutMs = 2000;

    /** KMS 장애 시 Fallback 키 사용 (운영 환경 비권장) */
    @Builder.Default
    private final boolean kmsFallbackEnabled = true;

    /** Kafka 브로커 주소 */
    private final String kafkaBootstrapServers;

    /** Kafka 토픽명 */
    @Builder.Default
    private final String kafkaTopic = "secure-hr-logs";

    /** Kafka 재시도 횟수 */
    @Builder.Default
    private final int kafkaRetries = 3;

    /** Kafka acks 설정: "all", "1", "0" */
    @Builder.Default
    private final String kafkaAcks = "all";

    /** Kafka 배치 크기 (bytes) */
    @Builder.Default
    private final int kafkaBatchSize = 16384;

    /** Kafka linger 시간 (ms) */
    @Builder.Default
    private final int kafkaLingerMs = 1;

    /** Kafka 압축 타입: none, gzip, snappy, lz4, zstd */
    @Builder.Default
    private final String kafkaCompressionType = "zstd";

    /** Kafka send() 최대 블로킹 시간 (ms) */
    @Builder.Default
    private final long kafkaMaxBlockMs = 5000;

    /** Kafka 보안 프로토콜 */
    @Builder.Default
    private final String kafkaSecurityProtocol = "PLAINTEXT";

    /** Circuit Breaker용 Fallback 디렉토리 */
    @Builder.Default
    private final String fallbackDirectory = "logs/fallback";

    /** Merkle Tree 무결성 검증 활성화 */
    @Builder.Default
    private final boolean integrityEnabled = true;

    /** Circuit Breaker 실패 임계치 */
    @Builder.Default
    private final int circuitBreakerFailureThreshold = 3;

    /** 초당 로그 Rate Limit */
    @Builder.Default
    private final long rateLimitLogsPerSecond = 20000;

    public enum LoggingMode {
        /** 동기 로깅 (호출자 블로킹) */
        SYNC,
        /** 비동기 로깅 (링 버퍼) */
        ASYNC,
        /** Fallback 모드 (디스크 전용, Kafka 없음) */
        FALLBACK
    }

    /** 개발용 기본 설정 */
    public static SecureLogConfig defaultConfig() {
        return SecureLogConfig.builder().build();
    }

    /**
     * 레거시 KMS 엔드포인트 기반 운영 설정.
     * @deprecated AWS KMS는 {@link #awsKmsProductionConfig(String, String, String)} 사용
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

    /** AWS KMS 기반 운영 설정 */
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
