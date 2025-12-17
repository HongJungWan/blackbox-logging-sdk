package io.github.hongjungwan.blackbox.api.config;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

/**
 * SDK 설정. 로깅 모드, PII 마스킹, 암호화, Fallback 설정 포함.
 * Console 출력을 기본으로 사용.
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

    /** 비동기 로깅용 Consumer 스레드 수 (기본: 2) */
    @Builder.Default
    private final int consumerThreads = 2;

    /** PII 마스킹 활성화 */
    @Builder.Default
    private final boolean piiMaskingEnabled = true;

    /** 마스킹 대상 PII 패턴 */
    @Builder.Default
    private final List<String> piiPatterns = List.of("rrn", "credit_card", "password", "ssn");

    /** 암호화 활성화 */
    @Builder.Default
    private final boolean encryptionEnabled = true;

    /** Fallback 디렉토리 (오류 시 파일 저장, 키 저장 시) */
    @Builder.Default
    private final String fallbackDirectory = "logs/fallback";

    /** Merkle Tree 무결성 검증 활성화 */
    @Builder.Default
    private final boolean integrityEnabled = true;

    /** 초당 로그 Rate Limit */
    @Builder.Default
    private final long rateLimitLogsPerSecond = 20000;

    public enum LoggingMode {
        /** 동기 로깅 (호출자 블로킹) */
        SYNC,
        /** 비동기 로깅 (링 버퍼) */
        ASYNC,
        /** Fallback 모드 (디스크 전용) */
        FALLBACK
    }

    /** 개발용 기본 설정 */
    public static SecureLogConfig defaultConfig() {
        return SecureLogConfig.builder().build();
    }

    /** 프로덕션 설정 */
    public static SecureLogConfig productionConfig() {
        return SecureLogConfig.builder()
                .mode(LoggingMode.ASYNC)
                .encryptionEnabled(true)
                .piiMaskingEnabled(true)
                .integrityEnabled(true)
                .build();
    }
}
