package io.github.hongjungwan.blackbox.api.interceptor;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;

/**
 * 로그 파이프라인 Interceptor. Chain of Responsibility 패턴으로 단계별 커스텀 처리 지원.
 */
@FunctionalInterface
public interface LogInterceptor {

    /**
     * 로그 엔트리 인터셉트. null 반환 시 로그 드롭.
     */
    LogEntry intercept(LogEntry entry, Chain chain);

    /** Interceptor 체인 */
    interface Chain {
        /** 다음 Interceptor로 진행 */
        LogEntry proceed(LogEntry entry);

        /** 현재 처리 단계 */
        ProcessingStage stage();

        /** 체인 메타데이터 */
        ChainMetadata metadata();
    }

    /** 파이프라인 처리 단계 */
    enum ProcessingStage {
        /** 처리 전 */
        PRE_PROCESS,
        /** 중복 제거 후 */
        POST_DEDUP,
        /** PII 마스킹 후 */
        POST_MASK,
        /** 무결성 해시 후 */
        POST_INTEGRITY,
        /** 암호화 후 */
        POST_ENCRYPT,
        /** 전송 전 */
        PRE_TRANSPORT,
        /** 전송 성공 후 */
        POST_TRANSPORT,
        /** 에러 발생 시 */
        ON_ERROR
    }

    /** 체인 메타데이터 */
    interface ChainMetadata {
        /** 체인 실행 시작 시간 (nanos) */
        long startTimeNanos();

        /** 체인 내 Interceptor 총 개수 */
        int interceptorCount();

        /** 현재 Interceptor 인덱스 (0-based) */
        int currentIndex();
    }

    /** Interceptor 우선순위. 낮을수록 먼저 실행. */
    enum Priority {
        HIGHEST(0),
        HIGH(100),
        NORMAL(500),
        LOW(900),
        LOWEST(1000);

        private final int value;

        Priority(int value) {
            this.value = value;
        }

        public int value() {
            return value;
        }
    }
}
