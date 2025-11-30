package io.github.hongjungwan.blackbox.core.interceptor;

import io.github.hongjungwan.blackbox.core.domain.LogEntry;

/**
 * FEAT-10: Interceptor/Hook System (Sentry/Datadog Pattern)
 *
 * Extensible log processing interceptor chain.
 * Allows custom processing at each stage of the pipeline.
 *
 * Based on:
 * - Sentry SDK Hooks
 * - Datadog APM Interceptors
 * - OkHttp Interceptor Chain
 *
 * @see <a href="https://github.com/getsentry/sentry-java">Sentry Java</a>
 * @see <a href="https://github.com/DataDog/dd-trace-java">Datadog Trace Java</a>
 */
@FunctionalInterface
public interface LogInterceptor {

    /**
     * Intercept and process a log entry.
     *
     * @param entry The log entry being processed
     * @param chain The interceptor chain to continue processing
     * @return The processed log entry, or null to drop the log
     */
    LogEntry intercept(LogEntry entry, Chain chain);

    /**
     * Interceptor chain for chained processing
     */
    interface Chain {
        /**
         * Continue processing with the next interceptor
         */
        LogEntry proceed(LogEntry entry);

        /**
         * Get the current processing stage
         */
        ProcessingStage stage();

        /**
         * Get interceptor chain metadata
         */
        ChainMetadata metadata();
    }

    /**
     * Processing stages in the log pipeline
     */
    enum ProcessingStage {
        /** Before any processing */
        PRE_PROCESS,
        /** After deduplication check */
        POST_DEDUP,
        /** After PII masking */
        POST_MASK,
        /** After integrity hash */
        POST_INTEGRITY,
        /** After encryption */
        POST_ENCRYPT,
        /** Before transport */
        PRE_TRANSPORT,
        /** After successful transport */
        POST_TRANSPORT,
        /** On transport failure */
        ON_ERROR
    }

    /**
     * Chain metadata for interceptors
     */
    interface ChainMetadata {
        long startTimeNanos();
        int interceptorCount();
        int currentIndex();
    }

    /**
     * Priority levels for interceptor ordering
     */
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
