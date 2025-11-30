package io.github.hongjungwan.blackbox.api.interceptor;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;

/**
 * Extensible log processing interceptor.
 *
 * <p>Allows custom processing at each stage of the log pipeline.
 * Follows the Chain of Responsibility pattern (OkHttp Interceptor style).</p>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * // Custom interceptor to add application metadata
 * LogInterceptor appMetadata = (entry, chain) -> {
 *     LogEntry enriched = LogEntry.builder()
 *             .timestamp(entry.getTimestamp())
 *             .level(entry.getLevel())
 *             .message(entry.getMessage())
 *             .context(Map.of(
 *                 "app.name", "hr-system",
 *                 "app.version", "1.0.0"
 *             ))
 *             .build();
 *     return chain.proceed(enriched);
 * };
 *
 * // Sampling interceptor (drop 90% of DEBUG logs)
 * LogInterceptor sampler = (entry, chain) -> {
 *     if ("DEBUG".equals(entry.getLevel()) && Math.random() > 0.1) {
 *         return null; // Drop
 *     }
 *     return chain.proceed(entry);
 * };
 * }</pre>
 *
 * @since 8.0.0
 * @see Chain
 * @see ProcessingStage
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
     * Interceptor chain for chained processing.
     */
    interface Chain {
        /**
         * Continue processing with the next interceptor.
         */
        LogEntry proceed(LogEntry entry);

        /**
         * Get the current processing stage.
         */
        ProcessingStage stage();

        /**
         * Get interceptor chain metadata.
         */
        ChainMetadata metadata();
    }

    /**
     * Processing stages in the log pipeline.
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
     * Chain metadata for interceptors.
     */
    interface ChainMetadata {
        /** Start time of chain execution in nanoseconds */
        long startTimeNanos();

        /** Total number of interceptors in chain */
        int interceptorCount();

        /** Current interceptor index (0-based) */
        int currentIndex();
    }

    /**
     * Priority levels for interceptor ordering.
     * Lower value = higher priority (executes first).
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
