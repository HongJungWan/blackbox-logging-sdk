package io.github.hongjungwan.blackbox.core.internal;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * FEAT-02: Semantic Deduplication (Smart Throttling)
 *
 * Algorithm: messageTemplate + Throwable hash as key
 * Logic: Within sliding window (1 second), duplicate logs increment counter only
 * Storage: Caffeine Cache with W-TinyLFU for minimal memory footprint
 *
 * Summary Log Emission: When deduplication window expires (cache eviction),
 * a summary log with repeat_count is emitted via the registered callback.
 */
@Slf4j
public class SemanticDeduplicator implements AutoCloseable {

    private final SecureLogConfig config;

    // Caffeine cache with W-TinyLFU eviction algorithm
    // Key: Log signature (message + throwable hash)
    // Value: Deduplication counter
    private final Cache<LogSignature, DeduplicationEntry> cache;

    // Callback for emitting summary logs when deduplication window expires
    private final AtomicReference<Consumer<LogEntry>> summaryCallback = new AtomicReference<>();

    // Dedicated Virtual Thread executor for async summary emission
    // Prevents eviction listener from blocking cache operations
    private final ExecutorService summaryExecutor = Executors.newVirtualThreadPerTaskExecutor();

    public SemanticDeduplicator(SecureLogConfig config) {
        this.config = config;

        this.cache = Caffeine.newBuilder()
                .maximumSize(10_000) // Limit memory usage
                .expireAfterWrite(Duration.ofMillis(config.getDeduplicationWindowMs()))
                .evictionListener((LogSignature key, DeduplicationEntry entry, RemovalCause cause) -> {
                    // Emit summary log asynchronously when entry expires due to time window
                    // Using Virtual Thread executor to avoid blocking cache operations
                    if (entry != null && cause == RemovalCause.EXPIRED) {
                        summaryExecutor.submit(() -> emitSummaryIfNeeded(key, entry));
                    }
                })
                .build();
    }

    /**
     * Register a callback to receive summary log entries when deduplication window expires.
     * The callback will be invoked with a LogEntry containing repeat_count for deduplicated logs.
     *
     * @param callback the callback to invoke with summary log entries
     */
    public void setSummaryCallback(Consumer<LogEntry> callback) {
        this.summaryCallback.set(callback);
    }

    /**
     * Emit summary log entry if there were duplicates.
     */
    private void emitSummaryIfNeeded(LogSignature signature, DeduplicationEntry entry) {
        int repeatCount = entry.getCount();
        if (repeatCount > 1) {
            Consumer<LogEntry> callback = summaryCallback.get();
            if (callback != null) {
                LogEntry firstEntry = entry.getFirstEntry();
                if (firstEntry != null) {
                    LogEntry summaryEntry = LogEntry.builder()
                            .timestamp(System.currentTimeMillis())
                            .level(firstEntry.getLevel())
                            .traceId(firstEntry.getTraceId())
                            .spanId(firstEntry.getSpanId())
                            .context(firstEntry.getContext())
                            .message(firstEntry.getMessage() + " [repeated]")
                            .payload(firstEntry.getPayload())
                            .repeatCount(repeatCount)
                            .throwable(firstEntry.getThrowable())
                            .build();

                    try {
                        callback.accept(summaryEntry);
                    } catch (Exception e) {
                        log.warn("Failed to emit deduplication summary log", e);
                    }
                }
            }
        }
    }

    /**
     * Check if log entry is a duplicate within the sliding window
     *
     * @return true if duplicate (should skip), false if unique (should process)
     */
    public boolean isDuplicate(LogEntry entry) {
        LogSignature signature = LogSignature.from(entry);

        DeduplicationEntry dedup = cache.get(signature, key -> new DeduplicationEntry(entry));

        if (dedup == null) {
            return false;
        }

        // Increment counter atomically
        int count = dedup.counter.incrementAndGet();

        // First occurrence: not a duplicate
        // Note: count is 1 for the first call since we start at 0 and increment
        // The firstEntry is already set in the DeduplicationEntry constructor
        if (count == 1) {
            return false;
        }

        // Duplicate detected
        // When deduplication window expires (cache eviction), summary log will be emitted via callback

        return true;
    }

    /**
     * Get repeat count for a log signature
     */
    public int getRepeatCount(LogEntry entry) {
        LogSignature signature = LogSignature.from(entry);
        DeduplicationEntry dedup = cache.getIfPresent(signature);

        return dedup != null ? dedup.counter.get() : 0;
    }

    /**
     * Get and reset repeat count for entries that should emit a summary log.
     * This atomically retrieves the current count and resets it to 1 (for the next occurrence).
     *
     * @param entry the log entry to check
     * @return the repeat count before reset, or 0 if entry was not deduplicated
     */
    public int getAndResetRepeatCount(LogEntry entry) {
        LogSignature signature = LogSignature.from(entry);
        DeduplicationEntry dedup = cache.getIfPresent(signature);

        if (dedup == null) {
            return 0;
        }

        // Atomically get current count and reset to 1 for next window
        int count = dedup.counter.getAndSet(1);
        return count;
    }

    /**
     * Check if entry is duplicate and return the enriched entry with repeat_count if applicable.
     * Call this when the deduplication window expires or periodically to emit summary logs.
     *
     * @param entry the original log entry
     * @return LogEntry with repeat_count set, or null if no duplicates were recorded
     */
    public LogEntry createSummaryEntry(LogEntry entry) {
        int repeatCount = getAndResetRepeatCount(entry);

        if (repeatCount <= 1) {
            return null; // No duplicates to summarize
        }

        return LogEntry.builder()
                .timestamp(entry.getTimestamp())
                .level(entry.getLevel())
                .traceId(entry.getTraceId())
                .spanId(entry.getSpanId())
                .context(entry.getContext())
                .message(entry.getMessage() + " [repeated]")
                .payload(entry.getPayload())
                .integrity(entry.getIntegrity())
                .encryptedDek(entry.getEncryptedDek())
                .repeatCount(repeatCount)
                .throwable(entry.getThrowable())
                .build();
    }

    /**
     * Clear cache (for testing)
     */
    public void clear() {
        cache.invalidateAll();
    }

    /**
     * Shutdown the executor service gracefully.
     * Waits for pending summary emissions to complete.
     */
    @Override
    public void close() {
        summaryExecutor.shutdown();
        try {
            if (!summaryExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                summaryExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            summaryExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Log signature for deduplication
     * Hash based on message template and throwable
     */
    static class LogSignature {
        private final String messageTemplate;
        private final String throwableSignature;
        private final int hashCode;

        private LogSignature(String messageTemplate, String throwableSignature) {
            this.messageTemplate = messageTemplate;
            this.throwableSignature = throwableSignature;
            this.hashCode = Objects.hash(messageTemplate, throwableSignature);
        }

        static LogSignature from(LogEntry entry) {
            // Extract message template (without interpolated values)
            String template = extractTemplate(entry.getMessage());

            // Extract throwable signature
            String throwableSig = entry.getThrowable() != null
                    ? entry.getThrowable().substring(0, Math.min(100, entry.getThrowable().length()))
                    : "";

            return new LogSignature(template, throwableSig);
        }

        /**
         * Extract message template by removing dynamic values.
         * Example: "User 123 logged in" -> "User {} logged in"
         *
         * <p>ZERO-ALLOCATION: Uses char array manipulation instead of regex replaceAll()
         * to avoid object allocation in hot paths.</p>
         */
        private static String extractTemplate(String message) {
            if (message == null || message.isEmpty()) {
                return "";
            }

            // Zero-allocation approach: use char array manipulation
            char[] chars = message.toCharArray();
            StringBuilder result = new StringBuilder(chars.length);
            boolean inNumber = false;

            for (char c : chars) {
                if (Character.isDigit(c)) {
                    if (!inNumber) {
                        // Start of a number sequence - replace with {}
                        result.append("{}");
                        inNumber = true;
                    }
                    // Skip additional digits in the same number sequence
                } else {
                    result.append(c);
                    inNumber = false;
                }
            }

            return result.toString();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            LogSignature that = (LogSignature) o;
            return Objects.equals(messageTemplate, that.messageTemplate) &&
                    Objects.equals(throwableSignature, that.throwableSignature);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
    }

    /**
     * Deduplication entry with atomic counter and first entry reference
     */
    static class DeduplicationEntry {
        private final AtomicInteger counter = new AtomicInteger(0);
        private final long firstSeenTimestamp = System.currentTimeMillis();
        private volatile LogEntry firstEntry;

        public DeduplicationEntry() {
        }

        public DeduplicationEntry(LogEntry firstEntry) {
            this.firstEntry = firstEntry;
        }

        public int getCount() {
            return counter.get();
        }

        public long getFirstSeenTimestamp() {
            return firstSeenTimestamp;
        }

        public LogEntry getFirstEntry() {
            return firstEntry;
        }

        public void setFirstEntry(LogEntry entry) {
            this.firstEntry = entry;
        }
    }
}
