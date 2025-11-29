package io.github.hongjungwan.blackbox.core.deduplication;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * FEAT-02: Semantic Deduplication (Smart Throttling)
 *
 * Algorithm: messageTemplate + Throwable hash as key
 * Logic: Within sliding window (1 second), duplicate logs increment counter only
 * Storage: Caffeine Cache with W-TinyLFU for minimal memory footprint
 */
public class SemanticDeduplicator {

    private final SecureLogConfig config;

    // Caffeine cache with W-TinyLFU eviction algorithm
    // Key: Log signature (message + throwable hash)
    // Value: Deduplication counter
    private final Cache<LogSignature, DeduplicationEntry> cache;

    public SemanticDeduplicator(SecureLogConfig config) {
        this.config = config;

        this.cache = Caffeine.newBuilder()
                .maximumSize(10_000) // Limit memory usage
                .expireAfterWrite(Duration.ofMillis(config.getDeduplicationWindowMs()))
                .build();
    }

    /**
     * Check if log entry is a duplicate within the sliding window
     *
     * @return true if duplicate (should skip), false if unique (should process)
     */
    public boolean isDuplicate(LogEntry entry) {
        LogSignature signature = LogSignature.from(entry);

        DeduplicationEntry dedup = cache.get(signature, key -> new DeduplicationEntry());

        if (dedup == null) {
            return false;
        }

        // Increment counter atomically
        int count = dedup.counter.incrementAndGet();

        // First occurrence: not a duplicate
        if (count == 1) {
            return false;
        }

        // Duplicate detected
        // On window expiration, a summary log with repeat_count will be sent
        // (Implementation would require scheduled task or callback)

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
     * Clear cache (for testing)
     */
    public void clear() {
        cache.invalidateAll();
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
         * Extract message template by removing dynamic values
         * Example: "User 123 logged in" -> "User {} logged in"
         */
        private static String extractTemplate(String message) {
            if (message == null) {
                return "";
            }

            // Simple heuristic: replace numbers with {}
            // More sophisticated: use SLF4J message pattern
            return message.replaceAll("\\d+", "{}");
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
     * Deduplication entry with atomic counter
     */
    static class DeduplicationEntry {
        private final AtomicInteger counter = new AtomicInteger(0);
        private final long firstSeenTimestamp = System.currentTimeMillis();

        public int getCount() {
            return counter.get();
        }

        public long getFirstSeenTimestamp() {
            return firstSeenTimestamp;
        }
    }
}
