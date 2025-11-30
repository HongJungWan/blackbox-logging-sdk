package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.api.interceptor.LogInterceptor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

/**
 * Collection of common interceptors for typical use cases.
 *
 * <p>All interceptors are fail-safe (exceptions don't break the chain).</p>
 */
@Slf4j
public final class BuiltInInterceptors {

    private BuiltInInterceptors() {}

    /**
     * Context Enrichment Interceptor.
     * Automatically adds trace context to log entries.
     */
    public static LogInterceptor contextEnrichment() {
        return (entry, chain) -> {
            LoggingContext ctx = LoggingContext.current();

            // Build enhanced context
            Map<String, Object> enrichedContext = new HashMap<>();
            if (entry.getContext() != null) {
                enrichedContext.putAll(entry.getContext());
            }

            // Add trace IDs if not present
            String traceId = entry.getTraceId();
            String spanId = entry.getSpanId();

            if (traceId == null || traceId.isEmpty()) {
                traceId = ctx.getTraceId();
            }
            if (spanId == null || spanId.isEmpty()) {
                spanId = ctx.getSpanId();
            }

            // Add baggage items to context
            ctx.getBaggage().forEach((k, v) -> {
                if (!enrichedContext.containsKey(k)) {
                    enrichedContext.put(k, v);
                }
            });

            LogEntry enriched = LogEntry.builder()
                    .timestamp(entry.getTimestamp())
                    .level(entry.getLevel())
                    .traceId(traceId)
                    .spanId(spanId)
                    .context(enrichedContext)
                    .message(entry.getMessage())
                    .payload(entry.getPayload())
                    .integrity(entry.getIntegrity())
                    .encryptedDek(entry.getEncryptedDek())
                    .repeatCount(entry.getRepeatCount())
                    .throwable(entry.getThrowable())
                    .build();

            return chain.proceed(enriched);
        };
    }

    /**
     * Sampling Interceptor.
     * Drop logs based on sampling rate (for high-volume scenarios).
     */
    public static LogInterceptor sampling(double rate) {
        if (rate <= 0) {
            return (entry, chain) -> null; // Drop all
        }
        if (rate >= 1.0) {
            return (entry, chain) -> chain.proceed(entry); // Keep all
        }

        return (entry, chain) -> {
            if (Math.random() < rate) {
                return chain.proceed(entry);
            }
            return null; // Sampled out
        };
    }

    /**
     * Level Filter Interceptor.
     * Filter logs by level.
     */
    public static LogInterceptor levelFilter(Set<String> allowedLevels) {
        return (entry, chain) -> {
            if (allowedLevels.contains(entry.getLevel())) {
                return chain.proceed(entry);
            }
            return null;
        };
    }

    /**
     * Field Redaction Interceptor.
     * Remove sensitive fields before logging (beyond masking).
     */
    public static LogInterceptor fieldRedaction(Set<String> fieldsToRedact) {
        return (entry, chain) -> {
            if (entry.getPayload() == null) {
                return chain.proceed(entry);
            }

            Map<String, Object> redacted = new HashMap<>(entry.getPayload());
            fieldsToRedact.forEach(field -> redacted.put(field, "[REDACTED]"));

            LogEntry redactedEntry = LogEntry.builder()
                    .timestamp(entry.getTimestamp())
                    .level(entry.getLevel())
                    .traceId(entry.getTraceId())
                    .spanId(entry.getSpanId())
                    .context(entry.getContext())
                    .message(entry.getMessage())
                    .payload(redacted)
                    .integrity(entry.getIntegrity())
                    .encryptedDek(entry.getEncryptedDek())
                    .repeatCount(entry.getRepeatCount())
                    .throwable(entry.getThrowable())
                    .build();

            return chain.proceed(redactedEntry);
        };
    }

    /**
     * Conditional Interceptor.
     * Apply interceptor only when condition is met.
     */
    public static LogInterceptor conditional(
            Predicate<LogEntry> condition,
            LogInterceptor interceptor) {
        return (entry, chain) -> {
            if (condition.test(entry)) {
                return interceptor.intercept(entry, chain);
            }
            return chain.proceed(entry);
        };
    }

    /**
     * Metrics Interceptor.
     * Collect processing metrics.
     */
    public static LogInterceptor metrics(MetricsCollector collector) {
        return (entry, chain) -> {
            long startTime = System.nanoTime();

            try {
                LogEntry result = chain.proceed(entry);

                long duration = System.nanoTime() - startTime;
                collector.recordSuccess(entry.getLevel(), duration);

                return result;

            } catch (Exception e) {
                long duration = System.nanoTime() - startTime;
                collector.recordFailure(entry.getLevel(), duration, e);
                throw e;
            }
        };
    }

    /**
     * Rate Counter Interceptor.
     * Count logs per level/category.
     */
    public static LogInterceptor rateCounter() {
        return new RateCounterInterceptor();
    }

    /**
     * Error Context Enrichment.
     * Add extra context when throwable is present (stored as String in LogEntry).
     */
    public static LogInterceptor errorEnrichment() {
        return (entry, chain) -> {
            String throwableStr = entry.getThrowable();
            if (throwableStr == null || throwableStr.isEmpty()) {
                return chain.proceed(entry);
            }

            Map<String, Object> enrichedContext = new HashMap<>();
            if (entry.getContext() != null) {
                enrichedContext.putAll(entry.getContext());
            }

            // Parse throwable string (format: "ClassName: message")
            int colonIndex = throwableStr.indexOf(':');
            if (colonIndex > 0) {
                enrichedContext.put("error.type", throwableStr.substring(0, colonIndex).trim());
                if (colonIndex + 1 < throwableStr.length()) {
                    enrichedContext.put("error.message", throwableStr.substring(colonIndex + 1).trim());
                }
            } else {
                enrichedContext.put("error.type", throwableStr);
            }

            LogEntry enriched = LogEntry.builder()
                    .timestamp(entry.getTimestamp())
                    .level(entry.getLevel())
                    .traceId(entry.getTraceId())
                    .spanId(entry.getSpanId())
                    .context(enrichedContext)
                    .message(entry.getMessage())
                    .payload(entry.getPayload())
                    .integrity(entry.getIntegrity())
                    .encryptedDek(entry.getEncryptedDek())
                    .repeatCount(entry.getRepeatCount())
                    .throwable(entry.getThrowable())
                    .build();

            return chain.proceed(enriched);
        };
    }

    /**
     * Metrics collector interface.
     */
    public interface MetricsCollector {
        void recordSuccess(String level, long durationNanos);
        void recordFailure(String level, long durationNanos, Exception e);
    }

    /**
     * Rate counter implementation.
     */
    private static class RateCounterInterceptor implements LogInterceptor {
        private final Map<String, AtomicLong> counters = new HashMap<>();

        @Override
        public LogEntry intercept(LogEntry entry, Chain chain) {
            counters.computeIfAbsent(entry.getLevel(), k -> new AtomicLong())
                    .incrementAndGet();
            return chain.proceed(entry);
        }

        public long getCount(String level) {
            AtomicLong counter = counters.get(level);
            return counter != null ? counter.get() : 0;
        }

        public Map<String, Long> getAllCounts() {
            Map<String, Long> result = new HashMap<>();
            counters.forEach((k, v) -> result.put(k, v.get()));
            return result;
        }
    }
}
