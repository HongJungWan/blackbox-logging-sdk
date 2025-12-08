package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.api.interceptor.LogInterceptor;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

/**
 * 내장 인터셉터 모음 (Sampling, LevelFilter, FieldRedaction 등). Fail-safe 설계.
 */
@Slf4j
public final class BuiltInInterceptors {

    private BuiltInInterceptors() {}

    /** 컨텍스트 보강 (trace/span ID, baggage 추가) */
    public static LogInterceptor contextEnrichment() {
        return (entry, chain) -> {
            LoggingContext ctx = LoggingContext.current();

            Map<String, Object> enrichedContext = new HashMap<>();
            if (entry.getContext() != null) {
                enrichedContext.putAll(entry.getContext());
            }

            String traceId = entry.getTraceId();
            String spanId = entry.getSpanId();

            if (traceId == null || traceId.isEmpty()) {
                traceId = ctx.getTraceId();
            }
            if (spanId == null || spanId.isEmpty()) {
                spanId = ctx.getSpanId();
            }

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

    /** 샘플링 (0.0-1.0 비율) */
    public static LogInterceptor sampling(double rate) {
        if (rate <= 0) {
            return (entry, chain) -> null;
        }
        if (rate >= 1.0) {
            return (entry, chain) -> chain.proceed(entry);
        }

        return (entry, chain) -> {
            if (ThreadLocalRandom.current().nextDouble() < rate) {
                return chain.proceed(entry);
            }
            return null;
        };
    }

    /** 레벨 필터 */
    public static LogInterceptor levelFilter(Set<String> allowedLevels) {
        return (entry, chain) -> {
            if (allowedLevels.contains(entry.getLevel())) {
                return chain.proceed(entry);
            }
            return null;
        };
    }

    /** 필드 삭제 ([REDACTED] 치환) */
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

    /** 조건부 인터셉터 */
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

    /** 메트릭 수집 */
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

    public static LogInterceptor rateCounter() {
        return new RateCounterInterceptor();
    }

    /** 에러 컨텍스트 보강 */
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

    public interface MetricsCollector {
        void recordSuccess(String level, long durationNanos);
        void recordFailure(String level, long durationNanos, Exception e);
    }

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
