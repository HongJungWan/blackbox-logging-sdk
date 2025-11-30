package io.github.hongjungwan.blackbox.core.context;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * FEAT-09: Context Propagation System (OpenTelemetry Pattern)
 *
 * Thread-safe logging context that automatically propagates across:
 * - Thread boundaries (including Virtual Threads)
 * - Async operations
 * - External service calls
 *
 * Based on: OpenTelemetry Context, Datadog APM Scope
 *
 * @see <a href="https://github.com/open-telemetry/opentelemetry-java">OpenTelemetry Java</a>
 */
public final class LoggingContext {

    private static final ThreadLocal<LoggingContext> CURRENT = ThreadLocal.withInitial(LoggingContext::empty);

    // Immutable context data
    private final String traceId;
    private final String spanId;
    private final String parentSpanId;
    private final Map<String, String> baggage;
    private final Map<String, Object> attributes;

    private LoggingContext(Builder builder) {
        this.traceId = builder.traceId;
        this.spanId = builder.spanId;
        this.parentSpanId = builder.parentSpanId;
        this.baggage = Collections.unmodifiableMap(new HashMap<>(builder.baggage));
        this.attributes = Collections.unmodifiableMap(new HashMap<>(builder.attributes));
    }

    /**
     * Get current context from ThreadLocal
     */
    public static LoggingContext current() {
        return CURRENT.get();
    }

    /**
     * Create empty context
     */
    public static LoggingContext empty() {
        return builder().build();
    }

    /**
     * Create context from W3C Trace Context header
     * Format: 00-{trace-id}-{parent-id}-{flags}
     */
    public static LoggingContext fromTraceParent(String traceParent) {
        if (traceParent == null || traceParent.isEmpty()) {
            return empty();
        }

        String[] parts = traceParent.split("-");
        if (parts.length >= 3) {
            return builder()
                    .traceId(parts[1])
                    .spanId(generateSpanId())
                    .parentSpanId(parts[2])
                    .build();
        }
        return empty();
    }

    /**
     * Create new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Create builder from current context (for creating child spans)
     */
    public Builder toBuilder() {
        return new Builder()
                .traceId(this.traceId)
                .spanId(generateSpanId())
                .parentSpanId(this.spanId)
                .baggage(new HashMap<>(this.baggage))
                .attributes(new HashMap<>(this.attributes));
    }

    /**
     * Make this context current (attach to ThreadLocal)
     * Returns a Scope that should be closed when done
     */
    public Scope makeCurrent() {
        LoggingContext previous = CURRENT.get();
        CURRENT.set(this);
        return () -> CURRENT.set(previous);
    }

    /**
     * Create a child context for a new span
     */
    public LoggingContext createChild() {
        return toBuilder().build();
    }

    /**
     * Create a Runnable wrapper that propagates this context
     */
    public Runnable wrap(Runnable runnable) {
        return () -> {
            try (Scope ignored = this.makeCurrent()) {
                runnable.run();
            }
        };
    }

    /**
     * Create a Callable wrapper that propagates this context
     */
    public <T> java.util.concurrent.Callable<T> wrap(java.util.concurrent.Callable<T> callable) {
        return () -> {
            try (Scope ignored = this.makeCurrent()) {
                return callable.call();
            }
        };
    }

    /**
     * Export context as W3C Trace Context header
     */
    public String toTraceParent() {
        if (traceId == null || spanId == null) {
            return null;
        }
        return String.format("00-%s-%s-01", traceId, spanId);
    }

    /**
     * Export baggage as W3C Baggage header
     */
    public String toBaggageHeader() {
        if (baggage.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        baggage.forEach((k, v) -> {
            if (sb.length() > 0) sb.append(",");
            sb.append(k).append("=").append(v);
        });
        return sb.toString();
    }

    /**
     * Export context to MDC-compatible map
     */
    public Map<String, String> toMdc() {
        Map<String, String> mdc = new HashMap<>();
        if (traceId != null) mdc.put("traceId", traceId);
        if (spanId != null) mdc.put("spanId", spanId);
        if (parentSpanId != null) mdc.put("parentSpanId", parentSpanId);
        mdc.putAll(baggage);
        return mdc;
    }

    // Getters
    public String getTraceId() { return traceId; }
    public String getSpanId() { return spanId; }
    public String getParentSpanId() { return parentSpanId; }
    public Map<String, String> getBaggage() { return baggage; }
    public Map<String, Object> getAttributes() { return attributes; }

    public Optional<String> getBaggageItem(String key) {
        return Optional.ofNullable(baggage.get(key));
    }

    @SuppressWarnings("unchecked")
    public <T> Optional<T> getAttribute(String key) {
        return Optional.ofNullable((T) attributes.get(key));
    }

    /**
     * Generate random span ID (16 hex chars)
     */
    private static String generateSpanId() {
        return Long.toHexString(java.util.concurrent.ThreadLocalRandom.current().nextLong());
    }

    /**
     * Generate random trace ID (32 hex chars)
     */
    public static String generateTraceId() {
        return Long.toHexString(java.util.concurrent.ThreadLocalRandom.current().nextLong())
                + Long.toHexString(java.util.concurrent.ThreadLocalRandom.current().nextLong());
    }

    /**
     * Scope for context management (AutoCloseable)
     */
    @FunctionalInterface
    public interface Scope extends AutoCloseable {
        @Override
        void close(); // No exception
    }

    /**
     * Builder for immutable LoggingContext
     */
    public static class Builder {
        private String traceId;
        private String spanId;
        private String parentSpanId;
        private Map<String, String> baggage = new ConcurrentHashMap<>();
        private Map<String, Object> attributes = new ConcurrentHashMap<>();

        public Builder traceId(String traceId) {
            this.traceId = traceId;
            return this;
        }

        public Builder spanId(String spanId) {
            this.spanId = spanId;
            return this;
        }

        public Builder parentSpanId(String parentSpanId) {
            this.parentSpanId = parentSpanId;
            return this;
        }

        public Builder newTrace() {
            this.traceId = generateTraceId();
            this.spanId = generateSpanId();
            this.parentSpanId = null;
            return this;
        }

        public Builder baggage(Map<String, String> baggage) {
            this.baggage.putAll(baggage);
            return this;
        }

        public Builder addBaggage(String key, String value) {
            this.baggage.put(key, value);
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            this.attributes.putAll(attributes);
            return this;
        }

        public Builder addAttribute(String key, Object value) {
            this.attributes.put(key, value);
            return this;
        }

        /**
         * HR Domain specific: Add user context
         */
        public Builder userId(String userId) {
            this.baggage.put("user_id", userId);
            return this;
        }

        /**
         * HR Domain specific: Add department context
         */
        public Builder department(String department) {
            this.baggage.put("department", department);
            return this;
        }

        /**
         * HR Domain specific: Add operation type
         */
        public Builder operation(String operation) {
            this.baggage.put("operation", operation);
            return this;
        }

        public LoggingContext build() {
            if (traceId == null) {
                traceId = generateTraceId();
            }
            if (spanId == null) {
                spanId = generateSpanId();
            }
            return new LoggingContext(this);
        }
    }
}
