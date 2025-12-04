package io.github.hongjungwan.blackbox.api.context;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe logging context for trace propagation.
 *
 * <p>Automatically propagates context across:</p>
 * <ul>
 *   <li>Thread boundaries (including Virtual Threads)</li>
 *   <li>Async operations</li>
 *   <li>External service calls (via W3C Trace Context headers)</li>
 * </ul>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * // Create and activate context
 * try (var scope = LoggingContext.builder()
 *         .newTrace()
 *         .userId("admin")
 *         .department("HR")
 *         .build()
 *         .makeCurrent()) {
 *
 *     // All logs within this scope will have trace context
 *     logger.info("Processing request");
 *
 *     // Propagate to async tasks
 *     executor.submit(LoggingContext.current().wrap(() -> {
 *         logger.info("Async task");
 *     }));
 * }
 *
 * // Propagate to HTTP calls
 * String traceParent = LoggingContext.current().toTraceParent();
 * httpClient.setHeader("traceparent", traceParent);
 * }</pre>
 *
 * <p>Based on OpenTelemetry Context and W3C Trace Context specifications.</p>
 *
 * @since 8.0.0
 * @see <a href="https://www.w3.org/TR/trace-context/">W3C Trace Context</a>
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
     * Get current context from ThreadLocal.
     *
     * @return the current LoggingContext, or an empty context if none is set
     */
    public static LoggingContext current() {
        return CURRENT.get();
    }

    /**
     * Create an empty context with auto-generated trace and span IDs.
     *
     * @return a new empty LoggingContext
     */
    public static LoggingContext empty() {
        return builder().build();
    }

    /**
     * Create context from W3C Trace Context header.
     * Format: 00-{trace-id}-{parent-id}-{flags}
     *
     * @param traceParent the W3C traceparent header value
     * @return a new LoggingContext parsed from the header, or empty if invalid
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
     * Create a new builder for constructing a LoggingContext.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Create a builder from this context for creating child spans.
     *
     * @return a new Builder pre-populated with this context's data
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
     * Make this context current (attach to ThreadLocal).
     * Returns a Scope that should be closed when done.
     *
     * @return a Scope that restores the previous context when closed
     */
    public Scope makeCurrent() {
        LoggingContext previous = CURRENT.get();
        CURRENT.set(this);
        return () -> CURRENT.set(previous);
    }

    /**
     * Create a child context for a new span.
     *
     * @return a new child LoggingContext with this context as parent
     */
    public LoggingContext createChild() {
        return toBuilder().build();
    }

    /**
     * Create a Runnable wrapper that propagates this context.
     *
     * @param runnable the runnable to wrap
     * @return a wrapped Runnable that activates this context during execution
     */
    public Runnable wrap(Runnable runnable) {
        return () -> {
            try (Scope ignored = this.makeCurrent()) {
                runnable.run();
            }
        };
    }

    /**
     * Create a Callable wrapper that propagates this context.
     *
     * @param <T> the return type of the callable
     * @param callable the callable to wrap
     * @return a wrapped Callable that activates this context during execution
     */
    public <T> java.util.concurrent.Callable<T> wrap(java.util.concurrent.Callable<T> callable) {
        return () -> {
            try (Scope ignored = this.makeCurrent()) {
                return callable.call();
            }
        };
    }

    /**
     * Export context as W3C Trace Context header.
     *
     * @return the traceparent header value, or null if trace/span IDs are missing
     */
    public String toTraceParent() {
        if (traceId == null || spanId == null) {
            return null;
        }
        return String.format("00-%s-%s-01", traceId, spanId);
    }

    /**
     * Export baggage as W3C Baggage header.
     *
     * @return the baggage header value, or null if baggage is empty
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
     * Export context to MDC-compatible map.
     *
     * @return a map containing traceId, spanId, parentSpanId, and baggage entries
     */
    public Map<String, String> toMdc() {
        Map<String, String> mdc = new HashMap<>();
        if (traceId != null) mdc.put("traceId", traceId);
        if (spanId != null) mdc.put("spanId", spanId);
        if (parentSpanId != null) mdc.put("parentSpanId", parentSpanId);
        mdc.putAll(baggage);
        return mdc;
    }

    /**
     * Returns the trace ID.
     *
     * @return the trace ID
     */
    public String getTraceId() { return traceId; }

    /**
     * Returns the span ID.
     *
     * @return the span ID
     */
    public String getSpanId() { return spanId; }

    /**
     * Returns the parent span ID.
     *
     * @return the parent span ID
     */
    public String getParentSpanId() { return parentSpanId; }

    /**
     * Returns the baggage map.
     *
     * @return the immutable baggage map
     */
    public Map<String, String> getBaggage() { return baggage; }

    /**
     * Returns the attributes map.
     *
     * @return the immutable attributes map
     */
    public Map<String, Object> getAttributes() { return attributes; }

    /**
     * Returns the baggage value for the specified key.
     *
     * @param key the baggage key
     * @return an Optional containing the value, or empty if not found
     */
    public Optional<String> getBaggageItem(String key) {
        return Optional.ofNullable(baggage.get(key));
    }

    /**
     * Returns the attribute value for the specified key.
     *
     * @param <T> the expected type of the attribute value
     * @param key the attribute key
     * @return an Optional containing the value, or empty if not found
     */
    @SuppressWarnings("unchecked")
    public <T> Optional<T> getAttribute(String key) {
        return Optional.ofNullable((T) attributes.get(key));
    }

    /**
     * Generate random span ID (16 hex chars).
     */
    private static String generateSpanId() {
        return Long.toHexString(java.util.concurrent.ThreadLocalRandom.current().nextLong());
    }

    /**
     * Generate random trace ID (32 hex chars).
     *
     * FIX P2 #12: Include timestamp component to reduce collision probability.
     * Format: timestamp_hex (variable) + random1_hex + random2_partial_hex
     *
     * @return a 32-character hexadecimal trace ID
     */
    public static String generateTraceId() {
        long timestamp = System.currentTimeMillis();
        long random1 = java.util.concurrent.ThreadLocalRandom.current().nextLong();
        long random2 = java.util.concurrent.ThreadLocalRandom.current().nextLong();
        // Combine timestamp and randoms, ensuring we get a consistent length
        String timestampHex = Long.toHexString(timestamp);
        String random1Hex = Long.toHexString(random1);
        String combined = timestampHex + random1Hex + Long.toHexString(random2 >>> 16);
        // Ensure we return exactly 32 hex chars (pad or truncate as needed)
        if (combined.length() >= 32) {
            return combined.substring(0, 32);
        }
        // Pad with leading zeros if needed (unlikely but safe)
        return String.format("%32s", combined).replace(' ', '0');
    }

    /**
     * Scope for context management (AutoCloseable).
     */
    @FunctionalInterface
    public interface Scope extends AutoCloseable {
        @Override
        void close(); // No exception
    }

    /**
     * Builder for immutable LoggingContext.
     */
    public static class Builder {
        private String traceId;
        private String spanId;
        private String parentSpanId;
        private Map<String, String> baggage = new ConcurrentHashMap<>();
        private Map<String, Object> attributes = new ConcurrentHashMap<>();

        /**
         * Sets the trace ID.
         *
         * @param traceId the trace ID to set
         * @return this builder for method chaining
         */
        public Builder traceId(String traceId) {
            this.traceId = traceId;
            return this;
        }

        /**
         * Sets the span ID.
         *
         * @param spanId the span ID to set
         * @return this builder for method chaining
         */
        public Builder spanId(String spanId) {
            this.spanId = spanId;
            return this;
        }

        /**
         * Sets the parent span ID.
         *
         * @param parentSpanId the parent span ID to set
         * @return this builder for method chaining
         */
        public Builder parentSpanId(String parentSpanId) {
            this.parentSpanId = parentSpanId;
            return this;
        }

        /**
         * Generates new trace and span IDs, clearing the parent span ID.
         *
         * @return this builder for method chaining
         */
        public Builder newTrace() {
            this.traceId = generateTraceId();
            this.spanId = generateSpanId();
            this.parentSpanId = null;
            return this;
        }

        /**
         * Sets the baggage map, merging with existing entries.
         *
         * @param baggage the baggage key-value pairs to add
         * @return this builder for method chaining
         */
        public Builder baggage(Map<String, String> baggage) {
            this.baggage.putAll(baggage);
            return this;
        }

        /**
         * Adds a single baggage entry.
         *
         * @param key the baggage key
         * @param value the baggage value
         * @return this builder for method chaining
         */
        public Builder addBaggage(String key, String value) {
            this.baggage.put(key, value);
            return this;
        }

        /**
         * Sets the attributes map, merging with existing entries.
         *
         * @param attributes the attribute key-value pairs to add
         * @return this builder for method chaining
         */
        public Builder attributes(Map<String, Object> attributes) {
            this.attributes.putAll(attributes);
            return this;
        }

        /**
         * Adds a single attribute entry.
         *
         * @param key the attribute key
         * @param value the attribute value
         * @return this builder for method chaining
         */
        public Builder addAttribute(String key, Object value) {
            this.attributes.put(key, value);
            return this;
        }

        /**
         * HR Domain specific: Add user context.
         *
         * @param userId the user ID to add to baggage
         * @return this builder for method chaining
         */
        public Builder userId(String userId) {
            this.baggage.put("user_id", userId);
            return this;
        }

        /**
         * HR Domain specific: Add department context.
         *
         * @param department the department name to add to baggage
         * @return this builder for method chaining
         */
        public Builder department(String department) {
            this.baggage.put("department", department);
            return this;
        }

        /**
         * HR Domain specific: Add operation type.
         *
         * @param operation the operation type to add to baggage
         * @return this builder for method chaining
         */
        public Builder operation(String operation) {
            this.baggage.put("operation", operation);
            return this;
        }

        /**
         * Builds an immutable LoggingContext instance.
         *
         * @return the constructed LoggingContext
         */
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
