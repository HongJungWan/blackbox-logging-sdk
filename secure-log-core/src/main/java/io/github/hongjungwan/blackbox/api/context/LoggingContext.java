package io.github.hongjungwan.blackbox.api.context;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 스레드 안전 로깅 Context. 스레드/비동기 경계 간 트레이스 전파. W3C Trace Context 지원.
 */
public final class LoggingContext {

    private static final ThreadLocal<LoggingContext> CURRENT = ThreadLocal.withInitial(LoggingContext::empty);

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

    /** 현재 ThreadLocal Context 반환 */
    public static LoggingContext current() {
        return CURRENT.get();
    }

    /** 새 trace/span ID로 빈 Context 생성 */
    public static LoggingContext empty() {
        return builder().build();
    }

    /** W3C traceparent 헤더에서 Context 생성. 형식: 00-{trace-id}-{parent-id}-{flags} */
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

    /** 새 Builder 생성 */
    public static Builder builder() {
        return new Builder();
    }

    /** 하위 Span 생성을 위한 Builder 반환 */
    public Builder toBuilder() {
        return new Builder()
                .traceId(this.traceId)
                .spanId(generateSpanId())
                .parentSpanId(this.spanId)
                .baggage(new HashMap<>(this.baggage))
                .attributes(new HashMap<>(this.attributes));
    }

    /** ThreadLocal에 설정. 반환된 Scope close 시 이전 Context 복원. */
    public Scope makeCurrent() {
        LoggingContext previous = CURRENT.get();
        CURRENT.set(this);
        return () -> CURRENT.set(previous);
    }

    /** 하위 Span용 자식 Context 생성 */
    public LoggingContext createChild() {
        return toBuilder().build();
    }

    /** Runnable 래핑. 실행 시 이 Context 활성화. */
    public Runnable wrap(Runnable runnable) {
        return () -> {
            try (Scope ignored = this.makeCurrent()) {
                runnable.run();
            }
        };
    }

    /** Callable 래핑. 실행 시 이 Context 활성화. */
    public <T> java.util.concurrent.Callable<T> wrap(java.util.concurrent.Callable<T> callable) {
        return () -> {
            try (Scope ignored = this.makeCurrent()) {
                return callable.call();
            }
        };
    }

    /** W3C traceparent 헤더 형식으로 내보내기 */
    public String toTraceParent() {
        if (traceId == null || spanId == null) {
            return null;
        }
        return String.format("00-%s-%s-01", traceId, spanId);
    }

    /** W3C baggage 헤더 형식으로 내보내기 */
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

    /** MDC 호환 Map으로 내보내기 */
    public Map<String, String> toMdc() {
        Map<String, String> mdc = new HashMap<>();
        if (traceId != null) mdc.put("traceId", traceId);
        if (spanId != null) mdc.put("spanId", spanId);
        if (parentSpanId != null) mdc.put("parentSpanId", parentSpanId);
        mdc.putAll(baggage);
        return mdc;
    }

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

    /** 랜덤 Span ID 생성 (16 hex chars) */
    private static String generateSpanId() {
        return Long.toHexString(java.util.concurrent.ThreadLocalRandom.current().nextLong());
    }

    /** 랜덤 Trace ID 생성 (32 hex chars). 타임스탬프 포함으로 충돌 확률 최소화. */
    public static String generateTraceId() {
        long timestamp = System.currentTimeMillis();
        long random1 = java.util.concurrent.ThreadLocalRandom.current().nextLong();
        long random2 = java.util.concurrent.ThreadLocalRandom.current().nextLong();
        String timestampHex = Long.toHexString(timestamp);
        String random1Hex = Long.toHexString(random1);
        String combined = timestampHex + random1Hex + Long.toHexString(random2 >>> 16);
        if (combined.length() >= 32) {
            return combined.substring(0, 32);
        }
        return String.format("%32s", combined).replace(' ', '0');
    }

    /** Context 스코프 관리 (AutoCloseable) */
    @FunctionalInterface
    public interface Scope extends AutoCloseable {
        @Override
        void close();
    }

    /** 불변 LoggingContext 빌더 */
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

        /** 새 trace/span ID 생성, parent 초기화 */
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

        /** HR 도메인: 사용자 ID 설정 */
        public Builder userId(String userId) {
            this.baggage.put("user_id", userId);
            return this;
        }

        /** HR 도메인: 부서 설정 */
        public Builder department(String department) {
            this.baggage.put("department", department);
            return this;
        }

        /** HR 도메인: 작업 유형 설정 */
        public Builder operation(String operation) {
            this.baggage.put("operation", operation);
            return this;
        }

        /** 불변 LoggingContext 생성 */
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
