package io.github.hongjungwan.blackbox.core.context;

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/**
 * FEAT-09: Context Propagator (OpenTelemetry Pattern)
 *
 * Handles context injection/extraction for cross-service propagation.
 * Supports multiple propagation formats via SPI.
 *
 * Based on: OpenTelemetry TextMapPropagator
 *
 * @see <a href="https://github.com/open-telemetry/opentelemetry-java">OpenTelemetry Java</a>
 */
public final class ContextPropagator {

    private static final ContextPropagator INSTANCE = new ContextPropagator();

    private final List<TextMapPropagator> propagators = new CopyOnWriteArrayList<>();

    private ContextPropagator() {
        // Register default propagators
        propagators.add(new W3CTraceContextPropagator());
        propagators.add(new W3CBaggagePropagator());

        // Load additional propagators via SPI
        ServiceLoader.load(TextMapPropagator.class)
                .forEach(propagators::add);
    }

    public static ContextPropagator getInstance() {
        return INSTANCE;
    }

    /**
     * Inject context into carrier (e.g., HTTP headers)
     */
    public <C> void inject(LoggingContext context, C carrier, Setter<C> setter) {
        for (TextMapPropagator propagator : propagators) {
            propagator.inject(context, carrier, setter);
        }
    }

    /**
     * Extract context from carrier (e.g., HTTP headers)
     */
    public <C> LoggingContext extract(C carrier, Getter<C> getter) {
        LoggingContext.Builder builder = LoggingContext.builder();

        for (TextMapPropagator propagator : propagators) {
            propagator.extract(builder, carrier, getter);
        }

        return builder.build();
    }

    /**
     * Register additional propagator
     */
    public void register(TextMapPropagator propagator) {
        propagators.add(propagator);
    }

    /**
     * Functional interface for setting values in carrier
     */
    @FunctionalInterface
    public interface Setter<C> {
        void set(C carrier, String key, String value);
    }

    /**
     * Functional interface for getting values from carrier
     */
    @FunctionalInterface
    public interface Getter<C> {
        String get(C carrier, String key);
    }

    /**
     * Interface for text-based context propagation
     */
    public interface TextMapPropagator {
        <C> void inject(LoggingContext context, C carrier, Setter<C> setter);
        <C> void extract(LoggingContext.Builder builder, C carrier, Getter<C> getter);
        List<String> fields();
    }

    /**
     * W3C Trace Context Propagator
     * Format: traceparent: 00-{trace-id}-{parent-id}-{flags}
     */
    static class W3CTraceContextPropagator implements TextMapPropagator {

        private static final String TRACEPARENT = "traceparent";
        private static final String TRACESTATE = "tracestate";

        @Override
        public <C> void inject(LoggingContext context, C carrier, Setter<C> setter) {
            String traceParent = context.toTraceParent();
            if (traceParent != null) {
                setter.set(carrier, TRACEPARENT, traceParent);
            }
        }

        @Override
        public <C> void extract(LoggingContext.Builder builder, C carrier, Getter<C> getter) {
            String traceParent = getter.get(carrier, TRACEPARENT);
            if (traceParent != null && !traceParent.isEmpty()) {
                String[] parts = traceParent.split("-");
                if (parts.length >= 3) {
                    builder.traceId(parts[1]);
                    builder.parentSpanId(parts[2]);
                }
            }
        }

        @Override
        public List<String> fields() {
            return List.of(TRACEPARENT, TRACESTATE);
        }
    }

    /**
     * W3C Baggage Propagator
     * Format: baggage: key1=value1,key2=value2
     */
    static class W3CBaggagePropagator implements TextMapPropagator {

        private static final String BAGGAGE = "baggage";

        @Override
        public <C> void inject(LoggingContext context, C carrier, Setter<C> setter) {
            String baggageHeader = context.toBaggageHeader();
            if (baggageHeader != null) {
                setter.set(carrier, BAGGAGE, baggageHeader);
            }
        }

        @Override
        public <C> void extract(LoggingContext.Builder builder, C carrier, Getter<C> getter) {
            String baggageHeader = getter.get(carrier, BAGGAGE);
            if (baggageHeader != null && !baggageHeader.isEmpty()) {
                Map<String, String> baggage = parseBaggage(baggageHeader);
                builder.baggage(baggage);
            }
        }

        private Map<String, String> parseBaggage(String header) {
            Map<String, String> result = new HashMap<>();
            for (String pair : header.split(",")) {
                String[] kv = pair.trim().split("=", 2);
                if (kv.length == 2) {
                    result.put(kv[0].trim(), kv[1].trim());
                }
            }
            return result;
        }

        @Override
        public List<String> fields() {
            return List.of(BAGGAGE);
        }
    }

    /**
     * Convenience methods for common carriers
     */
    public static class Carriers {

        /**
         * Map-based carrier (for testing or simple use cases)
         */
        public static Setter<Map<String, String>> mapSetter() {
            return Map::put;
        }

        public static Getter<Map<String, String>> mapGetter() {
            return Map::get;
        }
    }
}
