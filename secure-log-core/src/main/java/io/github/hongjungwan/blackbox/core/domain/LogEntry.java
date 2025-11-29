package io.github.hongjungwan.blackbox.core.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.Map;

/**
 * Canonical log entry structure for SecureHR Logging SDK.
 * Transmitted as Zstd-compressed binary format.
 */
@Getter
@Builder
@JsonDeserialize(builder = LogEntry.LogEntryBuilder.class)
public class LogEntry {
    /**
     * Timestamp in milliseconds since epoch
     */
    private final long timestamp;

    /**
     * Log level (TRACE, DEBUG, INFO, WARN, ERROR)
     */
    private final String level;

    /**
     * Distributed tracing trace ID
     */
    private final String traceId;

    /**
     * Distributed tracing span ID
     */
    private final String spanId;

    /**
     * Contextual metadata (user_id, region, etc.)
     */
    private final Map<String, Object> context;

    /**
     * Log message
     */
    private final String message;

    /**
     * Structured payload (may contain masked/encrypted fields)
     */
    private final Map<String, Object> payload;

    /**
     * Integrity hash (Merkle Tree chain)
     */
    private final String integrity;

    /**
     * Encrypted Data Encryption Key (DEK) - envelope encryption
     */
    private final String encryptedDek;

    /**
     * Repeat count for deduplicated logs
     */
    private final Integer repeatCount;

    /**
     * Exception stack trace (if applicable)
     */
    private final String throwable;

    public static LogEntry fromEvent(ch.qos.logback.classic.spi.ILoggingEvent event) {
        return LogEntry.builder()
                .timestamp(event.getTimeStamp())
                .level(event.getLevel().toString())
                .traceId(extractTraceId(event))
                .spanId(extractSpanId(event))
                .context(extractContext(event))
                .message(event.getFormattedMessage())
                .payload(extractPayload(event))
                .throwable(extractThrowable(event))
                .build();
    }

    private static String extractTraceId(ch.qos.logback.classic.spi.ILoggingEvent event) {
        // Extract from MDC or similar context
        return event.getMDCPropertyMap().get("trace_id");
    }

    private static String extractSpanId(ch.qos.logback.classic.spi.ILoggingEvent event) {
        return event.getMDCPropertyMap().get("span_id");
    }

    private static Map<String, Object> extractContext(ch.qos.logback.classic.spi.ILoggingEvent event) {
        return Map.copyOf(event.getMDCPropertyMap());
    }

    private static Map<String, Object> extractPayload(ch.qos.logback.classic.spi.ILoggingEvent event) {
        // Extract structured arguments if using structured logging
        Object[] args = event.getArgumentArray();
        if (args != null && args.length > 0 && args[args.length - 1] instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = (Map<String, Object>) args[args.length - 1];
            return payload;
        }
        return Map.of();
    }

    private static String extractThrowable(ch.qos.logback.classic.spi.ILoggingEvent event) {
        if (event.getThrowableProxy() != null) {
            return event.getThrowableProxy().getClassName() + ": " + event.getThrowableProxy().getMessage();
        }
        return null;
    }

    @JsonPOJOBuilder(withPrefix = "")
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LogEntryBuilder {
        // Lombok generates the builder methods
    }
}
