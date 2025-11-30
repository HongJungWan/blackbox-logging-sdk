package io.github.hongjungwan.blackbox.api.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

/**
 * Canonical log entry structure for SecureHR Logging SDK.
 *
 * <p>Represents a single log entry with all security metadata.
 * Transmitted as Zstd-compressed binary format for efficiency.</p>
 *
 * <h2>Structure:</h2>
 * <pre>{@code
 * {
 *   "ts": 1716345000123,
 *   "lvl": "INFO",
 *   "trace_id": "0af7651916cd43dd8448eb211c80319c",
 *   "span_id": "b7ad6b7169203331",
 *   "ctx": { "user_id": "emp_1001", "region": "KR" },
 *   "msg": "Salary processed",
 *   "payload": {
 *     "amount": "******",
 *     "bank": "ENC(A1b...)"
 *   },
 *   "integ": "sha256:a8f..."
 * }
 * }</pre>
 *
 * @since 8.0.0
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
     * Distributed tracing trace ID (W3C format: 32 hex chars)
     */
    private final String traceId;

    /**
     * Distributed tracing span ID (W3C format: 16 hex chars)
     */
    private final String spanId;

    /**
     * Contextual metadata (user_id, region, department, etc.)
     */
    private final Map<String, Object> context;

    /**
     * Log message (human-readable)
     */
    private final String message;

    /**
     * Structured payload (may contain masked/encrypted fields)
     */
    private final Map<String, Object> payload;

    /**
     * Integrity hash (Merkle Tree chain: "sha256:...")
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
     * Exception information (if applicable)
     */
    private final String throwable;

    /**
     * Create LogEntry from Logback ILoggingEvent.
     */
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
        return event.getMDCPropertyMap().get("trace_id");
    }

    private static String extractSpanId(ch.qos.logback.classic.spi.ILoggingEvent event) {
        return event.getMDCPropertyMap().get("span_id");
    }

    private static Map<String, Object> extractContext(ch.qos.logback.classic.spi.ILoggingEvent event) {
        return Map.copyOf(event.getMDCPropertyMap());
    }

    private static Map<String, Object> extractPayload(ch.qos.logback.classic.spi.ILoggingEvent event) {
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
