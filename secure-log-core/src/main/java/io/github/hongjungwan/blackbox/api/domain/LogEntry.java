package io.github.hongjungwan.blackbox.api.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;

import java.util.HashMap;
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

    private static final String PAYLOAD_MDC_KEY = "secure.payload";

    private static Map<String, Object> extractPayload(ch.qos.logback.classic.spi.ILoggingEvent event) {
        // First, check MDC for "secure.payload" key (set by DefaultSecureLogger)
        String mdcPayload = event.getMDCPropertyMap().get(PAYLOAD_MDC_KEY);
        if (mdcPayload != null && !mdcPayload.isEmpty()) {
            Map<String, Object> parsed = parsePayloadFromMdc(mdcPayload);
            if (parsed != null && !parsed.isEmpty()) {
                return parsed;
            }
        }

        // Fall back to checking argumentArray
        Object[] args = event.getArgumentArray();
        if (args != null && args.length > 0 && args[args.length - 1] instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = (Map<String, Object>) args[args.length - 1];
            return payload;
        }
        return Map.of();
    }

    /**
     * Parse payload from MDC string representation.
     * Handles the simple JSON-like format produced by DefaultSecureLogger.convertPayloadToString().
     * Format: {"key1": "value1", "key2": value2}
     */
    private static Map<String, Object> parsePayloadFromMdc(String mdcPayload) {
        if (mdcPayload == null || mdcPayload.length() < 2) {
            return null;
        }

        // Remove outer braces
        String content = mdcPayload.trim();
        if (!content.startsWith("{") || !content.endsWith("}")) {
            return null;
        }
        content = content.substring(1, content.length() - 1).trim();

        if (content.isEmpty()) {
            return Map.of();
        }

        Map<String, Object> result = new HashMap<>();

        // Simple parser for key-value pairs
        // This handles the format: "key1": "value1", "key2": value2
        int i = 0;
        while (i < content.length()) {
            // Skip whitespace
            while (i < content.length() && Character.isWhitespace(content.charAt(i))) {
                i++;
            }

            if (i >= content.length()) break;

            // Expect opening quote for key
            if (content.charAt(i) != '"') break;
            i++;

            // Read key
            int keyStart = i;
            while (i < content.length() && content.charAt(i) != '"') {
                i++;
            }
            if (i >= content.length()) break;
            String key = content.substring(keyStart, i);
            i++; // skip closing quote

            // Skip ": "
            while (i < content.length() && (content.charAt(i) == ':' || Character.isWhitespace(content.charAt(i)))) {
                i++;
            }

            if (i >= content.length()) break;

            // Read value
            Object value;
            if (content.charAt(i) == '"') {
                // String value
                i++; // skip opening quote
                int valueStart = i;
                while (i < content.length() && content.charAt(i) != '"') {
                    i++;
                }
                value = content.substring(valueStart, i);
                if (i < content.length()) i++; // skip closing quote
            } else {
                // Non-string value (number, boolean, null)
                int valueStart = i;
                while (i < content.length() && content.charAt(i) != ',' && content.charAt(i) != '}') {
                    i++;
                }
                String valueStr = content.substring(valueStart, i).trim();
                value = parseValue(valueStr);
            }

            result.put(key, value);

            // Skip comma and whitespace
            while (i < content.length() && (content.charAt(i) == ',' || Character.isWhitespace(content.charAt(i)))) {
                i++;
            }
        }

        return result;
    }

    /**
     * Parse a non-string value from string representation.
     */
    private static Object parseValue(String valueStr) {
        if (valueStr == null || valueStr.isEmpty() || "null".equals(valueStr)) {
            return null;
        }
        if ("true".equalsIgnoreCase(valueStr)) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(valueStr)) {
            return Boolean.FALSE;
        }
        // Try to parse as number
        try {
            if (valueStr.contains(".")) {
                return Double.parseDouble(valueStr);
            } else {
                return Long.parseLong(valueStr);
            }
        } catch (NumberFormatException e) {
            // Return as string if parsing fails
            return valueStr;
        }
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
