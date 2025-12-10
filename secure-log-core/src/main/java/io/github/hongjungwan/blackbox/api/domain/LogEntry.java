package io.github.hongjungwan.blackbox.api.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * 로그 엔트리. 마스킹, 암호화, 직렬화 파이프라인의 기본 단위. Zstd 압축 전송.
 */
@Slf4j
@Getter
@Builder
@JsonDeserialize(builder = LogEntry.LogEntryBuilder.class)
public class LogEntry {

    private static final ObjectMapper MDC_PAYLOAD_MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<>() {};

    /** 타임스탬프 (epoch millis) */
    private final long timestamp;

    /** 로그 레벨 */
    private final String level;

    /** 분산 추적 Trace ID (W3C 32 hex chars) */
    private final String traceId;

    /** 분산 추적 Span ID (W3C 16 hex chars) */
    private final String spanId;

    /** 컨텍스트 메타데이터 (user_id, region 등) */
    private final Map<String, Object> context;

    /** 로그 메시지 */
    private final String message;

    /** 구조화된 페이로드 (마스킹/암호화 필드 포함 가능) */
    private final Map<String, Object> payload;

    /** 무결성 해시 (Merkle Tree: "sha256:...") */
    private final String integrity;

    /** 암호화된 DEK (Envelope Encryption) */
    private final String encryptedDek;

    /** 중복 제거된 로그의 반복 횟수 */
    private final Integer repeatCount;

    /** 예외 정보 */
    private final String throwable;

    /** Logback ILoggingEvent에서 LogEntry 생성 */
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
        String mdcPayload = event.getMDCPropertyMap().get(PAYLOAD_MDC_KEY);
        if (mdcPayload != null && !mdcPayload.isEmpty()) {
            Map<String, Object> parsed = parsePayloadFromMdc(mdcPayload);
            if (parsed != null && !parsed.isEmpty()) {
                return parsed;
            }
        }

        Object[] args = event.getArgumentArray();
        if (args != null && args.length > 0 && args[args.length - 1] instanceof Map) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> payload = (Map<String, Object>) args[args.length - 1];
                return payload;
            } catch (ClassCastException e) {
                log.debug("Failed to cast argument to Map<String, Object>: {}", e.getMessage());
                return Map.of();
            }
        }
        return Map.of();
    }

    /** MDC payload JSON 파싱 (중첩 객체/배열 지원) */
    private static Map<String, Object> parsePayloadFromMdc(String mdcPayload) {
        if (mdcPayload == null || mdcPayload.isEmpty()) {
            return null;
        }
        try {
            return MDC_PAYLOAD_MAPPER.readValue(mdcPayload, MAP_TYPE_REF);
        } catch (Exception e) {
            log.debug("Failed to parse MDC payload as JSON, falling back to argumentArray: {}", e.getMessage());
            return null;
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
    }
}
