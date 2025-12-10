package io.github.hongjungwan.blackbox.api.domain;

import io.github.hongjungwan.blackbox.api.annotation.AuditAction;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 감사 문맥 정보 (불변 객체).
 *
 * AOP에서 수집된 "누가(Who)", "누구의(Whom)", "왜(Why)" 정보를 담는 도메인 객체.
 * LoggingContext와 연동되어 로그에 자동 포함.
 *
 * HR 도메인 감사 예시:
 * AuditInfo.builder()
 *     .who("인사팀 관리자 kim@company.com")
 *     .whom("직원 emp123")
 *     .why("급여 정보 조회")
 *     .action(AuditAction.READ)
 *     .resourceType("Salary")
 *     .build();
 */
public final class AuditInfo {

    private final String who;           // 수행자 (예: "인사팀 관리자 kim@company.com")
    private final String whom;          // 대상자 (예: "직원 emp123")
    private final String why;           // 사유 (예: "급여 정보 조회")
    private final AuditAction action;   // 작업 유형 (예: READ)
    private final String resourceType;  // 리소스 유형 (예: "Salary")
    private final String traceId;       // 추적 ID
    private final Instant timestamp;    // 발생 시각
    private final Map<String, Object> additionalData;  // 추가 데이터

    private AuditInfo(Builder builder) {
        this.who = builder.who;
        this.whom = builder.whom;
        this.why = builder.why;
        this.action = builder.action;
        this.resourceType = builder.resourceType;
        this.traceId = builder.traceId;
        this.timestamp = builder.timestamp;
        this.additionalData = builder.additionalData.isEmpty()
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(builder.additionalData));
    }

    public String getWho() {
        return who;
    }

    public String getWhom() {
        return whom;
    }

    public String getWhy() {
        return why;
    }

    public AuditAction getAction() {
        return action;
    }

    public String getResourceType() {
        return resourceType;
    }

    public String getTraceId() {
        return traceId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public Map<String, Object> getAdditionalData() {
        return additionalData;
    }

    /**
     * LoggingContext 속성에 주입하기 위한 Map 변환.
     */
    public Map<String, Object> toAttributeMap() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("audit.who", who);
        attributes.put("audit.whom", whom);
        attributes.put("audit.why", why);
        attributes.put("audit.action", action != null ? action.name() : null);
        attributes.put("audit.resourceType", resourceType);
        attributes.put("audit.timestamp", timestamp != null ? timestamp.toString() : null);

        if (!additionalData.isEmpty()) {
            additionalData.forEach((key, value) ->
                    attributes.put("audit." + key, value));
        }

        return attributes;
    }

    /**
     * 로그 페이로드에 포함할 간결한 Map 반환.
     */
    public Map<String, Object> toLogPayload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("who", who);
        payload.put("whom", whom);
        payload.put("why", why);
        payload.put("action", action != null ? action.name() : null);

        if (resourceType != null && !resourceType.isEmpty()) {
            payload.put("resourceType", resourceType);
        }

        return payload;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditInfo auditInfo = (AuditInfo) o;
        return Objects.equals(who, auditInfo.who)
                && Objects.equals(whom, auditInfo.whom)
                && Objects.equals(why, auditInfo.why)
                && action == auditInfo.action
                && Objects.equals(traceId, auditInfo.traceId)
                && Objects.equals(timestamp, auditInfo.timestamp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(who, whom, why, action, traceId, timestamp);
    }

    @Override
    public String toString() {
        return "AuditInfo{" +
                "who='" + who + '\'' +
                ", whom='" + whom + '\'' +
                ", why='" + why + '\'' +
                ", action=" + action +
                ", resourceType='" + resourceType + '\'' +
                ", traceId='" + traceId + '\'' +
                '}';
    }

    /**
     * AuditInfo 빌더.
     */
    public static final class Builder {
        private String who;
        private String whom;
        private String why;
        private AuditAction action = AuditAction.READ;
        private String resourceType;
        private String traceId;
        private Instant timestamp = Instant.now();
        private final Map<String, Object> additionalData = new LinkedHashMap<>();

        private Builder() {}

        public Builder who(String who) {
            this.who = who;
            return this;
        }

        public Builder whom(String whom) {
            this.whom = whom;
            return this;
        }

        public Builder why(String why) {
            this.why = why;
            return this;
        }

        public Builder action(AuditAction action) {
            this.action = action;
            return this;
        }

        public Builder resourceType(String resourceType) {
            this.resourceType = resourceType;
            return this;
        }

        public Builder traceId(String traceId) {
            this.traceId = traceId;
            return this;
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder addData(String key, Object value) {
            this.additionalData.put(key, value);
            return this;
        }

        public AuditInfo build() {
            return new AuditInfo(this);
        }
    }
}
