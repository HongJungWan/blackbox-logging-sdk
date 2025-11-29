package io.github.hongjungwan.blackbox.test;

import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import org.assertj.core.api.AbstractAssert;

import java.util.Map;

/**
 * FEAT-07: LogAssert TestKit
 *
 * AssertJ-style fluent API for testing logs
 *
 * Usage:
 * <pre>
 * assertThatLog(entry)
 *     .hasField("rrn")
 *     .isMasked();
 * </pre>
 */
public class LogAssert extends AbstractAssert<LogAssert, LogEntry> {

    private String currentField;

    public LogAssert(LogEntry actual) {
        super(actual, LogAssert.class);
    }

    public static LogAssert assertThatLog(LogEntry actual) {
        return new LogAssert(actual);
    }

    /**
     * Assert log has specific field in payload
     */
    public LogAssert hasField(String fieldName) {
        isNotNull();

        if (actual.getPayload() == null || !actual.getPayload().containsKey(fieldName)) {
            failWithMessage("Expected log to have field <%s> but it was not present", fieldName);
        }

        this.currentField = fieldName;
        return this;
    }

    /**
     * Assert current field is masked (contains asterisks)
     */
    public LogAssert isMasked() {
        isNotNull();

        if (currentField == null) {
            failWithMessage("No field selected. Call hasField() first");
        }

        Object value = actual.getPayload().get(currentField);

        if (value == null) {
            failWithMessage("Field <%s> is null, cannot check masking", currentField);
        }

        String strValue = value.toString();
        if (!strValue.contains("*")) {
            failWithMessage("Expected field <%s> to be masked but was <%s>", currentField, strValue);
        }

        return this;
    }

    /**
     * Assert current field is NOT masked
     */
    public LogAssert isNotMasked() {
        isNotNull();

        if (currentField == null) {
            failWithMessage("No field selected. Call hasField() first");
        }

        Object value = actual.getPayload().get(currentField);

        if (value != null && value.toString().contains("*")) {
            failWithMessage("Expected field <%s> NOT to be masked but was <%s>", currentField, value);
        }

        return this;
    }

    /**
     * Assert current field is encrypted
     */
    public LogAssert isEncrypted() {
        isNotNull();

        if (currentField == null) {
            failWithMessage("No field selected. Call hasField() first");
        }

        Object value = actual.getPayload().get(currentField);

        if (value == null) {
            failWithMessage("Field <%s> is null, cannot check encryption", currentField);
        }

        String strValue = value.toString();
        if (!strValue.startsWith("ENC(")) {
            failWithMessage("Expected field <%s> to be encrypted but was <%s>", currentField, strValue);
        }

        return this;
    }

    /**
     * Assert log has integrity hash
     */
    public LogAssert hasIntegrity() {
        isNotNull();

        if (actual.getIntegrity() == null || actual.getIntegrity().isEmpty()) {
            failWithMessage("Expected log to have integrity hash but it was missing");
        }

        if (!actual.getIntegrity().startsWith("sha256:")) {
            failWithMessage("Expected integrity hash to start with 'sha256:' but was <%s>", actual.getIntegrity());
        }

        return this;
    }

    /**
     * Assert log has encrypted DEK
     */
    public LogAssert hasEncryptedDek() {
        isNotNull();

        if (actual.getEncryptedDek() == null || actual.getEncryptedDek().isEmpty()) {
            failWithMessage("Expected log to have encrypted DEK but it was missing");
        }

        return this;
    }

    /**
     * Assert log level
     */
    public LogAssert hasLevel(String level) {
        isNotNull();

        if (!level.equals(actual.getLevel())) {
            failWithMessage("Expected log level to be <%s> but was <%s>", level, actual.getLevel());
        }

        return this;
    }

    /**
     * Assert message contains text
     */
    public LogAssert messageContains(String text) {
        isNotNull();

        if (actual.getMessage() == null || !actual.getMessage().contains(text)) {
            failWithMessage("Expected message to contain <%s> but was <%s>", text, actual.getMessage());
        }

        return this;
    }

    /**
     * Assert has trace ID
     */
    public LogAssert hasTraceId() {
        isNotNull();

        if (actual.getTraceId() == null || actual.getTraceId().isEmpty()) {
            failWithMessage("Expected log to have trace ID but it was missing");
        }

        return this;
    }

    /**
     * Assert has span ID
     */
    public LogAssert hasSpanId() {
        isNotNull();

        if (actual.getSpanId() == null || actual.getSpanId().isEmpty()) {
            failWithMessage("Expected log to have span ID but it was missing");
        }

        return this;
    }

    /**
     * Assert context contains key
     */
    public LogAssert hasContextKey(String key) {
        isNotNull();

        if (actual.getContext() == null || !actual.getContext().containsKey(key)) {
            failWithMessage("Expected context to contain key <%s> but it was not present", key);
        }

        return this;
    }

    /**
     * Assert context value equals
     */
    public LogAssert hasContextValue(String key, Object value) {
        hasContextKey(key);

        Object actualValue = actual.getContext().get(key);
        if (!value.equals(actualValue)) {
            failWithMessage("Expected context[%s] to be <%s> but was <%s>", key, value, actualValue);
        }

        return this;
    }

    /**
     * Assert payload equals map
     */
    public LogAssert hasPayload(Map<String, Object> expected) {
        isNotNull();

        if (!expected.equals(actual.getPayload())) {
            failWithMessage("Expected payload to be <%s> but was <%s>", expected, actual.getPayload());
        }

        return this;
    }

    /**
     * Assert repeat count
     */
    public LogAssert hasRepeatCount(int count) {
        isNotNull();

        if (actual.getRepeatCount() == null) {
            failWithMessage("Expected repeat count to be <%d> but was null", count);
        }

        if (actual.getRepeatCount() != count) {
            failWithMessage("Expected repeat count to be <%d> but was <%d>", count, actual.getRepeatCount());
        }

        return this;
    }
}
