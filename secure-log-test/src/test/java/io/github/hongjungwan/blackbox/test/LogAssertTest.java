package io.github.hongjungwan.blackbox.test;

import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.github.hongjungwan.blackbox.test.LogAssert.assertThatLog;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test LogAssert utility
 */
class LogAssertTest {

    @Test
    void testMaskedField() {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Test message")
                .payload(Map.of("rrn", "123456-*******"))
                .build();

        assertThatLog(entry)
                .hasField("rrn")
                .isMasked();
    }

    @Test
    void testNotMaskedField() {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Test message")
                .payload(Map.of("name", "John Doe"))
                .build();

        assertThatLog(entry)
                .hasField("name")
                .isNotMasked();
    }

    @Test
    void testEncryptedField() {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Test message")
                .payload(Map.of("sensitive", "ENC(a8f7b2c1...)"))
                .build();

        assertThatLog(entry)
                .hasField("sensitive")
                .isEncrypted();
    }

    @Test
    void testIntegrity() {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Test message")
                .integrity("sha256:abc123...")
                .build();

        assertThatLog(entry)
                .hasIntegrity();
    }

    @Test
    void testTracing() {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Test message")
                .traceId("0af7651916cd43dd")
                .spanId("b7ad6b7169203331")
                .build();

        assertThatLog(entry)
                .hasTraceId()
                .hasSpanId();
    }

    @Test
    void testContext() {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Test message")
                .context(Map.of("user_id", "emp_1001", "region", "KR"))
                .build();

        assertThatLog(entry)
                .hasContextKey("user_id")
                .hasContextValue("user_id", "emp_1001")
                .hasContextKey("region")
                .hasContextValue("region", "KR");
    }

    @Test
    void testMissingFieldThrows() {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Test message")
                .payload(Map.of())
                .build();

        assertThatThrownBy(() ->
                assertThatLog(entry).hasField("missing")
        ).hasMessageContaining("Expected log to have field");
    }
}
