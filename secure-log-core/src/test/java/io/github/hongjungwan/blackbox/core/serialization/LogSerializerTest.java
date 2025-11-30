package io.github.hongjungwan.blackbox.core.serialization;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("LogSerializer 테스트")
class LogSerializerTest {

    private LogSerializer serializer;

    @BeforeEach
    void setUp() {
        serializer = new LogSerializer();
    }

    @Nested
    @DisplayName("직렬화/역직렬화 라운드트립")
    class RoundTripTests {

        @Test
        @DisplayName("기본 로그 엔트리를 직렬화/역직렬화할 수 있어야 한다")
        void shouldSerializeAndDeserializeBasicEntry() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test message")
                    .build();

            // when
            byte[] serialized = serializer.serialize(original);
            LogEntry deserialized = serializer.deserialize(serialized);

            // then
            assertThat(deserialized.getTimestamp()).isEqualTo(original.getTimestamp());
            assertThat(deserialized.getLevel()).isEqualTo(original.getLevel());
            assertThat(deserialized.getMessage()).isEqualTo(original.getMessage());
        }

        @Test
        @DisplayName("페이로드가 있는 로그 엔트리를 직렬화/역직렬화할 수 있어야 한다")
        void shouldSerializeAndDeserializeEntryWithPayload() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test with payload")
                    .payload(Map.of("key1", "value1", "key2", 123))
                    .build();

            // when
            byte[] serialized = serializer.serialize(original);
            LogEntry deserialized = serializer.deserialize(serialized);

            // then
            assertThat(deserialized.getPayload()).containsEntry("key1", "value1");
            assertThat(deserialized.getPayload()).containsEntry("key2", 123);
        }

        @Test
        @DisplayName("분산 추적 ID가 있는 로그 엔트리를 처리할 수 있어야 한다")
        void shouldHandleDistributedTracingIds() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Traced message")
                    .traceId("0af7651916cd43dd8448eb211c80319c")
                    .spanId("b7ad6b7169203331")
                    .build();

            // when
            byte[] serialized = serializer.serialize(original);
            LogEntry deserialized = serializer.deserialize(serialized);

            // then
            assertThat(deserialized.getTraceId()).isEqualTo(original.getTraceId());
            assertThat(deserialized.getSpanId()).isEqualTo(original.getSpanId());
        }

        @Test
        @DisplayName("모든 필드가 있는 완전한 로그 엔트리를 처리할 수 있어야 한다")
        void shouldHandleFullEntry() {
            // given
            LogEntry original = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("ERROR")
                    .traceId("trace123")
                    .spanId("span456")
                    .context(Map.of("userId", "user_001", "region", "KR"))
                    .message("Full entry test")
                    .payload(Map.of("data", "value"))
                    .integrity("sha256:abc123")
                    .encryptedDek("ENC(xyz)")
                    .repeatCount(5)
                    .throwable("java.lang.Exception: test")
                    .build();

            // when
            byte[] serialized = serializer.serialize(original);
            LogEntry deserialized = serializer.deserialize(serialized);

            // then
            assertThat(deserialized.getTimestamp()).isEqualTo(original.getTimestamp());
            assertThat(deserialized.getLevel()).isEqualTo(original.getLevel());
            assertThat(deserialized.getTraceId()).isEqualTo(original.getTraceId());
            assertThat(deserialized.getSpanId()).isEqualTo(original.getSpanId());
            assertThat(deserialized.getContext()).isEqualTo(original.getContext());
            assertThat(deserialized.getMessage()).isEqualTo(original.getMessage());
            assertThat(deserialized.getPayload()).isEqualTo(original.getPayload());
            assertThat(deserialized.getIntegrity()).isEqualTo(original.getIntegrity());
            assertThat(deserialized.getEncryptedDek()).isEqualTo(original.getEncryptedDek());
            assertThat(deserialized.getRepeatCount()).isEqualTo(original.getRepeatCount());
            assertThat(deserialized.getThrowable()).isEqualTo(original.getThrowable());
        }
    }

    @Nested
    @DisplayName("압축")
    class CompressionTests {

        @Test
        @DisplayName("압축된 데이터는 원본 JSON보다 작아야 한다")
        void shouldCompressData() {
            // given
            StringBuilder longMessage = new StringBuilder();
            for (int i = 0; i < 100; i++) {
                longMessage.append("This is a repeated message for compression test. ");
            }

            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message(longMessage.toString())
                    .build();

            // when
            byte[] serialized = serializer.serialize(entry);

            // then
            // Zstd should compress repetitive content significantly
            assertThat(serialized.length).isLessThan(longMessage.length());
        }

        @Test
        @DisplayName("다른 압축 레벨로 직렬화/역직렬화가 가능해야 한다")
        void shouldWorkWithDifferentCompressionLevels() {
            // given
            LogSerializer lowCompression = new LogSerializer(1);
            LogSerializer highCompression = new LogSerializer(22);

            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Compression level test")
                    .build();

            // when
            byte[] lowData = lowCompression.serialize(entry);
            byte[] highData = highCompression.serialize(entry);

            LogEntry fromLow = lowCompression.deserialize(lowData);
            LogEntry fromHigh = highCompression.deserialize(highData);

            // then
            assertThat(fromLow.getMessage()).isEqualTo(entry.getMessage());
            assertThat(fromHigh.getMessage()).isEqualTo(entry.getMessage());
        }
    }

    @Nested
    @DisplayName("에러 처리")
    class ErrorHandlingTests {

        @Test
        @DisplayName("손상된 데이터는 역직렬화 예외를 발생시켜야 한다")
        void shouldThrowExceptionForCorruptedData() {
            // given
            byte[] corruptedData = new byte[]{0x01, 0x02, 0x03, 0x04};

            // when/then - Zstd throws ZstdException for corrupted data
            assertThatThrownBy(() -> serializer.deserialize(corruptedData))
                    .isInstanceOf(Exception.class);
        }

        @Test
        @DisplayName("빈 데이터는 역직렬화 예외를 발생시켜야 한다")
        void shouldThrowExceptionForEmptyData() {
            // given
            byte[] emptyData = new byte[0];

            // when/then
            assertThatThrownBy(() -> serializer.deserialize(emptyData))
                    .isInstanceOf(Exception.class);
        }
    }

    @Nested
    @DisplayName("특수 문자 처리")
    class SpecialCharacterTests {

        @Test
        @DisplayName("유니코드 문자를 처리할 수 있어야 한다")
        void shouldHandleUnicodeCharacters() {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("한글 메시지 🎉 日本語")
                    .build();

            // when
            byte[] serialized = serializer.serialize(entry);
            LogEntry deserialized = serializer.deserialize(serialized);

            // then
            assertThat(deserialized.getMessage()).isEqualTo("한글 메시지 🎉 日本語");
        }

        @Test
        @DisplayName("JSON 특수 문자를 처리할 수 있어야 한다")
        void shouldHandleJsonSpecialCharacters() {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Message with \"quotes\" and \\ backslash")
                    .build();

            // when
            byte[] serialized = serializer.serialize(entry);
            LogEntry deserialized = serializer.deserialize(serialized);

            // then
            assertThat(deserialized.getMessage()).isEqualTo("Message with \"quotes\" and \\ backslash");
        }
    }
}
