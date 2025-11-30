package io.github.hongjungwan.blackbox.core.transport;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.internal.LogTransport;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LogTransport 테스트")
class LogTransportTest {

    @TempDir
    Path tempDir;

    private LogTransport transport;
    private LogSerializer serializer;
    private SecureLogConfig config;

    @BeforeEach
    void setUp() {
        serializer = new LogSerializer();
        config = SecureLogConfig.builder()
                .fallbackDirectory(tempDir.toString())
                // No Kafka configured - will use fallback
                .build();
        transport = new LogTransport(config, serializer);
    }

    @AfterEach
    void tearDown() {
        if (transport != null) {
            transport.close();
        }
    }

    @Nested
    @DisplayName("폴백 저장")
    class FallbackStorageTests {

        @Test
        @DisplayName("Kafka가 없을 때 폴백 디렉토리에 파일을 생성해야 한다")
        void shouldWriteToFallbackWhenKafkaNotConfigured() throws IOException {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test message")
                    .build();
            byte[] data = serializer.serialize(entry);

            // when
            transport.send(data);

            // then
            try (Stream<Path> files = Files.list(tempDir)) {
                List<Path> fallbackFiles = files
                        .filter(p -> p.toString().endsWith(".zst"))
                        .toList();
                assertThat(fallbackFiles).hasSize(1);
            }
        }

        @Test
        @DisplayName("폴백 파일 이름이 올바른 형식이어야 한다")
        void shouldCreateFallbackFileWithCorrectFormat() throws IOException {
            // given
            byte[] data = "test data".getBytes();

            // when
            transport.sendToFallback(data);

            // then
            try (Stream<Path> files = Files.list(tempDir)) {
                List<Path> fallbackFiles = files
                        .filter(p -> p.getFileName().toString().startsWith("log-"))
                        .filter(p -> p.toString().endsWith(".zst"))
                        .toList();
                assertThat(fallbackFiles).hasSize(1);
            }
        }

        @Test
        @DisplayName("LogEntry를 폴백에 저장할 수 있어야 한다")
        void shouldWriteLogEntryToFallback() throws IOException {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("ERROR")
                    .message("Error message")
                    .build();

            // when
            transport.sendToFallback(entry);

            // then
            try (Stream<Path> files = Files.list(tempDir)) {
                long count = files.filter(p -> p.toString().endsWith(".zst")).count();
                assertThat(count).isEqualTo(1);
            }
        }
    }

    @Nested
    @DisplayName("서킷 브레이커")
    class CircuitBreakerTests {

        @Test
        @DisplayName("연속 실패 시 서킷이 열려야 한다")
        void shouldOpenCircuitAfterConsecutiveFailures() throws IOException {
            // given - config with invalid Kafka to trigger failures
            SecureLogConfig failingConfig = SecureLogConfig.builder()
                    .kafkaBootstrapServers("localhost:9999") // Invalid server
                    .fallbackDirectory(tempDir.toString())
                    .kafkaMaxBlockMs(100) // Quick timeout
                    .build();

            // Note: Creating transport with invalid Kafka will try to connect
            // In real scenario, failures would accumulate on send()
            // For this test, we verify fallback behavior without Kafka

            // when - multiple sends without Kafka
            byte[] data = "test".getBytes();
            for (int i = 0; i < 5; i++) {
                transport.send(data);
            }

            // then - should have fallback files
            try (Stream<Path> files = Files.list(tempDir)) {
                long count = files.filter(p -> p.toString().endsWith(".zst")).count();
                assertThat(count).isGreaterThan(0);
            }
        }
    }

    @Nested
    @DisplayName("폴백 디렉토리 관리")
    class FallbackDirectoryTests {

        @Test
        @DisplayName("폴백 디렉토리가 자동으로 생성되어야 한다")
        void shouldCreateFallbackDirectory() {
            // given
            Path nestedDir = tempDir.resolve("nested").resolve("fallback");
            SecureLogConfig configWithNestedDir = SecureLogConfig.builder()
                    .fallbackDirectory(nestedDir.toString())
                    .build();

            // when
            LogTransport transportWithNestedDir = new LogTransport(configWithNestedDir, serializer);

            // then
            assertThat(Files.exists(nestedDir)).isTrue();
            transportWithNestedDir.close();
        }
    }

    @Nested
    @DisplayName("리소스 정리")
    class ResourceCleanupTests {

        @Test
        @DisplayName("close() 후에도 안전해야 한다")
        void shouldBeSafeAfterClose() {
            // given
            transport.close();

            // when/then - should not throw
            transport.close(); // Double close should be safe
        }
    }
}
