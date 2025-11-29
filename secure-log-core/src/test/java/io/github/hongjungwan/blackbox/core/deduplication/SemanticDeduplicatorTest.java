package io.github.hongjungwan.blackbox.core.deduplication;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SemanticDeduplicator 테스트")
class SemanticDeduplicatorTest {

    private SemanticDeduplicator deduplicator;

    @BeforeEach
    void setUp() {
        SecureLogConfig config = SecureLogConfig.builder()
                .deduplicationWindowMs(1000) // 1 second window
                .build();
        deduplicator = new SemanticDeduplicator(config);
    }

    @Nested
    @DisplayName("중복 감지")
    class DuplicateDetectionTests {

        @Test
        @DisplayName("첫 번째 로그는 중복이 아니어야 한다")
        void shouldNotBeDuplicateForFirstOccurrence() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("User logged in")
                    .build();

            // when
            boolean isDuplicate = deduplicator.isDuplicate(entry);

            // then
            assertThat(isDuplicate).isFalse();
        }

        @Test
        @DisplayName("동일한 메시지의 두 번째 로그는 중복이어야 한다")
        void shouldBeDuplicateForSecondOccurrence() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("User logged in")
                    .build();

            // when
            deduplicator.isDuplicate(entry); // first call
            boolean isDuplicate = deduplicator.isDuplicate(entry); // second call

            // then
            assertThat(isDuplicate).isTrue();
        }

        @Test
        @DisplayName("다른 메시지는 중복이 아니어야 한다")
        void shouldNotBeDuplicateForDifferentMessages() {
            // given
            LogEntry entry1 = LogEntry.builder()
                    .message("User logged in")
                    .build();
            LogEntry entry2 = LogEntry.builder()
                    .message("User logged out")
                    .build();

            // when
            boolean isDuplicate1 = deduplicator.isDuplicate(entry1);
            boolean isDuplicate2 = deduplicator.isDuplicate(entry2);

            // then
            assertThat(isDuplicate1).isFalse();
            assertThat(isDuplicate2).isFalse();
        }
    }

    @Nested
    @DisplayName("메시지 템플릿 추출")
    class MessageTemplateTests {

        @Test
        @DisplayName("숫자가 다른 메시지도 동일한 템플릿으로 인식해야 한다")
        void shouldRecognizeSameTemplateWithDifferentNumbers() {
            // given
            LogEntry entry1 = LogEntry.builder()
                    .message("User 123 logged in at 1234567890")
                    .build();
            LogEntry entry2 = LogEntry.builder()
                    .message("User 456 logged in at 9876543210")
                    .build();

            // when
            boolean isDuplicate1 = deduplicator.isDuplicate(entry1);
            boolean isDuplicate2 = deduplicator.isDuplicate(entry2);

            // then
            assertThat(isDuplicate1).isFalse();
            assertThat(isDuplicate2).isTrue(); // Same template
        }

        @Test
        @DisplayName("null 메시지도 처리해야 한다")
        void shouldHandleNullMessage() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message(null)
                    .build();

            // when
            boolean isDuplicate = deduplicator.isDuplicate(entry);

            // then
            assertThat(isDuplicate).isFalse();
        }
    }

    @Nested
    @DisplayName("예외 시그니처 처리")
    class ThrowableSignatureTests {

        @Test
        @DisplayName("동일한 예외를 가진 로그는 중복으로 인식해야 한다")
        void shouldRecognizeDuplicateWithSameThrowable() {
            // given
            String throwableStr = "java.lang.NullPointerException: null value";
            LogEntry entry1 = LogEntry.builder()
                    .message("Error occurred")
                    .throwable(throwableStr)
                    .build();
            LogEntry entry2 = LogEntry.builder()
                    .message("Error occurred")
                    .throwable(throwableStr)
                    .build();

            // when
            boolean isDuplicate1 = deduplicator.isDuplicate(entry1);
            boolean isDuplicate2 = deduplicator.isDuplicate(entry2);

            // then
            assertThat(isDuplicate1).isFalse();
            assertThat(isDuplicate2).isTrue();
        }

        @Test
        @DisplayName("다른 예외를 가진 로그는 중복이 아니어야 한다")
        void shouldNotBeDuplicateWithDifferentThrowable() {
            // given
            LogEntry entry1 = LogEntry.builder()
                    .message("Error occurred")
                    .throwable("java.lang.NullPointerException")
                    .build();
            LogEntry entry2 = LogEntry.builder()
                    .message("Error occurred")
                    .throwable("java.lang.IllegalArgumentException")
                    .build();

            // when
            boolean isDuplicate1 = deduplicator.isDuplicate(entry1);
            boolean isDuplicate2 = deduplicator.isDuplicate(entry2);

            // then
            assertThat(isDuplicate1).isFalse();
            assertThat(isDuplicate2).isFalse();
        }
    }

    @Nested
    @DisplayName("반복 카운트")
    class RepeatCountTests {

        @Test
        @DisplayName("반복 횟수를 정확히 추적해야 한다")
        void shouldTrackRepeatCount() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Repeated message")
                    .build();

            // when
            deduplicator.isDuplicate(entry);
            deduplicator.isDuplicate(entry);
            deduplicator.isDuplicate(entry);
            int count = deduplicator.getRepeatCount(entry);

            // then
            assertThat(count).isEqualTo(3);
        }

        @Test
        @DisplayName("존재하지 않는 로그의 반복 횟수는 0이어야 한다")
        void shouldReturnZeroForNonExistentEntry() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Never seen before")
                    .build();

            // when
            int count = deduplicator.getRepeatCount(entry);

            // then
            assertThat(count).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("스레드 안전성")
    class ThreadSafetyTests {

        @Test
        @DisplayName("동시 접근에서도 카운트가 정확해야 한다")
        void shouldBeThreadSafe() throws InterruptedException {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Concurrent message")
                    .build();
            int threadCount = 10;
            int iterationsPerThread = 100;
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger duplicateCount = new AtomicInteger(0);

            ExecutorService executor = Executors.newFixedThreadPool(threadCount);

            // when
            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterationsPerThread; j++) {
                            if (deduplicator.isDuplicate(entry)) {
                                duplicateCount.incrementAndGet();
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            // then
            int totalCount = deduplicator.getRepeatCount(entry);
            assertThat(totalCount).isEqualTo(threadCount * iterationsPerThread);
            // First call is not duplicate, rest are duplicates
            assertThat(duplicateCount.get()).isEqualTo(totalCount - 1);
        }
    }

    @Nested
    @DisplayName("캐시 관리")
    class CacheManagementTests {

        @Test
        @DisplayName("캐시 클리어 후에는 중복이 아니어야 한다")
        void shouldNotBeDuplicateAfterClear() {
            // given
            LogEntry entry = LogEntry.builder()
                    .message("Message to clear")
                    .build();
            deduplicator.isDuplicate(entry);
            assertThat(deduplicator.isDuplicate(entry)).isTrue();

            // when
            deduplicator.clear();

            // then
            assertThat(deduplicator.isDuplicate(entry)).isFalse();
        }
    }
}
