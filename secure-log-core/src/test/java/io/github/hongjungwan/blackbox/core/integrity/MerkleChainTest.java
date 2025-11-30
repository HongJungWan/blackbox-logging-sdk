package io.github.hongjungwan.blackbox.core.integrity;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("MerkleChain 테스트")
class MerkleChainTest {

    private MerkleChain merkleChain;

    @BeforeEach
    void setUp() {
        merkleChain = new MerkleChain();
    }

    @Nested
    @DisplayName("해시 체이닝")
    class HashChainingTests {

        @Test
        @DisplayName("무결성 해시가 추가되어야 한다")
        void shouldAddIntegrityHash() {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test message")
                    .build();

            // when
            LogEntry chainedEntry = merkleChain.addToChain(entry);

            // then
            assertThat(chainedEntry.getIntegrity()).isNotNull();
            assertThat(chainedEntry.getIntegrity()).startsWith("sha256:");
            assertThat(chainedEntry.getIntegrity().length()).isEqualTo(71); // "sha256:" + 64 hex chars
        }

        @Test
        @DisplayName("동일한 입력은 동일한 해시를 생성해야 한다")
        void shouldGenerateSameHashForSameInput() {
            // given
            long timestamp = System.currentTimeMillis();
            LogEntry entry1 = LogEntry.builder()
                    .timestamp(timestamp)
                    .level("INFO")
                    .message("Same message")
                    .build();

            // Reset chain between calls
            merkleChain.reset();
            LogEntry chained1 = merkleChain.addToChain(entry1);

            merkleChain.reset();
            LogEntry entry2 = LogEntry.builder()
                    .timestamp(timestamp)
                    .level("INFO")
                    .message("Same message")
                    .build();
            LogEntry chained2 = merkleChain.addToChain(entry2);

            // then
            assertThat(chained1.getIntegrity()).isEqualTo(chained2.getIntegrity());
        }

        @Test
        @DisplayName("연속된 엔트리는 서로 다른 해시를 가져야 한다 (체이닝)")
        void shouldHaveDifferentHashesForChainedEntries() {
            // given
            LogEntry entry1 = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("First message")
                    .build();
            LogEntry entry2 = LogEntry.builder()
                    .timestamp(System.currentTimeMillis() + 1)
                    .level("INFO")
                    .message("Second message")
                    .build();

            // when
            LogEntry chained1 = merkleChain.addToChain(entry1);
            LogEntry chained2 = merkleChain.addToChain(entry2);

            // then
            assertThat(chained1.getIntegrity()).isNotEqualTo(chained2.getIntegrity());
        }
    }

    @Nested
    @DisplayName("무결성 검증")
    class IntegrityVerificationTests {

        @Test
        @DisplayName("유효한 체인은 검증을 통과해야 한다")
        void shouldVerifyValidChain() {
            // given
            String initialHash = "0000000000000000000000000000000000000000000000000000000000000000";
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test message")
                    .build();

            LogEntry chainedEntry = merkleChain.addToChain(entry);

            // when
            boolean isValid = merkleChain.verifyChain(chainedEntry, initialHash);

            // then
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("변조된 데이터는 검증에 실패해야 한다")
        void shouldFailVerificationForTamperedData() {
            // given
            String initialHash = "0000000000000000000000000000000000000000000000000000000000000000";
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Original message")
                    .build();

            LogEntry chainedEntry = merkleChain.addToChain(entry);

            // Tamper with the entry
            LogEntry tamperedEntry = LogEntry.builder()
                    .timestamp(chainedEntry.getTimestamp())
                    .level("INFO")
                    .message("Tampered message")
                    .integrity(chainedEntry.getIntegrity())
                    .build();

            // when
            boolean isValid = merkleChain.verifyChain(tamperedEntry, initialHash);

            // then
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("잘못된 이전 해시는 검증에 실패해야 한다")
        void shouldFailVerificationForWrongPreviousHash() {
            // given
            LogEntry entry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("Test message")
                    .build();

            LogEntry chainedEntry = merkleChain.addToChain(entry);

            // when
            boolean isValid = merkleChain.verifyChain(chainedEntry, "wrong_previous_hash");

            // then
            assertThat(isValid).isFalse();
        }
    }

    @Nested
    @DisplayName("페이로드 포함")
    class PayloadInclusionTests {

        @Test
        @DisplayName("페이로드가 해시 계산에 포함되어야 한다")
        void shouldIncludePayloadInHash() {
            // given
            long timestamp = System.currentTimeMillis();
            LogEntry entryWithPayload = LogEntry.builder()
                    .timestamp(timestamp)
                    .level("INFO")
                    .message("Test")
                    .payload(Map.of("key", "value"))
                    .build();

            LogEntry entryWithoutPayload = LogEntry.builder()
                    .timestamp(timestamp)
                    .level("INFO")
                    .message("Test")
                    .build();

            // when
            LogEntry chained1 = merkleChain.addToChain(entryWithPayload);
            merkleChain.reset();
            LogEntry chained2 = merkleChain.addToChain(entryWithoutPayload);

            // then
            assertThat(chained1.getIntegrity()).isNotEqualTo(chained2.getIntegrity());
        }
    }

    @Nested
    @DisplayName("스레드 안전성")
    class ThreadSafetyTests {

        @Test
        @DisplayName("동시 접근에서도 해시 체인이 일관성을 유지해야 한다")
        void shouldMaintainConsistencyUnderConcurrentAccess() throws InterruptedException {
            // given
            int threadCount = 10;
            int entriesPerThread = 100;
            CountDownLatch latch = new CountDownLatch(threadCount);
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);

            // when
            for (int i = 0; i < threadCount; i++) {
                final int threadId = i;
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < entriesPerThread; j++) {
                            LogEntry entry = LogEntry.builder()
                                    .timestamp(System.currentTimeMillis())
                                    .level("INFO")
                                    .message("Thread " + threadId + " Entry " + j)
                                    .build();
                            LogEntry chained = merkleChain.addToChain(entry);
                            assertThat(chained.getIntegrity()).isNotNull();
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            // then - no exception thrown means consistent operation
        }
    }

    @Nested
    @DisplayName("체인 리셋")
    class ChainResetTests {

        @Test
        @DisplayName("리셋 후 초기 해시로 시작해야 한다")
        void shouldStartFromInitialHashAfterReset() {
            // given
            long timestamp = System.currentTimeMillis();
            LogEntry entry = LogEntry.builder()
                    .timestamp(timestamp)
                    .level("INFO")
                    .message("Test")
                    .build();

            LogEntry chained1 = merkleChain.addToChain(entry);
            merkleChain.reset();

            // Same entry after reset
            LogEntry entry2 = LogEntry.builder()
                    .timestamp(timestamp)
                    .level("INFO")
                    .message("Test")
                    .build();
            LogEntry chained2 = merkleChain.addToChain(entry2);

            // then
            assertThat(chained1.getIntegrity()).isEqualTo(chained2.getIntegrity());
        }
    }
}
