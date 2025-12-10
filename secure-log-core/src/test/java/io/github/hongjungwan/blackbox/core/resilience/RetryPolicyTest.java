package io.github.hongjungwan.blackbox.core.resilience;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for RetryPolicy (단순화된 버전 - 고정 간격 재시도)
 */
@DisplayName("RetryPolicy")
class RetryPolicyTest {

    @Nested
    @DisplayName("Successful Execution")
    class SuccessfulExecutionTests {

        @Test
        @DisplayName("should return result on success")
        void shouldReturnResultOnSuccess() {
            RetryPolicy policy = RetryPolicy.builder()
                    .maxAttempts(3)
                    .build();

            String result = policy.execute(() -> "success");

            assertThat(result).isEqualTo("success");
        }

        @Test
        @DisplayName("should not retry on success")
        void shouldNotRetryOnSuccess() {
            RetryPolicy policy = RetryPolicy.defaults();
            AtomicInteger attempts = new AtomicInteger(0);

            policy.execute(() -> {
                attempts.incrementAndGet();
                return "success";
            });

            assertThat(attempts.get()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("Retry Behavior")
    class RetryBehaviorTests {

        @Test
        @DisplayName("should retry up to max attempts")
        void shouldRetryUpToMaxAttempts() {
            RetryPolicy policy = RetryPolicy.builder()
                    .maxAttempts(3)
                    .initialDelay(Duration.ofMillis(1))
                    .build();

            AtomicInteger attempts = new AtomicInteger(0);

            assertThatThrownBy(() -> policy.execute(() -> {
                attempts.incrementAndGet();
                throw new RuntimeException("always fails");
            })).isInstanceOf(RetryPolicy.RetryExhaustedException.class);

            assertThat(attempts.get()).isEqualTo(3);
        }

        @Test
        @DisplayName("should succeed on last retry")
        void shouldSucceedOnLastRetry() {
            RetryPolicy policy = RetryPolicy.builder()
                    .maxAttempts(3)
                    .initialDelay(Duration.ofMillis(1))
                    .build();

            AtomicInteger attempts = new AtomicInteger(0);

            String result = policy.execute(() -> {
                if (attempts.incrementAndGet() < 3) {
                    throw new RuntimeException("not yet");
                }
                return "finally success";
            });

            assertThat(result).isEqualTo("finally success");
            assertThat(attempts.get()).isEqualTo(3);
        }

        @Test
        @DisplayName("should only retry specified exceptions")
        void shouldOnlyRetrySpecifiedExceptions() {
            RetryPolicy policy = RetryPolicy.builder()
                    .maxAttempts(3)
                    .retryOnExceptions(IllegalArgumentException.class)
                    .initialDelay(Duration.ofMillis(1))
                    .build();

            AtomicInteger attempts = new AtomicInteger(0);

            // Should not retry on RuntimeException
            assertThatThrownBy(() -> policy.execute(() -> {
                attempts.incrementAndGet();
                throw new RuntimeException("not retryable");
            })).isInstanceOf(RetryPolicy.RetryExhaustedException.class);

            assertThat(attempts.get()).isEqualTo(1);
        }

        @Test
        @DisplayName("should use custom retry predicate")
        void shouldUseCustomRetryPredicate() {
            RetryPolicy policy = RetryPolicy.builder()
                    .maxAttempts(5)
                    .retryOn(e -> e.getMessage() != null && e.getMessage().contains("retry"))
                    .initialDelay(Duration.ofMillis(1))
                    .build();

            AtomicInteger attempts = new AtomicInteger(0);

            // Should retry when message contains "retry", stop when it doesn't
            assertThatThrownBy(() -> policy.execute(() -> {
                int attempt = attempts.incrementAndGet();
                if (attempt < 3) {
                    throw new RuntimeException("please retry");
                }
                throw new RuntimeException("do not retry this");
            })).isInstanceOf(RetryPolicy.RetryExhaustedException.class);

            // Should have stopped after "do not retry this" exception (predicate returns false)
            assertThat(attempts.get()).isGreaterThanOrEqualTo(3);
        }
    }

    @Nested
    @DisplayName("Fixed Delay (단순화)")
    class FixedDelayTests {

        @Test
        @DisplayName("should use fixed delay for all retries")
        void shouldUseFixedDelay() {
            RetryPolicy policy = RetryPolicy.builder()
                    .initialDelay(Duration.ofMillis(100))
                    .build();

            // 모든 시도에서 동일한 딜레이
            assertThat(policy.calculateDelay(1).toMillis()).isEqualTo(100);
            assertThat(policy.calculateDelay(2).toMillis()).isEqualTo(100);
            assertThat(policy.calculateDelay(3).toMillis()).isEqualTo(100);
        }

        @Test
        @DisplayName("should use fixedDelay builder method")
        void shouldUseFixedDelayMethod() {
            RetryPolicy policy = RetryPolicy.builder()
                    .fixedDelay(Duration.ofMillis(500))
                    .build();

            assertThat(policy.calculateDelay(1).toMillis()).isEqualTo(500);
            assertThat(policy.calculateDelay(2).toMillis()).isEqualTo(500);
            assertThat(policy.calculateDelay(3).toMillis()).isEqualTo(500);
        }
    }

    @Nested
    @DisplayName("Runnable Execution")
    class RunnableExecutionTests {

        @Test
        @DisplayName("should execute runnable with retry")
        void shouldExecuteRunnableWithRetry() {
            RetryPolicy policy = RetryPolicy.builder()
                    .maxAttempts(3)
                    .initialDelay(Duration.ofMillis(1))
                    .build();

            AtomicInteger counter = new AtomicInteger(0);

            policy.execute((Runnable) () -> {
                if (counter.incrementAndGet() < 3) {
                    throw new RuntimeException("not yet");
                }
            });

            assertThat(counter.get()).isEqualTo(3);
        }
    }
}
