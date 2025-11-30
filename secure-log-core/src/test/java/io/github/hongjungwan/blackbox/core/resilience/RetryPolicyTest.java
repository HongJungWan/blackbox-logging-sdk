package io.github.hongjungwan.blackbox.core.resilience;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for RetryPolicy (FEAT-11: Resilience)
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
                    .noJitter()
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
                    .noJitter()
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
                    .noJitter()
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
                    .noJitter()
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
                    .noJitter()
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
    @DisplayName("Backoff Calculation")
    class BackoffCalculationTests {

        @Test
        @DisplayName("should calculate exponential delay")
        void shouldCalculateExponentialDelay() {
            RetryPolicy policy = RetryPolicy.builder()
                    .initialDelay(Duration.ofMillis(100))
                    .multiplier(2.0)
                    .maxDelay(Duration.ofSeconds(10))
                    .noJitter()
                    .build();

            // Attempt 1: 100ms
            assertThat(policy.calculateDelay(1).toMillis()).isEqualTo(100);

            // Attempt 2: 200ms
            assertThat(policy.calculateDelay(2).toMillis()).isEqualTo(200);

            // Attempt 3: 400ms
            assertThat(policy.calculateDelay(3).toMillis()).isEqualTo(400);
        }

        @Test
        @DisplayName("should cap at max delay")
        void shouldCapAtMaxDelay() {
            RetryPolicy policy = RetryPolicy.builder()
                    .initialDelay(Duration.ofSeconds(1))
                    .multiplier(10.0)
                    .maxDelay(Duration.ofSeconds(5))
                    .noJitter()
                    .build();

            // Attempt 3 would be 100s, should cap at 5s
            assertThat(policy.calculateDelay(3).toSeconds()).isEqualTo(5);
        }

        @Test
        @DisplayName("should apply jitter within bounds")
        void shouldApplyJitterWithinBounds() {
            RetryPolicy policy = RetryPolicy.builder()
                    .initialDelay(Duration.ofMillis(1000))
                    .multiplier(1.0)
                    .jitterFactor(0.25) // ±25%
                    .build();

            // Run multiple times to check jitter
            for (int i = 0; i < 10; i++) {
                Duration delay = policy.calculateDelay(1);
                // Should be between 750ms and 1250ms
                assertThat(delay.toMillis()).isBetween(750L, 1250L);
            }
        }

        @Test
        @DisplayName("should use fixed delay when multiplier is 1")
        void shouldUseFixedDelay() {
            RetryPolicy policy = RetryPolicy.builder()
                    .fixedDelay(Duration.ofMillis(500))
                    .noJitter()
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
                    .noJitter()
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
