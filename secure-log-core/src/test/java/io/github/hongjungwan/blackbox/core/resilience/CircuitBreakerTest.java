package io.github.hongjungwan.blackbox.core.resilience;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for CircuitBreaker (단순화된 버전)
 */
@DisplayName("CircuitBreaker")
class CircuitBreakerTest {

    private CircuitBreaker circuitBreaker;

    @BeforeEach
    void setUp() {
        circuitBreaker = CircuitBreaker.builder("test")
                .failureThreshold(3)
                .openDuration(Duration.ofMillis(100))
                .build();
    }

    @Nested
    @DisplayName("State Transitions")
    class StateTransitionTests {

        @Test
        @DisplayName("should start in CLOSED state")
        void shouldStartClosed() {
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("should transition to OPEN after failure threshold")
        void shouldOpenAfterFailures() {
            // Record failures up to threshold
            for (int i = 0; i < 3; i++) {
                circuitBreaker.onFailure(new RuntimeException("test"));
            }

            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.OPEN);
        }

        @Test
        @DisplayName("should reset failure count on success")
        void shouldResetFailureCountOnSuccess() {
            circuitBreaker.onFailure(new RuntimeException("test"));
            circuitBreaker.onFailure(new RuntimeException("test"));

            assertThat(circuitBreaker.getFailureCount()).isEqualTo(2);

            circuitBreaker.onSuccess();

            assertThat(circuitBreaker.getFailureCount()).isEqualTo(0);
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("should auto-reset to CLOSED after timeout")
        void shouldAutoResetAfterTimeout() throws InterruptedException {
            // Open the circuit
            for (int i = 0; i < 3; i++) {
                circuitBreaker.onFailure(new RuntimeException("test"));
            }
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.OPEN);

            // Wait for reset timeout
            Thread.sleep(150);

            // isOpen() check triggers auto-reset
            assertThat(circuitBreaker.isOpen()).isFalse();
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("should allow calls after timeout expires")
        void shouldAllowCallsAfterTimeout() throws InterruptedException {
            // Open the circuit
            for (int i = 0; i < 3; i++) {
                circuitBreaker.onFailure(new RuntimeException("test"));
            }

            // Wait for reset timeout
            Thread.sleep(150);

            // Should allow permission
            boolean permitted = circuitBreaker.tryAcquirePermission();
            assertThat(permitted).isTrue();
        }
    }

    @Nested
    @DisplayName("Execute with Protection")
    class ExecuteTests {

        @Test
        @DisplayName("should execute operation when CLOSED")
        void shouldExecuteWhenClosed() {
            String result = circuitBreaker.execute(() -> "success");

            assertThat(result).isEqualTo("success");
        }

        @Test
        @DisplayName("should throw exception when OPEN")
        void shouldThrowWhenOpen() {
            // Open the circuit
            for (int i = 0; i < 3; i++) {
                circuitBreaker.onFailure(new RuntimeException("test"));
            }

            assertThatThrownBy(() -> circuitBreaker.execute(() -> "test"))
                    .isInstanceOf(CircuitBreaker.CircuitBreakerOpenException.class);
        }

        @Test
        @DisplayName("should record failure on exception")
        void shouldRecordFailureOnException() {
            AtomicInteger attempts = new AtomicInteger(0);

            // Execute operations that fail
            for (int i = 0; i < 3; i++) {
                try {
                    circuitBreaker.execute(() -> {
                        attempts.incrementAndGet();
                        throw new RuntimeException("intentional failure");
                    });
                } catch (RuntimeException ignored) {
                    // Expected
                }
            }

            assertThat(attempts.get()).isEqualTo(3);
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.OPEN);
        }
    }

    @Nested
    @DisplayName("Metrics")
    class MetricsTests {

        @Test
        @DisplayName("should track failure count")
        void shouldTrackFailureCount() {
            circuitBreaker.onFailure(new RuntimeException("test"));
            circuitBreaker.onFailure(new RuntimeException("test"));

            CircuitBreaker.Metrics metrics = circuitBreaker.getMetrics();

            assertThat(metrics.failureCount()).isEqualTo(2);
            assertThat(metrics.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        }

        @Test
        @DisplayName("should notify state change listener")
        void shouldNotifyStateChangeListener() {
            AtomicInteger openedCount = new AtomicInteger(0);

            CircuitBreaker cb = CircuitBreaker.builder("listener-test")
                    .failureThreshold(2)
                    .onStateChange((name, from, to) -> {
                        if (to == CircuitBreaker.State.OPEN) {
                            openedCount.incrementAndGet();
                        }
                    })
                    .build();

            cb.onFailure(new RuntimeException("test"));
            cb.onFailure(new RuntimeException("test"));

            assertThat(openedCount.get()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("Reset")
    class ResetTests {

        @Test
        @DisplayName("should reset to CLOSED state")
        void shouldResetToClosed() {
            // Open the circuit
            for (int i = 0; i < 3; i++) {
                circuitBreaker.onFailure(new RuntimeException("test"));
            }
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.OPEN);

            // Reset
            circuitBreaker.reset();

            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
            assertThat(circuitBreaker.getFailureCount()).isEqualTo(0);
        }
    }
}
