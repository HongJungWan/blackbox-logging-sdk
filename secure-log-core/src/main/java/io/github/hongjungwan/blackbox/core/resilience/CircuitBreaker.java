package io.github.hongjungwan.blackbox.core.resilience;

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * FEAT-11: Circuit Breaker (Resilience4j Pattern)
 *
 * State machine-based circuit breaker with:
 * - CLOSED: Normal operation, counting failures
 * - OPEN: Failing fast, not attempting operations
 * - HALF_OPEN: Testing if service has recovered
 *
 * Features:
 * - Configurable failure thresholds
 * - Recovery timeout with exponential backoff
 * - Metrics and state change listeners
 *
 * CRITICAL: Uses ReentrantLock instead of synchronized (Virtual Thread safe)
 */
@Slf4j
public final class CircuitBreaker {

    private final String name;
    private final int failureThreshold;
    private final int successThreshold;
    private final Duration openDuration;
    private final Duration maxOpenDuration;

    private final AtomicReference<State> state = new AtomicReference<>(State.CLOSED);
    private final AtomicInteger failureCount = new AtomicInteger(0);
    private final AtomicInteger successCount = new AtomicInteger(0);
    private final AtomicInteger consecutiveOpenCount = new AtomicInteger(0);
    private volatile Instant openedAt;

    // Virtual Thread safe lock
    private final ReentrantLock stateLock = new ReentrantLock();

    // Listeners
    private StateChangeListener stateChangeListener;

    public enum State {
        CLOSED,
        OPEN,
        HALF_OPEN
    }

    private CircuitBreaker(Builder builder) {
        this.name = builder.name;
        this.failureThreshold = builder.failureThreshold;
        this.successThreshold = builder.successThreshold;
        this.openDuration = builder.openDuration;
        this.maxOpenDuration = builder.maxOpenDuration;
        this.stateChangeListener = builder.stateChangeListener;
    }

    /**
     * Execute operation with circuit breaker protection.
     *
     * @param <T> the return type of the operation
     * @param operation the operation to execute
     * @return the result of the operation
     * @throws CircuitBreakerOpenException if the circuit breaker is open
     */
    public <T> T execute(Supplier<T> operation) throws CircuitBreakerOpenException {
        // Check if we should allow the call
        if (!tryAcquirePermission()) {
            throw new CircuitBreakerOpenException(name);
        }

        try {
            T result = operation.get();
            onSuccess();
            return result;

        } catch (Exception e) {
            onFailure(e);
            throw e;
        }
    }

    /**
     * Execute runnable with circuit breaker protection
     */
    public void execute(Runnable operation) throws CircuitBreakerOpenException {
        execute(() -> {
            operation.run();
            return null;
        });
    }

    /**
     * Check if a call is permitted based on current circuit breaker state.
     *
     * @return true if the call is permitted, false if circuit is open
     */
    public boolean tryAcquirePermission() {
        stateLock.lock();
        try {
            State currentState = state.get();

            switch (currentState) {
                case CLOSED:
                    return true;

                case OPEN:
                    // Check if we should transition to HALF_OPEN
                    if (shouldAttemptReset()) {
                        return transitionToHalfOpen();
                    }
                    return false;

                case HALF_OPEN:
                    // Only allow limited calls in half-open state
                    return true;

                default:
                    return false;
            }
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * Record a successful operation and potentially transition state.
     */
    public void onSuccess() {
        State currentState = state.get();

        if (currentState == State.HALF_OPEN) {
            int successes = successCount.incrementAndGet();
            if (successes >= successThreshold) {
                transitionToClosed();
            }
        } else if (currentState == State.CLOSED) {
            // Reset failure count on success
            failureCount.set(0);
        }
    }

    /**
     * Record a failed operation and potentially transition to OPEN state.
     *
     * @param e the exception that caused the failure
     */
    public void onFailure(Exception e) {
        State currentState = state.get();

        if (currentState == State.HALF_OPEN) {
            // Any failure in half-open goes back to open
            transitionToOpen();
        } else if (currentState == State.CLOSED) {
            int failures = failureCount.incrementAndGet();
            if (failures >= failureThreshold) {
                transitionToOpen();
            }
        }
    }

    private boolean shouldAttemptReset() {
        if (openedAt == null) {
            return false;
        }

        // Calculate current open duration with exponential backoff
        Duration currentOpenDuration = calculateOpenDuration();
        return Instant.now().isAfter(openedAt.plus(currentOpenDuration));
    }

    /**
     * FIX P2 #14: Add jitter to backoff calculation to prevent thundering herd.
     * Adds +/-20% jitter to the calculated duration.
     */
    private Duration calculateOpenDuration() {
        int openCount = consecutiveOpenCount.get();
        if (openCount <= 1) {
            return applyJitter(openDuration);
        }

        // Exponential backoff: base * 2^(count-1), capped at max
        long backoffMs = openDuration.toMillis() * (1L << (Math.min(openCount - 1, 10)));
        long cappedMs = Math.min(backoffMs, maxOpenDuration.toMillis());
        return applyJitter(Duration.ofMillis(cappedMs));
    }

    /**
     * Apply +/-20% jitter to a duration.
     */
    private Duration applyJitter(Duration duration) {
        // Generate jitter factor between 0.8 and 1.2
        double jitter = 0.8 + (java.util.concurrent.ThreadLocalRandom.current().nextDouble() * 0.4);
        return Duration.ofMillis((long) (duration.toMillis() * jitter));
    }

    private void transitionToOpen() {
        stateLock.lock();
        try {
            State previous = state.get();
            if (previous != State.OPEN) {
                state.set(State.OPEN);
                openedAt = Instant.now();
                failureCount.set(0);
                successCount.set(0);
                consecutiveOpenCount.incrementAndGet();

                log.warn("Circuit breaker '{}' OPEN after {} failures",
                        name, failureThreshold);

                notifyStateChange(previous, State.OPEN);
            }
        } finally {
            stateLock.unlock();
        }
    }

    /**
     * FIX P0 #5: Use compareAndSet for atomic state transition verification.
     * Previously the method returned state.get() == State.HALF_OPEN instead of the actual
     * CAS result, which could return true even if this thread didn't perform the transition.
     */
    private boolean transitionToHalfOpen() {
        stateLock.lock();
        try {
            if (state.compareAndSet(State.OPEN, State.HALF_OPEN)) {
                successCount.set(0);

                log.info("Circuit breaker '{}' HALF_OPEN, testing recovery", name);

                notifyStateChange(State.OPEN, State.HALF_OPEN);
                return true;
            }
            return false;
        } finally {
            stateLock.unlock();
        }
    }

    private void transitionToClosed() {
        stateLock.lock();
        try {
            State previous = state.get();
            if (previous != State.CLOSED) {
                state.set(State.CLOSED);
                failureCount.set(0);
                successCount.set(0);
                consecutiveOpenCount.set(0);

                log.info("Circuit breaker '{}' CLOSED, service recovered", name);

                notifyStateChange(previous, State.CLOSED);
            }
        } finally {
            stateLock.unlock();
        }
    }

    private void notifyStateChange(State from, State to) {
        if (stateChangeListener != null) {
            try {
                stateChangeListener.onStateChange(name, from, to);
            } catch (Exception e) {
                log.warn("State change listener threw exception", e);
            }
        }
    }

    /**
     * Force reset to CLOSED state (for testing/admin purposes).
     */
    public void reset() {
        stateLock.lock();
        try {
            State previous = state.get();
            state.set(State.CLOSED);
            failureCount.set(0);
            successCount.set(0);
            consecutiveOpenCount.set(0);
            openedAt = null;

            log.info("Circuit breaker '{}' manually reset to CLOSED", name);

            if (previous != State.CLOSED) {
                notifyStateChange(previous, State.CLOSED);
            }
        } finally {
            stateLock.unlock();
        }
    }

    // Getters
    public String getName() { return name; }
    public State getState() { return state.get(); }
    public int getFailureCount() { return failureCount.get(); }

    /**
     * Get a snapshot of current circuit breaker metrics.
     *
     * @return the current metrics including state, failure count, and timing info
     */
    public Metrics getMetrics() {
        return new Metrics(
                name,
                state.get(),
                failureCount.get(),
                successCount.get(),
                consecutiveOpenCount.get(),
                openedAt
        );
    }

    /**
     * Create a new builder for constructing a CircuitBreaker.
     *
     * @param name the circuit breaker name for identification and logging
     * @return a new Builder instance
     */
    public static Builder builder(String name) {
        return new Builder(name);
    }

    /**
     * Metrics record
     */
    public record Metrics(
            String name,
            State state,
            int failureCount,
            int successCount,
            int consecutiveOpenCount,
            Instant openedAt
    ) {}

    /**
     * State change listener
     */
    @FunctionalInterface
    public interface StateChangeListener {
        void onStateChange(String name, State from, State to);
    }

    /**
     * Builder
     */
    public static class Builder {
        private final String name;
        private int failureThreshold = 3;
        private int successThreshold = 2;
        private Duration openDuration = Duration.ofSeconds(30);
        private Duration maxOpenDuration = Duration.ofMinutes(5);
        private StateChangeListener stateChangeListener;

        public Builder(String name) {
            this.name = name;
        }

        /**
         * Sets the number of failures before transitioning to OPEN state.
         *
         * @param threshold the failure threshold (default: 3)
         * @return this builder for method chaining
         */
        public Builder failureThreshold(int threshold) {
            this.failureThreshold = threshold;
            return this;
        }

        /**
         * Sets the number of successes in HALF_OPEN before transitioning to CLOSED.
         *
         * @param threshold the success threshold (default: 2)
         * @return this builder for method chaining
         */
        public Builder successThreshold(int threshold) {
            this.successThreshold = threshold;
            return this;
        }

        /**
         * Sets the initial duration to stay in OPEN state before testing recovery.
         *
         * @param duration the open duration (default: 30 seconds)
         * @return this builder for method chaining
         */
        public Builder openDuration(Duration duration) {
            this.openDuration = duration;
            return this;
        }

        /**
         * Sets the maximum duration for exponential backoff in OPEN state.
         *
         * @param maxDuration the maximum open duration (default: 5 minutes)
         * @return this builder for method chaining
         */
        public Builder maxOpenDuration(Duration maxDuration) {
            this.maxOpenDuration = maxDuration;
            return this;
        }

        /**
         * Sets the listener for state change events.
         *
         * @param listener the state change listener
         * @return this builder for method chaining
         */
        public Builder onStateChange(StateChangeListener listener) {
            this.stateChangeListener = listener;
            return this;
        }

        /**
         * Builds the CircuitBreaker instance.
         *
         * @return a new CircuitBreaker with the configured settings
         */
        public CircuitBreaker build() {
            return new CircuitBreaker(this);
        }
    }

    /**
     * Exception thrown when circuit is open
     */
    public static class CircuitBreakerOpenException extends RuntimeException {
        private final String circuitBreakerName;

        public CircuitBreakerOpenException(String name) {
            super("Circuit breaker '" + name + "' is OPEN");
            this.circuitBreakerName = name;
        }

        public String getCircuitBreakerName() {
            return circuitBreakerName;
        }
    }
}
