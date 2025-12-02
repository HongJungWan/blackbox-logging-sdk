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
     * Execute operation with circuit breaker protection
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
     * Check if call is permitted
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
     * Record successful operation
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
     * Record failed operation
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

    private Duration calculateOpenDuration() {
        int openCount = consecutiveOpenCount.get();
        if (openCount <= 1) {
            return openDuration;
        }

        // Exponential backoff: base * 2^(count-1), capped at max
        long backoffMs = openDuration.toMillis() * (1L << (Math.min(openCount - 1, 10)));
        return Duration.ofMillis(Math.min(backoffMs, maxOpenDuration.toMillis()));
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

    private boolean transitionToHalfOpen() {
        stateLock.lock();
        try {
            if (state.get() == State.OPEN) {
                State previous = state.get();
                state.set(State.HALF_OPEN);
                successCount.set(0);

                log.info("Circuit breaker '{}' HALF_OPEN, testing recovery", name);

                notifyStateChange(previous, State.HALF_OPEN);
                return true;
            }
            return state.get() == State.HALF_OPEN;
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
     * Force reset to closed state (for testing/admin)
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
     * Get metrics snapshot
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
     * Create builder
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

        public Builder failureThreshold(int threshold) {
            this.failureThreshold = threshold;
            return this;
        }

        public Builder successThreshold(int threshold) {
            this.successThreshold = threshold;
            return this;
        }

        public Builder openDuration(Duration duration) {
            this.openDuration = duration;
            return this;
        }

        public Builder maxOpenDuration(Duration maxDuration) {
            this.maxOpenDuration = maxDuration;
            return this;
        }

        public Builder onStateChange(StateChangeListener listener) {
            this.stateChangeListener = listener;
            return this;
        }

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
