package io.github.hongjungwan.blackbox.core.resilience;

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * FEAT-11: Retry Policy with Exponential Backoff (Sentry Pattern)
 *
 * Configurable retry policy supporting:
 * - Exponential backoff with jitter
 * - Retry budgets
 * - Exception filtering
 * - Custom backoff strategies
 *
 * Based on:
 * - Sentry SDK retry logic
 * - AWS SDK retry policies
 * - Resilience4j patterns
 *
 * @see <a href="https://github.com/getsentry/sentry-java">Sentry Java</a>
 * @see <a href="https://github.com/aws/aws-sdk-java-v2">AWS SDK Java v2</a>
 */
@Slf4j
public final class RetryPolicy {

    private final int maxAttempts;
    private final Duration initialDelay;
    private final Duration maxDelay;
    private final double multiplier;
    private final double jitterFactor;
    private final Predicate<Exception> retryPredicate;
    private final Set<Class<? extends Exception>> retryableExceptions;

    private RetryPolicy(Builder builder) {
        this.maxAttempts = builder.maxAttempts;
        this.initialDelay = builder.initialDelay;
        this.maxDelay = builder.maxDelay;
        this.multiplier = builder.multiplier;
        this.jitterFactor = builder.jitterFactor;
        this.retryPredicate = builder.retryPredicate;
        this.retryableExceptions = builder.retryableExceptions;
    }

    /**
     * Execute with retry
     */
    public <T> T execute(Supplier<T> operation) throws RetryExhaustedException {
        Exception lastException = null;
        int attempt = 0;

        while (attempt < maxAttempts) {
            try {
                return operation.get();

            } catch (Exception e) {
                lastException = e;
                attempt++;

                if (!shouldRetry(e, attempt)) {
                    throw new RetryExhaustedException("Non-retryable exception", e);
                }

                if (attempt < maxAttempts) {
                    Duration delay = calculateDelay(attempt);
                    log.debug("Retry attempt {}/{} after {}ms", attempt, maxAttempts, delay.toMillis());
                    sleep(delay);
                }
            }
        }

        throw new RetryExhaustedException(
                String.format("Exhausted %d retry attempts", maxAttempts),
                lastException
        );
    }

    /**
     * Execute runnable with retry
     */
    public void execute(Runnable operation) throws RetryExhaustedException {
        execute(() -> {
            operation.run();
            return null;
        });
    }

    /**
     * Calculate delay with exponential backoff and jitter
     */
    Duration calculateDelay(int attempt) {
        // Exponential backoff: initial * multiplier^(attempt-1)
        double exponentialDelay = initialDelay.toMillis() * Math.pow(multiplier, attempt - 1);

        // Cap at max delay
        long cappedDelay = Math.min((long) exponentialDelay, maxDelay.toMillis());

        // Add jitter: random value between [-jitter%, +jitter%]
        if (jitterFactor > 0) {
            double jitter = cappedDelay * jitterFactor;
            long jitterOffset = (long) (ThreadLocalRandom.current().nextDouble(-jitter, jitter));
            cappedDelay = Math.max(1, cappedDelay + jitterOffset);
        }

        return Duration.ofMillis(cappedDelay);
    }

    private boolean shouldRetry(Exception e, int attempt) {
        if (attempt >= maxAttempts) {
            return false;
        }

        // Check custom predicate first
        if (retryPredicate != null) {
            return retryPredicate.test(e);
        }

        // Check exception types
        if (!retryableExceptions.isEmpty()) {
            return retryableExceptions.stream()
                    .anyMatch(clazz -> clazz.isInstance(e));
        }

        // Default: retry all exceptions
        return true;
    }

    private void sleep(Duration duration) {
        // Use LockSupport for Virtual Thread compatibility
        // Use duration.toNanos() directly to avoid precision loss
        LockSupport.parkNanos(duration.toNanos());
    }

    /**
     * Create default retry policy
     */
    public static RetryPolicy defaults() {
        return builder().build();
    }

    /**
     * Create builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for RetryPolicy
     */
    public static class Builder {
        private int maxAttempts = 3;
        private Duration initialDelay = Duration.ofMillis(100);
        private Duration maxDelay = Duration.ofSeconds(30);
        private double multiplier = 2.0;
        private double jitterFactor = 0.25; // ±25%
        private Predicate<Exception> retryPredicate;
        private Set<Class<? extends Exception>> retryableExceptions = Set.of();

        public Builder maxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
            return this;
        }

        public Builder initialDelay(Duration initialDelay) {
            this.initialDelay = initialDelay;
            return this;
        }

        public Builder maxDelay(Duration maxDelay) {
            this.maxDelay = maxDelay;
            return this;
        }

        public Builder multiplier(double multiplier) {
            this.multiplier = multiplier;
            return this;
        }

        public Builder jitterFactor(double jitterFactor) {
            this.jitterFactor = jitterFactor;
            return this;
        }

        public Builder retryOn(Predicate<Exception> predicate) {
            this.retryPredicate = predicate;
            return this;
        }

        @SafeVarargs
        public final Builder retryOnExceptions(Class<? extends Exception>... exceptions) {
            this.retryableExceptions = Set.of(exceptions);
            return this;
        }

        /**
         * No jitter (for testing)
         */
        public Builder noJitter() {
            this.jitterFactor = 0;
            return this;
        }

        /**
         * Fixed delay (no exponential backoff)
         */
        public Builder fixedDelay(Duration delay) {
            this.initialDelay = delay;
            this.multiplier = 1.0;
            return this;
        }

        public RetryPolicy build() {
            return new RetryPolicy(this);
        }
    }

    /**
     * Exception thrown when retries are exhausted
     */
    public static class RetryExhaustedException extends RuntimeException {
        public RetryExhaustedException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
