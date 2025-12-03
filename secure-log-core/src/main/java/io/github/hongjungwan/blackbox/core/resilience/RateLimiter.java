package io.github.hongjungwan.blackbox.core.resilience;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;

/**
 * FEAT-11: Rate Limiter (Token Bucket Algorithm)
 *
 * High-performance rate limiter using token bucket algorithm.
 * Virtual Thread compatible (uses ReentrantLock).
 *
 * Features:
 * - Configurable rate and burst capacity
 * - Non-blocking and blocking modes
 * - Fair acquisition (optional)
 * - Metrics collection
 *
 * Based on: Guava RateLimiter, Resilience4j RateLimiter
 */
public final class RateLimiter {

    private final String name;
    private final long maxTokens;
    private final long refillRate; // tokens per second
    private final Duration refillPeriod;

    private final AtomicLong availableTokens;
    private final AtomicLong lastRefillTime;
    private final ReentrantLock refillLock = new ReentrantLock();

    // Metrics
    private final AtomicLong acquiredCount = new AtomicLong();
    private final AtomicLong rejectedCount = new AtomicLong();
    private final AtomicLong waitTimeNanos = new AtomicLong();

    private RateLimiter(Builder builder) {
        this.name = builder.name;
        this.maxTokens = builder.maxTokens;
        this.refillRate = builder.refillRate;
        this.refillPeriod = Duration.ofNanos(TimeUnit.SECONDS.toNanos(1) / refillRate);

        this.availableTokens = new AtomicLong(builder.initialTokens);
        this.lastRefillTime = new AtomicLong(System.nanoTime());
    }

    /**
     * Try to acquire a permit without waiting
     */
    public boolean tryAcquire() {
        return tryAcquire(1);
    }

    /**
     * Try to acquire multiple permits without waiting
     */
    public boolean tryAcquire(int permits) {
        refillTokens();

        long current;
        do {
            current = availableTokens.get();
            if (current < permits) {
                rejectedCount.incrementAndGet();
                return false;
            }
        } while (!availableTokens.compareAndSet(current, current - permits));

        acquiredCount.addAndGet(permits);
        return true;
    }

    /**
     * Acquire permit, waiting if necessary
     */
    public void acquire() {
        acquire(1);
    }

    /**
     * Acquire multiple permits, waiting if necessary
     */
    public void acquire(int permits) {
        long startTime = System.nanoTime();

        while (!tryAcquire(permits)) {
            // Wait for next refill
            LockSupport.parkNanos(refillPeriod.toNanos());
        }

        waitTimeNanos.addAndGet(System.nanoTime() - startTime);
    }

    /**
     * Try to acquire within timeout
     */
    public boolean tryAcquire(int permits, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        long startTime = System.nanoTime();

        while (!tryAcquire(permits)) {
            if (System.nanoTime() >= deadline) {
                return false;
            }
            // Wait for next refill or timeout
            long waitTime = Math.min(
                    refillPeriod.toNanos(),
                    deadline - System.nanoTime()
            );
            if (waitTime > 0) {
                LockSupport.parkNanos(waitTime);
            }
        }

        waitTimeNanos.addAndGet(System.nanoTime() - startTime);
        return true;
    }

    /**
     * Refill tokens based on elapsed time.
     *
     * FIX P0 #3: Prevent integer overflow in tokensToAdd calculation.
     * Previously, (elapsedNanos * refillRate) could overflow Long.MAX_VALUE
     * when elapsedNanos is large (e.g., after system pause) and refillRate is high.
     * Fix: Divide first, then multiply for the remainder to maintain precision.
     */
    private void refillTokens() {
        long now = System.nanoTime();
        long lastRefill = lastRefillTime.get();
        long elapsedNanos = now - lastRefill;

        // Calculate tokens to add with overflow protection
        long tokensToAdd = calculateTokensToAdd(elapsedNanos);

        if (tokensToAdd > 0) {
            // Use lock for atomic update of both values
            if (refillLock.tryLock()) {
                try {
                    // Recheck after acquiring lock
                    lastRefill = lastRefillTime.get();
                    elapsedNanos = now - lastRefill;
                    tokensToAdd = calculateTokensToAdd(elapsedNanos);

                    if (tokensToAdd > 0) {
                        long newTokens = Math.min(maxTokens, availableTokens.get() + tokensToAdd);
                        availableTokens.set(newTokens);
                        lastRefillTime.set(now);
                    }
                } finally {
                    refillLock.unlock();
                }
            }
        }
    }

    /**
     * Calculate tokens to add from elapsed nanoseconds with overflow protection.
     * FIX P0 #3: Reorder calculation to divide first, preventing overflow.
     */
    private long calculateTokensToAdd(long elapsedNanos) {
        long nanosPerSecond = TimeUnit.SECONDS.toNanos(1);
        // Divide first to prevent overflow
        long fullSeconds = elapsedNanos / nanosPerSecond;
        long tokensFromFullSeconds = fullSeconds * refillRate;

        // Calculate remaining nanos precision without overflow
        long remainingNanos = elapsedNanos % nanosPerSecond;
        long tokensFromRemainder = (remainingNanos * refillRate) / nanosPerSecond;

        return tokensFromFullSeconds + tokensFromRemainder;
    }

    /**
     * Get current available tokens
     */
    public long getAvailableTokens() {
        refillTokens();
        return availableTokens.get();
    }

    /**
     * Get metrics
     */
    public Metrics getMetrics() {
        return new Metrics(
                name,
                getAvailableTokens(),
                maxTokens,
                refillRate,
                acquiredCount.get(),
                rejectedCount.get(),
                Duration.ofNanos(waitTimeNanos.get())
        );
    }

    /**
     * Reset rate limiter to initial state
     */
    public void reset() {
        refillLock.lock();
        try {
            availableTokens.set(maxTokens);
            lastRefillTime.set(System.nanoTime());
            acquiredCount.set(0);
            rejectedCount.set(0);
            waitTimeNanos.set(0);
        } finally {
            refillLock.unlock();
        }
    }

    public String getName() { return name; }

    /**
     * Create builder
     */
    public static Builder builder(String name) {
        return new Builder(name);
    }

    /**
     * Create rate limiter with rate limit
     */
    public static RateLimiter create(String name, long permitsPerSecond) {
        return builder(name)
                .refillRate(permitsPerSecond)
                .maxTokens(permitsPerSecond)
                .build();
    }

    /**
     * Metrics record
     */
    public record Metrics(
            String name,
            long availableTokens,
            long maxTokens,
            long refillRate,
            long acquiredCount,
            long rejectedCount,
            Duration totalWaitTime
    ) {
        public double utilizationRate() {
            long total = acquiredCount + rejectedCount;
            return total > 0 ? (double) acquiredCount / total : 0;
        }
    }

    /**
     * Builder
     */
    public static class Builder {
        private final String name;
        private long maxTokens = 1000;
        private long refillRate = 100; // tokens per second
        private long initialTokens = -1; // -1 means use maxTokens

        public Builder(String name) {
            this.name = name;
        }

        public Builder maxTokens(long maxTokens) {
            this.maxTokens = maxTokens;
            return this;
        }

        public Builder refillRate(long tokensPerSecond) {
            this.refillRate = tokensPerSecond;
            return this;
        }

        public Builder initialTokens(long tokens) {
            this.initialTokens = tokens;
            return this;
        }

        /**
         * Start empty (for gradual ramp-up)
         */
        public Builder startEmpty() {
            this.initialTokens = 0;
            return this;
        }

        /**
         * Configure for log rate (logs per second)
         */
        public Builder logsPerSecond(long rate) {
            this.refillRate = rate;
            this.maxTokens = rate * 2; // Allow burst of 2x rate
            return this;
        }

        public RateLimiter build() {
            if (initialTokens < 0) {
                initialTokens = maxTokens;
            }
            return new RateLimiter(this);
        }
    }
}
