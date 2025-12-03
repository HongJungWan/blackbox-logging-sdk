package io.github.hongjungwan.blackbox.core.internal;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * FEAT-12: SDK Metrics & Observability (Datadog/Sentry Pattern)
 *
 * Comprehensive metrics collection for SDK operations.
 * Thread-safe, lock-free counters using LongAdder.
 *
 * Features:
 * - Throughput metrics (logs/sec)
 * - Latency histograms
 * - Error rates
 * - Pipeline stage metrics
 * - Resource utilization
 *
 * Based on:
 * - Datadog APM metrics
 * - Sentry SDK telemetry
 * - Micrometer patterns
 */
public final class SdkMetrics {

    private static final SdkMetrics INSTANCE = new SdkMetrics();

    private final Instant startTime = Instant.now();

    // Counters (thread-safe, lock-free)
    private final LongAdder logsProcessed = new LongAdder();
    private final LongAdder logsDropped = new LongAdder();
    private final LongAdder logsFailed = new LongAdder();
    private final LongAdder bytesProcessed = new LongAdder();
    private final LongAdder bytesSent = new LongAdder();

    // Per-level counters
    private final Map<String, LongAdder> levelCounters = new ConcurrentHashMap<>();

    // Latency tracking
    private final LatencyHistogram processingLatency = new LatencyHistogram("processing");
    private final LatencyHistogram transportLatency = new LatencyHistogram("transport");
    private final LatencyHistogram encryptionLatency = new LatencyHistogram("encryption");
    private final LatencyHistogram maskingLatency = new LatencyHistogram("masking");

    // Pipeline stage metrics
    private final Map<String, StageMetrics> stageMetrics = new ConcurrentHashMap<>();

    // Error tracking
    private final Map<String, LongAdder> errorCounters = new ConcurrentHashMap<>();

    // Circuit breaker metrics
    private final AtomicLong circuitBreakerOpened = new AtomicLong();
    private final AtomicLong circuitBreakerClosed = new AtomicLong();
    private final AtomicLong fallbackActivations = new AtomicLong();

    private SdkMetrics() {
        // Initialize stage metrics
        for (String stage : new String[]{"dedup", "mask", "integrity", "encrypt", "serialize", "transport"}) {
            stageMetrics.put(stage, new StageMetrics(stage));
        }
    }

    public static SdkMetrics getInstance() {
        return INSTANCE;
    }

    // ========== Recording Methods ==========

    public void recordLogProcessed(String level, long bytes) {
        logsProcessed.increment();
        bytesProcessed.add(bytes);
        levelCounters.computeIfAbsent(level, k -> new LongAdder()).increment();
    }

    public void recordLogDropped(String reason) {
        logsDropped.increment();
        errorCounters.computeIfAbsent("dropped:" + reason, k -> new LongAdder()).increment();
    }

    public void recordLogFailed(String stage, Throwable error) {
        logsFailed.increment();
        String errorKey = stage + ":" + error.getClass().getSimpleName();
        errorCounters.computeIfAbsent(errorKey, k -> new LongAdder()).increment();
    }

    public void recordBytesSent(long bytes) {
        bytesSent.add(bytes);
    }

    public void recordProcessingLatency(long nanos) {
        processingLatency.record(nanos);
    }

    public void recordTransportLatency(long nanos) {
        transportLatency.record(nanos);
    }

    public void recordEncryptionLatency(long nanos) {
        encryptionLatency.record(nanos);
    }

    public void recordMaskingLatency(long nanos) {
        maskingLatency.record(nanos);
    }

    public void recordStage(String stage, long nanos, boolean success) {
        StageMetrics metrics = stageMetrics.get(stage);
        if (metrics != null) {
            metrics.record(nanos, success);
        }
    }

    public void recordCircuitBreakerOpened() {
        circuitBreakerOpened.incrementAndGet();
    }

    public void recordCircuitBreakerClosed() {
        circuitBreakerClosed.incrementAndGet();
    }

    public void recordFallbackActivation() {
        fallbackActivations.incrementAndGet();
    }

    // ========== Timer Utilities ==========

    /**
     * Start a timer for measuring operation duration
     */
    public Timer startTimer() {
        return new Timer();
    }

    /**
     * Timer for measuring operation duration
     */
    public static class Timer {
        private final long startNanos = System.nanoTime();

        public long elapsedNanos() {
            return System.nanoTime() - startNanos;
        }

        public Duration elapsed() {
            return Duration.ofNanos(elapsedNanos());
        }
    }

    // ========== Snapshot Methods ==========

    /**
     * Get complete metrics snapshot
     */
    public Snapshot getSnapshot() {
        return new Snapshot(
                Instant.now(),
                startTime,
                logsProcessed.sum(),
                logsDropped.sum(),
                logsFailed.sum(),
                bytesProcessed.sum(),
                bytesSent.sum(),
                Map.copyOf(levelCounters),
                processingLatency.getStats(),
                transportLatency.getStats(),
                encryptionLatency.getStats(),
                maskingLatency.getStats(),
                stageMetrics.entrySet().stream()
                        .collect(java.util.stream.Collectors.toMap(
                                Map.Entry::getKey,
                                e -> e.getValue().getStats()
                        )),
                Map.copyOf(errorCounters),
                circuitBreakerOpened.get(),
                circuitBreakerClosed.get(),
                fallbackActivations.get()
        );
    }

    /**
     * Get throughput (logs per second)
     */
    public double getThroughput() {
        Duration uptime = Duration.between(startTime, Instant.now());
        long seconds = Math.max(1, uptime.getSeconds());
        return (double) logsProcessed.sum() / seconds;
    }

    /**
     * Get error rate (0.0 - 1.0)
     */
    public double getErrorRate() {
        long total = logsProcessed.sum() + logsFailed.sum();
        if (total == 0) return 0;
        return (double) logsFailed.sum() / total;
    }

    /**
     * Reset all metrics
     */
    public void reset() {
        logsProcessed.reset();
        logsDropped.reset();
        logsFailed.reset();
        bytesProcessed.reset();
        bytesSent.reset();
        levelCounters.values().forEach(LongAdder::reset);
        processingLatency.reset();
        transportLatency.reset();
        encryptionLatency.reset();
        maskingLatency.reset();
        stageMetrics.values().forEach(StageMetrics::reset);
        errorCounters.values().forEach(LongAdder::reset);
        circuitBreakerOpened.set(0);
        circuitBreakerClosed.set(0);
        fallbackActivations.set(0);
    }

    /**
     * Reset all metrics for testing purposes.
     * This method clears all counters, histograms, and maps to provide a clean state.
     *
     * @deprecated Use reset() instead. This method exists only for backward compatibility.
     */
    @Deprecated
    public void resetForTesting() {
        reset();
        // Also clear the maps to ensure completely fresh state for tests
        levelCounters.clear();
        errorCounters.clear();
    }

    // ========== Inner Classes ==========

    /**
     * Latency histogram for percentile calculations
     */
    public static class LatencyHistogram {
        private final String name;
        private final LongAdder count = new LongAdder();
        private final LongAdder totalNanos = new LongAdder();
        private final AtomicLong minNanos = new AtomicLong(Long.MAX_VALUE);
        private final AtomicLong maxNanos = new AtomicLong(0);

        // Bucket boundaries in nanoseconds (p50, p90, p99, p999)
        private final long[] bucketBoundaries = {
                1_000_000,      // 1ms
                5_000_000,      // 5ms
                10_000_000,     // 10ms
                50_000_000,     // 50ms
                100_000_000,    // 100ms
                500_000_000,    // 500ms
                1_000_000_000   // 1s
        };
        private final LongAdder[] buckets = new LongAdder[bucketBoundaries.length + 1];

        public LatencyHistogram(String name) {
            this.name = name;
            for (int i = 0; i < buckets.length; i++) {
                buckets[i] = new LongAdder();
            }
        }

        public void record(long nanos) {
            count.increment();
            totalNanos.add(nanos);

            // Update min/max
            updateMin(nanos);
            updateMax(nanos);

            // Update bucket
            int bucket = findBucket(nanos);
            buckets[bucket].increment();
        }

        private void updateMin(long nanos) {
            long current;
            do {
                current = minNanos.get();
                if (nanos >= current) return;
            } while (!minNanos.compareAndSet(current, nanos));
        }

        private void updateMax(long nanos) {
            long current;
            do {
                current = maxNanos.get();
                if (nanos <= current) return;
            } while (!maxNanos.compareAndSet(current, nanos));
        }

        private int findBucket(long nanos) {
            for (int i = 0; i < bucketBoundaries.length; i++) {
                if (nanos <= bucketBoundaries[i]) {
                    return i;
                }
            }
            return bucketBoundaries.length;
        }

        public LatencyStats getStats() {
            long c = count.sum();
            if (c == 0) {
                return new LatencyStats(name, 0, 0, 0, 0, 0);
            }

            return new LatencyStats(
                    name,
                    c,
                    (double) totalNanos.sum() / c / 1_000_000, // avg in ms
                    (double) minNanos.get() / 1_000_000,       // min in ms
                    (double) maxNanos.get() / 1_000_000,       // max in ms
                    estimatePercentile(0.99)                    // p99 in ms
            );
        }

        private double estimatePercentile(double percentile) {
            long total = count.sum();
            if (total == 0) return 0;

            long target = (long) (total * percentile);
            long cumulative = 0;

            for (int i = 0; i < buckets.length; i++) {
                cumulative += buckets[i].sum();
                if (cumulative >= target) {
                    if (i < bucketBoundaries.length) {
                        return (double) bucketBoundaries[i] / 1_000_000;
                    } else {
                        return (double) maxNanos.get() / 1_000_000;
                    }
                }
            }
            return (double) maxNanos.get() / 1_000_000;
        }

        public void reset() {
            count.reset();
            totalNanos.reset();
            minNanos.set(Long.MAX_VALUE);
            maxNanos.set(0);
            for (LongAdder bucket : buckets) {
                bucket.reset();
            }
        }
    }

    /**
     * Latency statistics
     */
    public record LatencyStats(
            String name,
            long count,
            double avgMs,
            double minMs,
            double maxMs,
            double p99Ms
    ) {}

    /**
     * Per-stage metrics
     */
    public static class StageMetrics {
        private final String name;
        private final LongAdder successCount = new LongAdder();
        private final LongAdder failureCount = new LongAdder();
        private final LatencyHistogram latency;

        public StageMetrics(String name) {
            this.name = name;
            this.latency = new LatencyHistogram(name);
        }

        public void record(long nanos, boolean success) {
            if (success) {
                successCount.increment();
            } else {
                failureCount.increment();
            }
            latency.record(nanos);
        }

        public StageStats getStats() {
            long success = successCount.sum();
            long failure = failureCount.sum();
            long total = success + failure;
            double successRate = total > 0 ? (double) success / total : 1.0;

            return new StageStats(
                    name,
                    success,
                    failure,
                    successRate,
                    latency.getStats()
            );
        }

        public void reset() {
            successCount.reset();
            failureCount.reset();
            latency.reset();
        }
    }

    /**
     * Stage statistics
     */
    public record StageStats(
            String name,
            long successCount,
            long failureCount,
            double successRate,
            LatencyStats latency
    ) {}

    /**
     * Complete metrics snapshot
     */
    public record Snapshot(
            Instant snapshotTime,
            Instant startTime,
            long logsProcessed,
            long logsDropped,
            long logsFailed,
            long bytesProcessed,
            long bytesSent,
            Map<String, LongAdder> levelCounts,
            LatencyStats processingLatency,
            LatencyStats transportLatency,
            LatencyStats encryptionLatency,
            LatencyStats maskingLatency,
            Map<String, StageStats> stageStats,
            Map<String, LongAdder> errorCounts,
            long circuitBreakerOpenedCount,
            long circuitBreakerClosedCount,
            long fallbackActivationCount
    ) {
        public Duration uptime() {
            return Duration.between(startTime, snapshotTime);
        }

        public double throughputPerSecond() {
            long seconds = Math.max(1, uptime().getSeconds());
            return (double) logsProcessed / seconds;
        }

        public double errorRate() {
            long total = logsProcessed + logsFailed;
            if (total == 0) return 0;
            return (double) logsFailed / total;
        }
    }
}
