package io.github.hongjungwan.blackbox.core.metrics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.StringWriter;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * FEAT-12: Metrics Exporter (Prometheus/JMX/JSON formats)
 *
 * Exports SDK metrics in various formats for observability integration.
 *
 * Supported formats:
 * - Prometheus text format
 * - JSON
 * - JMX (via MXBean registration)
 * - Custom exporters via SPI
 */
@Slf4j
public final class MetricsExporter {

    private final SdkMetrics metrics;
    private final ObjectMapper objectMapper;
    private ScheduledExecutorService scheduler;

    public MetricsExporter() {
        this(SdkMetrics.getInstance());
    }

    public MetricsExporter(SdkMetrics metrics) {
        this.metrics = metrics;
        this.objectMapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    /**
     * Export metrics in Prometheus text format
     */
    public String toPrometheus() {
        SdkMetrics.Snapshot snapshot = metrics.getSnapshot();
        StringBuilder sb = new StringBuilder();

        // Help and type declarations
        sb.append("# HELP secure_hr_logs_processed_total Total number of logs processed\n");
        sb.append("# TYPE secure_hr_logs_processed_total counter\n");
        sb.append(String.format("secure_hr_logs_processed_total %d\n", snapshot.logsProcessed()));

        sb.append("# HELP secure_hr_logs_dropped_total Total number of logs dropped\n");
        sb.append("# TYPE secure_hr_logs_dropped_total counter\n");
        sb.append(String.format("secure_hr_logs_dropped_total %d\n", snapshot.logsDropped()));

        sb.append("# HELP secure_hr_logs_failed_total Total number of logs failed\n");
        sb.append("# TYPE secure_hr_logs_failed_total counter\n");
        sb.append(String.format("secure_hr_logs_failed_total %d\n", snapshot.logsFailed()));

        sb.append("# HELP secure_hr_bytes_processed_total Total bytes processed\n");
        sb.append("# TYPE secure_hr_bytes_processed_total counter\n");
        sb.append(String.format("secure_hr_bytes_processed_total %d\n", snapshot.bytesProcessed()));

        sb.append("# HELP secure_hr_bytes_sent_total Total bytes sent\n");
        sb.append("# TYPE secure_hr_bytes_sent_total counter\n");
        sb.append(String.format("secure_hr_bytes_sent_total %d\n", snapshot.bytesSent()));

        // Throughput gauge
        sb.append("# HELP secure_hr_throughput_logs_per_second Current throughput\n");
        sb.append("# TYPE secure_hr_throughput_logs_per_second gauge\n");
        sb.append(String.format("secure_hr_throughput_logs_per_second %.2f\n", snapshot.throughputPerSecond()));

        // Error rate gauge
        sb.append("# HELP secure_hr_error_rate Current error rate\n");
        sb.append("# TYPE secure_hr_error_rate gauge\n");
        sb.append(String.format("secure_hr_error_rate %.4f\n", snapshot.errorRate()));

        // Latency histograms
        appendLatencyMetrics(sb, "processing", snapshot.processingLatency());
        appendLatencyMetrics(sb, "transport", snapshot.transportLatency());
        appendLatencyMetrics(sb, "encryption", snapshot.encryptionLatency());
        appendLatencyMetrics(sb, "masking", snapshot.maskingLatency());

        // Per-level counters
        sb.append("# HELP secure_hr_logs_by_level Logs processed by level\n");
        sb.append("# TYPE secure_hr_logs_by_level counter\n");
        snapshot.levelCounts().forEach((level, counter) ->
                sb.append(String.format("secure_hr_logs_by_level{level=\"%s\"} %d\n",
                        level, counter.sum())));

        // Circuit breaker metrics
        sb.append("# HELP secure_hr_circuit_breaker_opened_total Circuit breaker opened count\n");
        sb.append("# TYPE secure_hr_circuit_breaker_opened_total counter\n");
        sb.append(String.format("secure_hr_circuit_breaker_opened_total %d\n",
                snapshot.circuitBreakerOpenedCount()));

        sb.append("# HELP secure_hr_circuit_breaker_closed_total Circuit breaker closed count\n");
        sb.append("# TYPE secure_hr_circuit_breaker_closed_total counter\n");
        sb.append(String.format("secure_hr_circuit_breaker_closed_total %d\n",
                snapshot.circuitBreakerClosedCount()));

        sb.append("# HELP secure_hr_fallback_activations_total Fallback activations\n");
        sb.append("# TYPE secure_hr_fallback_activations_total counter\n");
        sb.append(String.format("secure_hr_fallback_activations_total %d\n",
                snapshot.fallbackActivationCount()));

        // Uptime
        sb.append("# HELP secure_hr_uptime_seconds SDK uptime in seconds\n");
        sb.append("# TYPE secure_hr_uptime_seconds gauge\n");
        sb.append(String.format("secure_hr_uptime_seconds %d\n", snapshot.uptime().getSeconds()));

        return sb.toString();
    }

    private void appendLatencyMetrics(StringBuilder sb, String name, SdkMetrics.LatencyStats stats) {
        String prefix = "secure_hr_" + name + "_latency";

        sb.append(String.format("# HELP %s_milliseconds %s latency in milliseconds\n", prefix, name));
        sb.append(String.format("# TYPE %s_milliseconds summary\n", prefix));
        sb.append(String.format("%s_milliseconds_count %d\n", prefix, stats.count()));
        sb.append(String.format("%s_milliseconds_avg %.2f\n", prefix, stats.avgMs()));
        sb.append(String.format("%s_milliseconds_min %.2f\n", prefix, stats.minMs()));
        sb.append(String.format("%s_milliseconds_max %.2f\n", prefix, stats.maxMs()));
        sb.append(String.format("%s_milliseconds{quantile=\"0.99\"} %.2f\n", prefix, stats.p99Ms()));
    }

    /**
     * Export metrics as JSON
     */
    public String toJson() {
        try {
            SdkMetrics.Snapshot snapshot = metrics.getSnapshot();
            Map<String, Object> json = new HashMap<>();

            json.put("timestamp", snapshot.snapshotTime().toString());
            json.put("uptime_seconds", snapshot.uptime().getSeconds());

            Map<String, Object> counters = new HashMap<>();
            counters.put("logs_processed", snapshot.logsProcessed());
            counters.put("logs_dropped", snapshot.logsDropped());
            counters.put("logs_failed", snapshot.logsFailed());
            counters.put("bytes_processed", snapshot.bytesProcessed());
            counters.put("bytes_sent", snapshot.bytesSent());
            json.put("counters", counters);

            Map<String, Object> rates = new HashMap<>();
            rates.put("throughput_per_second", snapshot.throughputPerSecond());
            rates.put("error_rate", snapshot.errorRate());
            json.put("rates", rates);

            Map<String, Object> latency = new HashMap<>();
            latency.put("processing", latencyToMap(snapshot.processingLatency()));
            latency.put("transport", latencyToMap(snapshot.transportLatency()));
            latency.put("encryption", latencyToMap(snapshot.encryptionLatency()));
            latency.put("masking", latencyToMap(snapshot.maskingLatency()));
            json.put("latency", latency);

            Map<String, Long> levels = new HashMap<>();
            snapshot.levelCounts().forEach((k, v) -> levels.put(k, v.sum()));
            json.put("logs_by_level", levels);

            Map<String, Object> circuitBreaker = new HashMap<>();
            circuitBreaker.put("opened_count", snapshot.circuitBreakerOpenedCount());
            circuitBreaker.put("closed_count", snapshot.circuitBreakerClosedCount());
            circuitBreaker.put("fallback_activations", snapshot.fallbackActivationCount());
            json.put("circuit_breaker", circuitBreaker);

            return objectMapper.writeValueAsString(json);

        } catch (Exception e) {
            log.error("Failed to export metrics as JSON", e);
            return "{}";
        }
    }

    private Map<String, Object> latencyToMap(SdkMetrics.LatencyStats stats) {
        Map<String, Object> map = new HashMap<>();
        map.put("count", stats.count());
        map.put("avg_ms", stats.avgMs());
        map.put("min_ms", stats.minMs());
        map.put("max_ms", stats.maxMs());
        map.put("p99_ms", stats.p99Ms());
        return map;
    }

    /**
     * Start periodic export
     */
    public void startPeriodicExport(Duration interval, Consumer<String> exporter) {
        if (scheduler != null) {
            throw new IllegalStateException("Periodic export already started");
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "secure-hr-metrics-exporter");
            t.setDaemon(true);
            return t;
        });

        scheduler.scheduleAtFixedRate(
                () -> {
                    try {
                        exporter.accept(toJson());
                    } catch (Exception e) {
                        log.error("Failed to export metrics", e);
                    }
                },
                interval.toMillis(),
                interval.toMillis(),
                TimeUnit.MILLISECONDS
        );

        log.info("Started periodic metrics export every {}ms", interval.toMillis());
    }

    /**
     * Stop periodic export
     */
    public void stopPeriodicExport() {
        if (scheduler != null) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            scheduler = null;
            log.info("Stopped periodic metrics export");
        }
    }

    /**
     * Log metrics at INFO level
     */
    public void logMetrics() {
        SdkMetrics.Snapshot snapshot = metrics.getSnapshot();
        log.info("SecureHR SDK Metrics: processed={}, dropped={}, failed={}, " +
                        "throughput={:.2f}/sec, errorRate={:.4f}%, " +
                        "avgLatency={:.2f}ms, p99Latency={:.2f}ms",
                snapshot.logsProcessed(),
                snapshot.logsDropped(),
                snapshot.logsFailed(),
                snapshot.throughputPerSecond(),
                snapshot.errorRate() * 100,
                snapshot.processingLatency().avgMs(),
                snapshot.processingLatency().p99Ms()
        );
    }
}
