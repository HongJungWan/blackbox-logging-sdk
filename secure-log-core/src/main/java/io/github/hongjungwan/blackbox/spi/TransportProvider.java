package io.github.hongjungwan.blackbox.spi;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * SPI for log transport backends.
 *
 * <p>Implement this interface to support different log destinations
 * (Kafka, Elasticsearch, CloudWatch, etc.).</p>
 *
 * <h2>Built-in Transports:</h2>
 * <ul>
 *   <li>KafkaTransport: Apache Kafka with Zstd compression</li>
 *   <li>FallbackTransport: Local disk with secure deletion</li>
 * </ul>
 *
 * <h2>Implementation Example:</h2>
 * <pre>{@code
 * public class ElasticsearchTransport implements TransportProvider {
 *     private final RestHighLevelClient client;
 *
 *     @Override
 *     public CompletableFuture<Void> send(LogEntry entry) {
 *         IndexRequest request = new IndexRequest("logs")
 *                 .source(serialize(entry));
 *         return CompletableFuture.runAsync(() ->
 *             client.index(request, RequestOptions.DEFAULT));
 *     }
 * }
 * }</pre>
 *
 * @since 8.0.0
 */
public interface TransportProvider {

    /**
     * Get the transport name.
     */
    String getName();

    /**
     * Send a single log entry asynchronously.
     *
     * @param entry The log entry to send
     * @return A future that completes when the send is done
     */
    CompletableFuture<Void> send(LogEntry entry);

    /**
     * Send a batch of log entries.
     *
     * @param entries The log entries to send
     * @return A future that completes when all entries are sent
     */
    default CompletableFuture<Void> sendBatch(List<LogEntry> entries) {
        CompletableFuture<?>[] futures = entries.stream()
                .map(this::send)
                .toArray(CompletableFuture[]::new);
        return CompletableFuture.allOf(futures);
    }

    /**
     * Check if this transport is healthy.
     *
     * @return true if transport is ready
     */
    boolean isHealthy();

    /**
     * Flush any pending entries.
     */
    void flush();

    /**
     * Shutdown the transport gracefully.
     */
    void close();

    /**
     * Get transport metrics.
     */
    default TransportMetrics getMetrics() {
        return TransportMetrics.EMPTY;
    }

    /**
     * Transport metrics interface.
     */
    interface TransportMetrics {
        long sentCount();
        long failedCount();
        long bytesWritten();
        double averageLatencyMs();

        TransportMetrics EMPTY = new TransportMetrics() {
            @Override public long sentCount() { return 0; }
            @Override public long failedCount() { return 0; }
            @Override public long bytesWritten() { return 0; }
            @Override public double averageLatencyMs() { return 0; }
        };
    }
}
