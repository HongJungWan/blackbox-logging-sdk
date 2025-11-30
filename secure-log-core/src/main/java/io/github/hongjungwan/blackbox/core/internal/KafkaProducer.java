package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;

import java.time.Duration;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * High-performance Kafka producer for log shipping.
 * Uses async sending with callbacks for non-blocking operation.
 */
@Slf4j
public class KafkaProducer implements AutoCloseable {

    private final org.apache.kafka.clients.producer.KafkaProducer<String, byte[]> producer;
    private final SecureLogConfig config;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicLong sentCount = new AtomicLong(0);
    private final AtomicLong errorCount = new AtomicLong(0);

    public KafkaProducer(SecureLogConfig config) {
        this.config = config;
        this.producer = createProducer(config);
        log.info("Kafka producer initialized: bootstrap.servers={}, topic={}",
                config.getKafkaBootstrapServers(), config.getKafkaTopic());
    }

    private org.apache.kafka.clients.producer.KafkaProducer<String, byte[]> createProducer(SecureLogConfig config) {
        Properties props = new Properties();

        // Required settings
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, config.getKafkaBootstrapServers());
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class.getName());

        // Reliability settings
        props.put(ProducerConfig.ACKS_CONFIG, config.getKafkaAcks());
        props.put(ProducerConfig.RETRIES_CONFIG, config.getKafkaRetries());
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "all".equals(config.getKafkaAcks()));

        // Performance tuning
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, config.getKafkaBatchSize());
        props.put(ProducerConfig.LINGER_MS_CONFIG, config.getKafkaLingerMs());
        props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, config.getKafkaCompressionType());
        props.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, config.getKafkaMaxBlockMs());

        // Buffer memory for batching
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432); // 32MB

        // Security protocol
        props.put("security.protocol", config.getKafkaSecurityProtocol());

        return new org.apache.kafka.clients.producer.KafkaProducer<>(props);
    }

    /**
     * Send data to the default topic asynchronously.
     *
     * @param data the serialized log data
     * @return CompletableFuture that completes when send is acknowledged
     */
    public CompletableFuture<RecordMetadata> send(byte[] data) {
        return send(config.getKafkaTopic(), data);
    }

    /**
     * Send data to a specific topic asynchronously.
     *
     * @param topic the Kafka topic
     * @param data  the serialized log data
     * @return CompletableFuture that completes when send is acknowledged
     */
    public CompletableFuture<RecordMetadata> send(String topic, byte[] data) {
        if (closed.get()) {
            CompletableFuture<RecordMetadata> future = new CompletableFuture<>();
            future.completeExceptionally(new IllegalStateException("Producer is closed"));
            return future;
        }

        CompletableFuture<RecordMetadata> future = new CompletableFuture<>();
        ProducerRecord<String, byte[]> record = new ProducerRecord<>(topic, data);

        producer.send(record, (metadata, exception) -> {
            if (exception != null) {
                errorCount.incrementAndGet();
                log.error("Failed to send log to Kafka topic {}: {}", topic, exception.getMessage());
                future.completeExceptionally(new KafkaSendException("Send failed", exception));
            } else {
                sentCount.incrementAndGet();
                if (log.isDebugEnabled()) {
                    log.debug("Sent {} bytes to {}-{} at offset {}",
                            data.length, metadata.topic(), metadata.partition(), metadata.offset());
                }
                future.complete(metadata);
            }
        });

        return future;
    }

    /**
     * Send data synchronously (blocking).
     * Use sparingly - prefer async send() for better performance.
     *
     * @param topic the Kafka topic
     * @param data  the serialized log data
     * @throws KafkaSendException if send fails
     */
    public void sendSync(String topic, byte[] data) {
        try {
            send(topic, data).join();
        } catch (Exception e) {
            throw new KafkaSendException("Synchronous send failed", e);
        }
    }

    /**
     * Flush any buffered records to Kafka.
     */
    public void flush() {
        if (!closed.get()) {
            producer.flush();
        }
    }

    /**
     * Get the total number of successfully sent messages.
     */
    public long getSentCount() {
        return sentCount.get();
    }

    /**
     * Get the total number of failed send attempts.
     */
    public long getErrorCount() {
        return errorCount.get();
    }

    /**
     * Check if the producer is closed.
     */
    public boolean isClosed() {
        return closed.get();
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            log.info("Closing Kafka producer (sent={}, errors={})", sentCount.get(), errorCount.get());
            try {
                producer.flush();
                producer.close(Duration.ofSeconds(5));
                log.info("Kafka producer closed successfully");
            } catch (Exception e) {
                log.warn("Error closing Kafka producer: {}", e.getMessage());
            }
        }
    }

    /**
     * Exception thrown when Kafka send fails.
     */
    public static class KafkaSendException extends RuntimeException {
        public KafkaSendException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
