package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.errors.AuthenticationException;
import org.apache.kafka.common.errors.AuthorizationException;
import org.apache.kafka.common.errors.InvalidTopicException;
import org.apache.kafka.common.errors.RecordTooLargeException;
import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.errors.TimeoutException;
import org.apache.kafka.common.errors.UnknownTopicOrPartitionException;
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
                KafkaSendException wrappedException = handleKafkaException(topic, data.length, exception);
                future.completeExceptionally(wrappedException);
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

    /**
     * Handle Kafka exceptions with detailed error categorization and logging.
     *
     * <p>Error categories:</p>
     * <ul>
     *   <li><strong>Authentication/Authorization:</strong> Credential or permission issues - requires config fix</li>
     *   <li><strong>Network/Timeout:</strong> Transient failures - may be retried</li>
     *   <li><strong>Data:</strong> Record too large or serialization issues - requires payload adjustment</li>
     *   <li><strong>Topic:</strong> Invalid topic or topic doesn't exist - requires config fix</li>
     * </ul>
     *
     * @param topic the target topic
     * @param dataSize the size of the data being sent
     * @param exception the original Kafka exception
     * @return a categorized KafkaSendException with detailed message
     */
    private KafkaSendException handleKafkaException(String topic, int dataSize, Exception exception) {
        String errorCategory;
        String errorMessage;
        boolean retryable;

        if (exception instanceof AuthenticationException) {
            errorCategory = "AUTHENTICATION";
            errorMessage = String.format(
                    "Kafka authentication failed for topic '%s'. Check SASL/SSL credentials and configuration. " +
                    "Security protocol: %s", topic, config.getKafkaSecurityProtocol());
            retryable = false;
            log.error("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage());

        } else if (exception instanceof AuthorizationException) {
            errorCategory = "AUTHORIZATION";
            errorMessage = String.format(
                    "Not authorized to send to topic '%s'. Check ACLs and permissions.", topic);
            retryable = false;
            log.error("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage());

        } else if (exception instanceof TimeoutException) {
            errorCategory = "TIMEOUT";
            errorMessage = String.format(
                    "Timeout sending to topic '%s' (bootstrap: %s). Kafka broker may be unavailable or overloaded.",
                    topic, config.getKafkaBootstrapServers());
            retryable = true;
            log.warn("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage());

        } else if (exception instanceof RecordTooLargeException) {
            errorCategory = "RECORD_TOO_LARGE";
            errorMessage = String.format(
                    "Record size %d bytes exceeds broker limit for topic '%s'. " +
                    "Increase broker's message.max.bytes or reduce payload size.", dataSize, topic);
            retryable = false;
            log.error("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage());

        } else if (exception instanceof SerializationException) {
            errorCategory = "SERIALIZATION";
            errorMessage = String.format(
                    "Failed to serialize record for topic '%s'. Check data format.", topic);
            retryable = false;
            log.error("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage());

        } else if (exception instanceof InvalidTopicException) {
            errorCategory = "INVALID_TOPIC";
            errorMessage = String.format(
                    "Invalid topic name '%s'. Topic names must match Kafka naming rules.", topic);
            retryable = false;
            log.error("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage());

        } else if (exception instanceof UnknownTopicOrPartitionException) {
            errorCategory = "UNKNOWN_TOPIC";
            errorMessage = String.format(
                    "Topic '%s' does not exist. Create the topic or enable auto.create.topics.enable on broker.", topic);
            retryable = false;
            log.error("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage());

        } else if (exception.getCause() instanceof java.net.ConnectException ||
                   exception.getCause() instanceof java.net.UnknownHostException) {
            errorCategory = "NETWORK";
            errorMessage = String.format(
                    "Cannot connect to Kafka broker at '%s'. Check network connectivity and broker availability.",
                    config.getKafkaBootstrapServers());
            retryable = true;
            log.warn("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage());

        } else {
            errorCategory = "UNKNOWN";
            errorMessage = String.format(
                    "Unexpected error sending to topic '%s': %s", topic, exception.getClass().getSimpleName());
            retryable = true;
            log.error("[{}] {}: {}", errorCategory, errorMessage, exception.getMessage(), exception);
        }

        return new KafkaSendException(errorCategory, errorMessage, retryable, exception);
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
     *
     * <p>Contains categorized error information for better error handling.</p>
     */
    public static class KafkaSendException extends RuntimeException {

        private final String errorCategory;
        private final boolean retryable;

        public KafkaSendException(String message, Throwable cause) {
            super(message, cause);
            this.errorCategory = "UNKNOWN";
            this.retryable = true;
        }

        public KafkaSendException(String category, String message, boolean retryable, Throwable cause) {
            super(message, cause);
            this.errorCategory = category;
            this.retryable = retryable;
        }

        /**
         * Get the error category (e.g., AUTHENTICATION, NETWORK, TIMEOUT).
         */
        public String getErrorCategory() {
            return errorCategory;
        }

        /**
         * Check if this error is potentially retryable.
         *
         * <p>Non-retryable errors include:</p>
         * <ul>
         *   <li>Authentication/Authorization failures</li>
         *   <li>Invalid topic configuration</li>
         *   <li>Record too large</li>
         *   <li>Serialization errors</li>
         * </ul>
         *
         * <p>Retryable errors include:</p>
         * <ul>
         *   <li>Network connectivity issues</li>
         *   <li>Timeouts</li>
         *   <li>Broker unavailability</li>
         * </ul>
         */
        public boolean isRetryable() {
            return retryable;
        }

        @Override
        public String toString() {
            return String.format("KafkaSendException[category=%s, retryable=%s]: %s",
                    errorCategory, retryable, getMessage());
        }
    }
}
