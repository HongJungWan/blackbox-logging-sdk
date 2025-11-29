package io.github.hongjungwan.blackbox.core.transport;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.serialization.LogSerializer;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * FEAT-05: Log Transport with Circuit Breaker Fallback
 *
 * Primary: Send to Kafka
 * Fallback: Write to local encrypted file when Kafka is unavailable
 */
@Slf4j
public class LogTransport {

    private final SecureLogConfig config;
    private final KafkaProducer kafkaProducer;
    private final LogSerializer serializer;
    private final Path fallbackDirectory;

    // Circuit breaker state
    private final AtomicBoolean circuitOpen = new AtomicBoolean(false);
    private volatile int consecutiveFailures = 0;
    private static final int FAILURE_THRESHOLD = 3;

    public LogTransport(SecureLogConfig config, LogSerializer serializer) {
        this.config = config;
        this.serializer = serializer;
        this.kafkaProducer = initializeKafkaProducer();
        this.fallbackDirectory = Paths.get(config.getFallbackDirectory());

        // Ensure fallback directory exists
        try {
            Files.createDirectories(fallbackDirectory);
        } catch (IOException e) {
            log.error("Failed to create fallback directory: " + fallbackDirectory, e);
        }
    }

    private KafkaProducer initializeKafkaProducer() {
        if (config.getKafkaBootstrapServers() != null) {
            return new KafkaProducer(config);
        }
        return null;
    }

    /**
     * Send log data to Kafka (with fallback)
     */
    public void send(byte[] data) {
        // Check circuit breaker
        if (circuitOpen.get()) {
            sendToFallback(data);
            return;
        }

        // Try primary transport (Kafka)
        try {
            if (kafkaProducer != null) {
                kafkaProducer.send(config.getKafkaTopic(), data);
                onSendSuccess();
            } else {
                // No Kafka configured, use fallback
                sendToFallback(data);
            }

        } catch (Exception e) {
            log.warn("Failed to send to Kafka, using fallback", e);
            onSendFailure();
            sendToFallback(data);
        }
    }

    /**
     * Send to fallback file storage
     */
    public void sendToFallback(byte[] data) {
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS"));
            Path fallbackFile = fallbackDirectory.resolve("log-" + timestamp + ".zst");

            Files.write(fallbackFile, data, StandardOpenOption.CREATE, StandardOpenOption.APPEND);

            log.debug("Written to fallback: " + fallbackFile);

        } catch (IOException e) {
            log.error("Failed to write to fallback storage", e);
        }
    }

    /**
     * Send LogEntry to fallback (alternative signature)
     */
    public void sendToFallback(LogEntry entry) {
        byte[] data = serializer.serialize(entry);
        sendToFallback(data);
    }

    /**
     * Handle successful send - reset circuit breaker
     */
    private void onSendSuccess() {
        if (consecutiveFailures > 0) {
            consecutiveFailures = 0;
            if (circuitOpen.compareAndSet(true, false)) {
                log.info("Circuit breaker CLOSED - Kafka recovered");
            }
        }
    }

    /**
     * Handle send failure - open circuit breaker if threshold reached
     */
    private void onSendFailure() {
        consecutiveFailures++;

        if (consecutiveFailures >= FAILURE_THRESHOLD) {
            if (circuitOpen.compareAndSet(false, true)) {
                log.warn("Circuit breaker OPEN - Switched to fallback mode after {} failures", FAILURE_THRESHOLD);
            }
        }
    }

    /**
     * Replay logs from fallback when Kafka recovers
     */
    public void replayFallbackLogs() {
        if (kafkaProducer == null || circuitOpen.get()) {
            log.warn("Cannot replay - Kafka not available");
            return;
        }

        try {
            Files.list(fallbackDirectory)
                    .filter(path -> path.toString().endsWith(".zst"))
                    .sorted()
                    .forEach(this::replayFile);

        } catch (IOException e) {
            log.error("Failed to replay fallback logs", e);
        }
    }

    private void replayFile(Path file) {
        try {
            byte[] data = Files.readAllBytes(file);

            // Send to Kafka
            kafkaProducer.send(config.getKafkaTopic(), data);

            // Secure delete after successful replay
            secureDelete(file);

            log.info("Replayed and deleted fallback file: " + file);

        } catch (Exception e) {
            log.error("Failed to replay file: " + file, e);
        }
    }

    /**
     * Secure delete: overwrite then delete
     */
    private void secureDelete(Path file) throws IOException {
        // Overwrite with random data
        byte[] zeros = new byte[(int) Files.size(file)];
        Files.write(file, zeros, StandardOpenOption.WRITE);

        // Delete file
        Files.delete(file);
    }

    public void close() {
        if (kafkaProducer != null) {
            kafkaProducer.close();
        }
    }
}
