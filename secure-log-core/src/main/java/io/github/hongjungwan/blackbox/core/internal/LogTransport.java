package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 로그 전송 (Kafka primary + 파일 Fallback). 단순 Circuit Breaker 내장.
 */
@Slf4j
public class LogTransport {

    private final SecureLogConfig config;
    private final KafkaProducer kafkaProducer;
    private final LogSerializer serializer;
    private final Path fallbackDirectory;

    private final AtomicBoolean circuitOpen = new AtomicBoolean(false);
    private final AtomicInteger consecutiveFailures = new AtomicInteger(0);
    private static final int FAILURE_THRESHOLD = 3;

    public LogTransport(SecureLogConfig config, LogSerializer serializer) {
        this.config = config;
        this.serializer = serializer;
        this.kafkaProducer = initializeKafkaProducer();
        this.fallbackDirectory = Paths.get(config.getFallbackDirectory());

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

    public void send(byte[] data) {
        if (circuitOpen.get()) {
            sendToFallback(data);
            return;
        }

        try {
            if (kafkaProducer != null) {
                kafkaProducer.send(config.getKafkaTopic(), data);
                onSendSuccess();
            } else {
                sendToFallback(data);
            }
        } catch (Exception e) {
            log.warn("Failed to send to Kafka, using fallback", e);
            onSendFailure();
            sendToFallback(data);
        }
    }

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

    public void sendToFallback(LogEntry entry) {
        byte[] data = serializer.serialize(entry);
        sendToFallback(data);
    }

    private void onSendSuccess() {
        if (consecutiveFailures.get() > 0) {
            consecutiveFailures.set(0);
            if (circuitOpen.compareAndSet(true, false)) {
                log.info("Circuit breaker CLOSED - Kafka recovered");
            }
        }
    }

    private void onSendFailure() {
        int failures = consecutiveFailures.incrementAndGet();

        if (failures >= FAILURE_THRESHOLD) {
            if (circuitOpen.compareAndSet(false, true)) {
                log.warn("Circuit breaker OPEN - Switched to fallback mode after {} failures", FAILURE_THRESHOLD);
            }
        }
    }

    /** Fallback 로그 재전송 */
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
            kafkaProducer.send(config.getKafkaTopic(), data);
            secureDelete(file);

            log.info("Replayed and deleted fallback file: " + file);

        } catch (Exception e) {
            log.error("Failed to replay file: " + file, e);
        }
    }

    /** 안전 삭제 (덮어쓰기 후 삭제) */
    private void secureDelete(Path file) throws IOException {
        long fileSize = Files.size(file);
        final int BUFFER_SIZE = 8192;
        byte[] zeros = new byte[BUFFER_SIZE];

        try (var channel = Files.newByteChannel(file,
                StandardOpenOption.WRITE, StandardOpenOption.SYNC)) {
            long remaining = fileSize;
            while (remaining > 0) {
                int toWrite = (int) Math.min(remaining, BUFFER_SIZE);
                channel.write(java.nio.ByteBuffer.wrap(zeros, 0, toWrite));
                remaining -= toWrite;
            }
        }

        Files.delete(file);
    }

    public void close() {
        if (kafkaProducer != null) {
            kafkaProducer.close();
        }
    }
}
