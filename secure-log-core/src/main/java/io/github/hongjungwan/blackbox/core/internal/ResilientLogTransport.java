package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.resilience.CircuitBreaker;
import io.github.hongjungwan.blackbox.core.resilience.RetryPolicy;
import io.github.hongjungwan.blackbox.core.resilience.RateLimiter;
import io.github.hongjungwan.blackbox.core.internal.SdkMetrics;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

/**
 * FEAT-11: Resilient Log Transport with Enhanced Reliability
 *
 * Improvements over base LogTransport:
 * - State machine-based Circuit Breaker with exponential backoff
 * - Configurable Retry Policy with jitter
 * - Rate Limiting for backpressure
 * - Automatic fallback replay
 * - Comprehensive metrics
 *
 * Based on:
 * - Sentry SDK retry logic
 * - AWS SDK exponential backoff
 * - Resilience4j patterns
 */
@Slf4j
public class ResilientLogTransport {

    private final SecureLogConfig config;
    private final KafkaProducer kafkaProducer;
    private final LogSerializer serializer;
    private final Path fallbackDirectory;

    // Resilience components
    private final CircuitBreaker circuitBreaker;
    private final RetryPolicy retryPolicy;
    private final RateLimiter rateLimiter;

    // Metrics
    private final SdkMetrics metrics = SdkMetrics.getInstance();

    // Replay scheduler
    private ScheduledExecutorService replayScheduler;
    private volatile boolean autoReplayEnabled = false;

    // Counter for unique fallback filenames
    private final AtomicLong fallbackFileCounter = new AtomicLong(0);

    public ResilientLogTransport(SecureLogConfig config, LogSerializer serializer) {
        this.config = config;
        this.serializer = serializer;
        this.kafkaProducer = initializeKafkaProducer();
        this.fallbackDirectory = Paths.get(config.getFallbackDirectory());

        // Initialize circuit breaker
        this.circuitBreaker = CircuitBreaker.builder("kafka-transport")
                .failureThreshold(config.getCircuitBreakerFailureThreshold())
                .successThreshold(2)
                .openDuration(Duration.ofSeconds(30))
                .maxOpenDuration(Duration.ofMinutes(5))
                .onStateChange((name, from, to) -> {
                    if (to == CircuitBreaker.State.OPEN) {
                        metrics.recordCircuitBreakerOpened();
                    } else if (to == CircuitBreaker.State.CLOSED) {
                        metrics.recordCircuitBreakerClosed();
                    }
                })
                .build();

        // Initialize retry policy
        this.retryPolicy = RetryPolicy.builder()
                .maxAttempts(config.getKafkaRetries())
                .initialDelay(Duration.ofMillis(100))
                .maxDelay(Duration.ofSeconds(10))
                .multiplier(2.0)
                .jitterFactor(0.25)
                .build();

        // Initialize rate limiter (20K logs/sec default)
        this.rateLimiter = RateLimiter.builder("transport")
                .logsPerSecond(20_000)
                .build();

        // Ensure fallback directory exists
        ensureFallbackDirectory();
    }

    private KafkaProducer initializeKafkaProducer() {
        if (config.getKafkaBootstrapServers() != null) {
            return new KafkaProducer(config);
        }
        return null;
    }

    private void ensureFallbackDirectory() {
        try {
            Files.createDirectories(fallbackDirectory);
        } catch (IOException e) {
            log.error("Failed to create fallback directory: {}", fallbackDirectory, e);
        }
    }

    /**
     * Send log data with full resilience support
     */
    public void send(byte[] data) {
        // Rate limiting check
        if (!rateLimiter.tryAcquire()) {
            log.debug("Rate limited, sending to fallback");
            metrics.recordLogDropped("rate_limited");
            sendToFallback(data);
            return;
        }

        // Circuit breaker check
        try {
            circuitBreaker.execute(() -> {
                sendWithRetry(data);
                return null;
            });
        } catch (CircuitBreaker.CircuitBreakerOpenException e) {
            log.debug("Circuit breaker open, using fallback");
            sendToFallback(data);
        } catch (Exception e) {
            log.warn("Send failed after retries, using fallback", e);
            sendToFallback(data);
        }
    }

    /**
     * Send with retry policy
     */
    private void sendWithRetry(byte[] data) {
        if (kafkaProducer == null) {
            throw new TransportException("Kafka producer not configured");
        }

        retryPolicy.execute(() -> {
            kafkaProducer.send(config.getKafkaTopic(), data);
        });
    }

    /**
     * Send to fallback file storage
     */
    public void sendToFallback(byte[] data) {
        try {
            String timestamp = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS"));
            long counter = fallbackFileCounter.incrementAndGet();
            Path fallbackFile = fallbackDirectory.resolve("log-" + timestamp + "-" + counter + ".zst");

            Files.write(fallbackFile, data,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);

            metrics.recordFallbackActivation();
            log.debug("Written to fallback: {}", fallbackFile);

        } catch (IOException e) {
            log.error("Failed to write to fallback storage", e);
        }
    }

    /**
     * Send LogEntry to fallback
     */
    public void sendToFallback(LogEntry entry) {
        byte[] data = serializer.serialize(entry);
        sendToFallback(data);
    }

    /**
     * Replay logs from fallback when Kafka recovers
     */
    public void replayFallbackLogs() {
        if (kafkaProducer == null) {
            log.warn("Cannot replay - Kafka not configured");
            return;
        }

        if (circuitBreaker.getState() != CircuitBreaker.State.CLOSED) {
            log.warn("Cannot replay - Circuit breaker not closed");
            return;
        }

        try (Stream<Path> files = Files.list(fallbackDirectory)) {
            List<Path> fallbackFiles = files
                    .filter(path -> path.toString().endsWith(".zst"))
                    .sorted()
                    .toList();

            log.info("Found {} fallback files to replay", fallbackFiles.size());

            for (Path file : fallbackFiles) {
                if (!replayFile(file)) {
                    log.warn("Replay interrupted due to failure");
                    break;
                }
            }

        } catch (IOException e) {
            log.error("Failed to list fallback files", e);
        }
    }

    /**
     * Replay a single fallback file with file locking to prevent concurrent processing.
     * Uses FileLock to ensure only one thread/process can replay a given file.
     *
     * @param file the fallback file to replay
     * @return true if replay succeeded or file was skipped (being processed), false on error
     */
    private boolean replayFile(Path file) {
        FileLock lock = null;
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            // Try to acquire exclusive lock (non-blocking)
            lock = channel.tryLock();
            if (lock == null) {
                // File is being processed by another thread/process, skip
                log.debug("File {} is being processed by another thread, skipping", file);
                return true;  // Not an error, just skip
            }

            // Read file contents while holding lock
            byte[] data = Files.readAllBytes(file);

            // Use circuit breaker for replay
            circuitBreaker.execute(() -> {
                kafkaProducer.send(config.getKafkaTopic(), data);
                return null;
            });

            // Release lock before secure delete
            if (lock != null && lock.isValid()) {
                try {
                    lock.release();
                } catch (IOException e) {
                    log.warn("Failed to release file lock: {}", e.getMessage());
                }
                lock = null;
            }

            // Secure delete after successful replay
            secureDelete(file);
            log.info("Replayed and deleted: {}", file);
            return true;

        } catch (Exception e) {
            log.error("Failed to replay file: {}", file, e);
            return false;
        } finally {
            // Ensure lock is released if still valid
            if (lock != null && lock.isValid()) {
                try {
                    lock.release();
                } catch (IOException e) {
                    log.warn("Failed to release file lock: {}", e.getMessage());
                }
            }
        }
    }

    /**
     * Secure delete: overwrite then delete
     */
    private void secureDelete(Path file) throws IOException {
        // Overwrite with zeros
        long size = Files.size(file);
        byte[] zeros = new byte[(int) Math.min(size, 8192)];

        try (var channel = Files.newByteChannel(file,
                StandardOpenOption.WRITE, StandardOpenOption.SYNC)) {
            long remaining = size;
            while (remaining > 0) {
                int toWrite = (int) Math.min(remaining, zeros.length);
                channel.write(java.nio.ByteBuffer.wrap(zeros, 0, toWrite));
                remaining -= toWrite;
            }
        }

        // Delete file
        Files.delete(file);
    }

    /**
     * Enable automatic fallback replay
     */
    public void enableAutoReplay(Duration interval) {
        if (autoReplayEnabled) {
            return;
        }

        replayScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "fallback-replay");
            t.setDaemon(true);
            return t;
        });

        replayScheduler.scheduleAtFixedRate(
                () -> {
                    if (circuitBreaker.getState() == CircuitBreaker.State.CLOSED) {
                        replayFallbackLogs();
                    }
                },
                interval.toSeconds(),
                interval.toSeconds(),
                TimeUnit.SECONDS
        );

        autoReplayEnabled = true;
        log.info("Enabled auto-replay every {}s", interval.toSeconds());
    }

    /**
     * Disable automatic fallback replay
     */
    public void disableAutoReplay() {
        if (replayScheduler != null) {
            replayScheduler.shutdown();
            try {
                if (!replayScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    replayScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                replayScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            replayScheduler = null;
        }
        autoReplayEnabled = false;
    }

    /**
     * Force circuit breaker reset (for testing/admin)
     */
    public void resetCircuitBreaker() {
        circuitBreaker.reset();
    }

    /**
     * Get circuit breaker state
     */
    public CircuitBreaker.State getCircuitBreakerState() {
        return circuitBreaker.getState();
    }

    /**
     * Get circuit breaker metrics
     */
    public CircuitBreaker.Metrics getCircuitBreakerMetrics() {
        return circuitBreaker.getMetrics();
    }

    /**
     * Get rate limiter metrics
     */
    public RateLimiter.Metrics getRateLimiterMetrics() {
        return rateLimiter.getMetrics();
    }

    public void close() {
        disableAutoReplay();
        if (kafkaProducer != null) {
            kafkaProducer.close();
        }
    }

    /**
     * Transport exception
     */
    public static class TransportException extends RuntimeException {
        public TransportException(String message) {
            super(message);
        }

        public TransportException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
