package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.resilience.CircuitBreaker;
import io.github.hongjungwan.blackbox.core.resilience.RetryPolicy;
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
 * ResilientLogTransport - 장애 복원력을 갖춘 로그 전송
 *
 * 주니어 면접용으로 단순화된 구현:
 * - Circuit Breaker: 연속 실패 시 fast-fail
 * - Retry Policy: 고정 간격 재시도
 * - Fallback: 파일 기반 백업
 *
 * RateLimiter 제거 - SDK 레벨 rate limiting은 과도함
 */
@Slf4j
public class ResilientLogTransport {

    private final SecureLogConfig config;
    private final KafkaProducer kafkaProducer;
    private final LogSerializer serializer;
    private final Path fallbackDirectory;

    // Resilience components (단순화됨)
    private final CircuitBreaker circuitBreaker;
    private final RetryPolicy retryPolicy;

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

        // 단순화된 Circuit Breaker
        this.circuitBreaker = CircuitBreaker.builder("kafka-transport")
                .failureThreshold(config.getCircuitBreakerFailureThreshold())
                .openDuration(Duration.ofSeconds(30))
                .onStateChange((name, from, to) -> {
                    if (to == CircuitBreaker.State.OPEN) {
                        metrics.recordCircuitBreakerOpened();
                    } else if (to == CircuitBreaker.State.CLOSED) {
                        metrics.recordCircuitBreakerClosed();
                    }
                })
                .build();

        // 단순화된 Retry Policy (고정 간격)
        this.retryPolicy = RetryPolicy.builder()
                .maxAttempts(config.getKafkaRetries())
                .initialDelay(Duration.ofMillis(100))
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
     * 로그 데이터 전송 (Circuit Breaker + Retry 적용)
     */
    public void send(byte[] data) {
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
     * 재시도 정책 적용하여 전송
     */
    private void sendWithRetry(byte[] data) {
        if (kafkaProducer == null) {
            throw new TransportException("Kafka producer not configured");
        }

        retryPolicy.execute(() -> {
            kafkaProducer.send(config.getKafkaTopic(), data).join();
        });
    }

    /**
     * Fallback 파일 저장소로 전송
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
     * LogEntry를 Fallback으로 전송
     */
    public void sendToFallback(LogEntry entry) {
        byte[] data = serializer.serialize(entry);
        sendToFallback(data);
    }

    /**
     * Kafka 복구 시 Fallback 로그 재전송
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
     * 단일 Fallback 파일 재전송 (파일 잠금으로 동시 처리 방지)
     */
    private boolean replayFile(Path file) {
        FileLock lock = null;
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            lock = channel.tryLock();
            if (lock == null) {
                log.debug("File {} is being processed by another thread, skipping", file);
                return true;
            }

            byte[] data = Files.readAllBytes(file);

            // Zstd 프레임 검증
            if (!isValidZstdFrame(data)) {
                log.warn("Corrupted fallback file (invalid Zstd frame), deleting: {}", file);
                releaseLock(lock);
                lock = null;
                Files.delete(file);
                return true;
            }

            // Circuit Breaker 적용하여 전송
            circuitBreaker.execute(() -> {
                kafkaProducer.send(config.getKafkaTopic(), data);
                return null;
            });

            releaseLock(lock);
            lock = null;

            // 성공 후 안전 삭제
            secureDelete(file);
            log.info("Replayed and deleted: {}", file);
            return true;

        } catch (Exception e) {
            log.error("Failed to replay file: {}", file, e);
            return false;
        } finally {
            releaseLock(lock);
        }
    }

    private void releaseLock(FileLock lock) {
        if (lock != null && lock.isValid()) {
            try {
                lock.release();
            } catch (IOException e) {
                log.warn("Failed to release file lock: {}", e.getMessage());
            }
        }
    }

    /**
     * Zstd 프레임 유효성 검사 (magic number: 0xFD2FB528)
     */
    private boolean isValidZstdFrame(byte[] data) {
        if (data == null || data.length < 4) {
            return false;
        }
        return (data[0] & 0xFF) == 0x28 &&
               (data[1] & 0xFF) == 0xB5 &&
               (data[2] & 0xFF) == 0x2F &&
               (data[3] & 0xFF) == 0xFD;
    }

    /**
     * 안전 삭제: 덮어쓰기 후 삭제
     */
    private void secureDelete(Path file) throws IOException {
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

        Files.delete(file);
    }

    /**
     * 자동 Fallback 재전송 활성화
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
     * 자동 Fallback 재전송 비활성화
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
     * Circuit Breaker 강제 리셋
     */
    public void resetCircuitBreaker() {
        circuitBreaker.reset();
    }

    /**
     * Circuit Breaker 상태 조회
     */
    public CircuitBreaker.State getCircuitBreakerState() {
        return circuitBreaker.getState();
    }

    /**
     * Circuit Breaker 메트릭 조회
     */
    public CircuitBreaker.Metrics getCircuitBreakerMetrics() {
        return circuitBreaker.getMetrics();
    }

    public void close() {
        disableAutoReplay();
        if (kafkaProducer != null) {
            kafkaProducer.close();
        }
    }

    /**
     * Transport 예외
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
