package io.github.hongjungwan.blackbox.core.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 콘솔(Standard Out) 로그 전송. JSON 형식으로 System.out에 출력.
 * 스레드 안전하며 오류 시 Fallback 파일 저장 지원.
 */
@Slf4j
public class ConsoleLogTransport implements AutoCloseable {

    private final ObjectMapper objectMapper;
    private final PrintStream outputStream;
    private final Path fallbackDirectory;
    private final LogSerializer serializer;
    private final ReentrantLock writeLock = new ReentrantLock();
    private final AtomicLong sentCount = new AtomicLong(0);
    private final AtomicLong errorCount = new AtomicLong(0);
    private final AtomicLong fallbackFileCounter = new AtomicLong(0);
    private final SdkMetrics metrics = SdkMetrics.getInstance();

    public ConsoleLogTransport(SecureLogConfig config, LogSerializer serializer) {
        this(config, serializer, System.out);
    }

    /** 테스트용 생성자 (PrintStream 주입 가능) */
    public ConsoleLogTransport(SecureLogConfig config, LogSerializer serializer, PrintStream outputStream) {
        this.serializer = serializer;
        this.outputStream = outputStream;
        this.fallbackDirectory = Paths.get(config.getFallbackDirectory());
        this.objectMapper = createObjectMapper();
        ensureFallbackDirectory();
    }

    private ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        return mapper;
    }

    private void ensureFallbackDirectory() {
        try {
            Files.createDirectories(fallbackDirectory);
        } catch (IOException e) {
            log.error("Failed to create fallback directory: {}", fallbackDirectory, e);
        }
    }

    /**
     * LogEntry를 JSON으로 직렬화하여 Standard Out에 출력.
     * 스레드 안전하게 구현되어 동시 출력 시에도 JSON이 섞이지 않음.
     */
    public void send(LogEntry entry) {
        writeLock.lock();
        try {
            String json = objectMapper.writeValueAsString(entry);
            outputStream.println(json);
            sentCount.incrementAndGet();

            if (log.isDebugEnabled()) {
                log.debug("Sent log entry to stdout: {} bytes", json.length());
            }
        } catch (JsonProcessingException e) {
            errorCount.incrementAndGet();
            log.error("Failed to serialize log entry", e);
            sendToFallback(entry);
        } finally {
            writeLock.unlock();
        }
    }

    /** Fallback 파일 저장 (Zstd 압축) */
    public void sendToFallback(LogEntry entry) {
        try {
            byte[] data = serializer.serialize(entry);
            sendToFallback(data);
        } catch (Exception e) {
            log.error("Failed to serialize entry for fallback", e);
        }
    }

    /** Fallback 파일 저장 (바이트 배열) */
    public void sendToFallback(byte[] data) {
        try {
            String timestamp = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS"));
            long counter = fallbackFileCounter.incrementAndGet();
            Path fallbackFile = fallbackDirectory.resolve("log-" + timestamp + "-" + counter + ".zst");

            // CREATE_NEW: 파일이 이미 존재하면 예외 발생 (Zstd 데이터 손상 방지)
            // 동일 파일명 충돌 시 재시도
            try {
                Files.write(fallbackFile, data, StandardOpenOption.CREATE_NEW);
            } catch (java.nio.file.FileAlreadyExistsException e) {
                // 충돌 시 나노초 추가하여 재시도
                fallbackFile = fallbackDirectory.resolve(
                        "log-" + timestamp + "-" + counter + "-" + System.nanoTime() + ".zst");
                Files.write(fallbackFile, data, StandardOpenOption.CREATE_NEW);
            }

            metrics.recordFallbackActivation();
            log.debug("Written to fallback: {}", fallbackFile);

        } catch (IOException e) {
            log.error("Failed to write to fallback storage", e);
        }
    }

    public long getSentCount() {
        return sentCount.get();
    }

    public long getErrorCount() {
        return errorCount.get();
    }

    @Override
    public void close() {
        log.info("ConsoleLogTransport closed (sent={}, errors={})", sentCount.get(), errorCount.get());
    }
}
