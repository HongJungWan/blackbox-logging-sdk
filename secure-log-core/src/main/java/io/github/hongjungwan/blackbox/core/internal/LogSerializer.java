package io.github.hongjungwan.blackbox.core.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.luben.zstd.Zstd;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.io.IOException;

/**
 * 로그 직렬화 (JSON + Zstd 압축). 최대 페이로드 크기 제한으로 메모리 보호.
 */
public class LogSerializer {

    private final ObjectMapper objectMapper;
    private final int compressionLevel;

    private final long maxPayloadSize;

    public static final long DEFAULT_MAX_PAYLOAD_SIZE = 100 * 1024 * 1024L;  // 100MB
    public static final long MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024L;     // 100MB

    public LogSerializer() {
        this(3, DEFAULT_MAX_PAYLOAD_SIZE);
    }

    public LogSerializer(int compressionLevel) {
        this(compressionLevel, DEFAULT_MAX_PAYLOAD_SIZE);
    }

    /** Zstd 압축 레벨 1-22 검증 */
    public LogSerializer(int compressionLevel, long maxPayloadSize) {
        if (compressionLevel < 1 || compressionLevel > 22) {
            throw new IllegalArgumentException(
                    "Zstd compression level must be between 1 and 22, got: " + compressionLevel);
        }
        this.compressionLevel = compressionLevel;
        this.maxPayloadSize = maxPayloadSize;
        this.objectMapper = createObjectMapper();
    }

    private ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        return mapper;
    }

    /** 직렬화 + Zstd 압축 */
    public byte[] serialize(LogEntry entry) {
        try {
            byte[] json = objectMapper.writeValueAsBytes(entry);

            if (json.length > maxPayloadSize) {
                throw new SerializationException(
                        String.format("Log entry exceeds maximum allowed size: %d bytes (max: %d bytes)",
                                json.length, maxPayloadSize), null);
            }

            return Zstd.compress(json, compressionLevel);

        } catch (SerializationException e) {
            throw e;
        } catch (IOException e) {
            throw new SerializationException("Failed to serialize log entry", e);
        }
    }

    /** 역직렬화 (Zstd 압축 해제 + JSON 파싱) */
    public LogEntry deserialize(byte[] data) {
        try {
            long originalSize = Zstd.decompressedSize(data);

            // 음수: 손상된 데이터 또는 알 수 없는 크기
            if (originalSize < 0) {
                throw new SerializationException(
                        "Invalid decompressed size: " + originalSize, null);
            }

            // 크기 제한 검증 (메모리 고갈 방지)
            if (originalSize > MAX_DECOMPRESSED_SIZE || originalSize > Integer.MAX_VALUE) {
                throw new SerializationException(
                        String.format("Decompressed size exceeds limit: %d bytes", originalSize), null);
            }

            byte[] decompressed = Zstd.decompress(data, (int) originalSize);

            if (decompressed.length != originalSize) {
                throw new SerializationException(
                        String.format("Size mismatch: expected %d, got %d", originalSize, decompressed.length), null);
            }

            return objectMapper.readValue(decompressed, LogEntry.class);

        } catch (SerializationException e) {
            throw e;
        } catch (IOException e) {
            throw new SerializationException("Failed to deserialize log entry", e);
        }
    }

    public static class SerializationException extends RuntimeException {
        public SerializationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
