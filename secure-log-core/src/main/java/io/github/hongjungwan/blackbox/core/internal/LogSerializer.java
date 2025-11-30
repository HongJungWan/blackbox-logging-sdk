package io.github.hongjungwan.blackbox.core.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.luben.zstd.Zstd;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.io.IOException;

/**
 * Log serializer with Zstd compression
 * Converts LogEntry to compressed binary format for efficient transport
 */
public class LogSerializer {

    private final ObjectMapper objectMapper;
    private final int compressionLevel;

    public LogSerializer() {
        this(3); // Default Zstd compression level
    }

    public LogSerializer(int compressionLevel) {
        this.compressionLevel = compressionLevel;
        this.objectMapper = createObjectMapper();
    }

    private ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
        return mapper;
    }

    /**
     * Serialize and compress log entry to binary format
     */
    public byte[] serialize(LogEntry entry) {
        try {
            // Step 1: Convert to JSON
            byte[] json = objectMapper.writeValueAsBytes(entry);

            // Step 2: Compress with Zstd
            byte[] compressed = Zstd.compress(json, compressionLevel);

            return compressed;

        } catch (IOException e) {
            throw new SerializationException("Failed to serialize log entry", e);
        }
    }

    /**
     * Deserialize and decompress log entry from binary format
     */
    public LogEntry deserialize(byte[] data) {
        try {
            // Step 1: Decompress with Zstd
            long originalSize = Zstd.decompressedSize(data);
            byte[] decompressed = Zstd.decompress(data, (int) originalSize);

            // Step 2: Parse JSON
            return objectMapper.readValue(decompressed, LogEntry.class);

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
