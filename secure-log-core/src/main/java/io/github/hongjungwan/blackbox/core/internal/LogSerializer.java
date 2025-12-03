package io.github.hongjungwan.blackbox.core.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.luben.zstd.Zstd;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.io.IOException;

/**
 * Log serializer with Zstd compression.
 *
 * <p>Converts LogEntry to compressed binary format for efficient transport.</p>
 *
 * <h2>Memory Protection</h2>
 * <p>This serializer enforces a maximum payload size to prevent memory exhaustion attacks
 * and OutOfMemoryError conditions. Payloads exceeding the limit will be rejected.</p>
 */
public class LogSerializer {

    private final ObjectMapper objectMapper;
    private final int compressionLevel;

    /**
     * Maximum allowed size for serialized JSON before compression (default: 100MB).
     * This prevents memory exhaustion from extremely large log entries.
     */
    private final long maxPayloadSize;

    /** Default maximum payload size: 100MB */
    public static final long DEFAULT_MAX_PAYLOAD_SIZE = 100 * 1024 * 1024L;

    /** Maximum allowed decompressed size: 100MB */
    public static final long MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024L;

    public LogSerializer() {
        this(3, DEFAULT_MAX_PAYLOAD_SIZE); // Default Zstd compression level
    }

    public LogSerializer(int compressionLevel) {
        this(compressionLevel, DEFAULT_MAX_PAYLOAD_SIZE);
    }

    /**
     * FIX P3 #18: Validate Zstd compression level range.
     */
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

    /**
     * Serialize and compress log entry to binary format.
     *
     * @param entry the log entry to serialize
     * @return compressed binary data
     * @throws SerializationException if JSON conversion fails due to unserializable fields,
     *         or if serialized JSON exceeds configured maxPayloadSize (default 100MB)
     */
    public byte[] serialize(LogEntry entry) {
        try {
            // Step 1: Convert to JSON
            byte[] json = objectMapper.writeValueAsBytes(entry);

            // Step 2: Validate size before compression
            if (json.length > maxPayloadSize) {
                throw new SerializationException(
                        String.format("Log entry exceeds maximum allowed size: %d bytes (max: %d bytes). " +
                                "Consider reducing payload size or increasing maxPayloadSize configuration.",
                                json.length, maxPayloadSize), null);
            }

            // Step 3: Compress with Zstd
            byte[] compressed = Zstd.compress(json, compressionLevel);

            return compressed;

        } catch (SerializationException e) {
            throw e; // Re-throw our own exceptions
        } catch (IOException e) {
            throw new SerializationException("Failed to serialize log entry", e);
        }
    }

    /**
     * Deserialize and decompress log entry from binary format.
     *
     * FIX P1 #8: Reordered size checks - check negative FIRST since it indicates unknown/invalid data.
     * Zstd returns -1 (ZSTD_CONTENTSIZE_UNKNOWN) for unknown size and -2 (ZSTD_CONTENTSIZE_ERROR) for error.
     *
     * @param data the compressed binary data
     * @return the deserialized log entry
     * @throws SerializationException if Zstd decompression fails due to corrupted or invalid data,
     *         if decompressed size exceeds MAX_DECOMPRESSED_SIZE (100MB),
     *         or if JSON parsing fails due to malformed structure
     */
    public LogEntry deserialize(byte[] data) {
        try {
            // Step 1: Decompress with Zstd
            long originalSize = Zstd.decompressedSize(data);

            // FIX P1 #8: Check negative size FIRST (indicates unknown/invalid data)
            if (originalSize < 0) {
                throw new SerializationException(
                        "Invalid decompressed size: " + originalSize + " (corrupted data or unknown size frame?)", null);
            }

            // Validate size to prevent memory exhaustion
            if (originalSize > MAX_DECOMPRESSED_SIZE) {
                throw new SerializationException(
                        String.format("Decompressed size exceeds maximum allowed: %d bytes (max: %d bytes). " +
                                "This may indicate corrupted data or a decompression bomb attack.",
                                originalSize, MAX_DECOMPRESSED_SIZE), null);
            }
            if (originalSize > Integer.MAX_VALUE) {
                throw new SerializationException(
                        "Decompressed size exceeds maximum allowed: " + originalSize +
                                " bytes (max: " + Integer.MAX_VALUE + " bytes)", null);
            }

            byte[] decompressed = Zstd.decompress(data, (int) originalSize);

            // Validate actual decompressed size matches expected size
            if (decompressed.length != originalSize) {
                throw new SerializationException(
                        String.format("Decompressed size mismatch: expected %d bytes but got %d bytes. " +
                                "This may indicate corrupted data.", originalSize, decompressed.length), null);
            }

            // Step 2: Parse JSON
            return objectMapper.readValue(decompressed, LogEntry.class);

        } catch (SerializationException e) {
            throw e; // Re-throw our own exceptions
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
