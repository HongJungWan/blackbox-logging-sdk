package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import lombok.extern.slf4j.Slf4j;

/**
 * Main log processing pipeline.
 *
 * <p>Pipeline stages:</p>
 * <ol>
 *   <li>PII Masking - mask sensitive data</li>
 *   <li>Merkle Chain Integrity - add hash chain</li>
 *   <li>Envelope Encryption - encrypt payload</li>
 *   <li>Serialization - Zstd compression</li>
 *   <li>Transport - Kafka or Fallback</li>
 * </ol>
 */
@Slf4j
public class LogProcessor {

    private final SecureLogConfig config;
    private final PiiMasker piiMasker;
    private final EnvelopeEncryption encryption;
    private final MerkleChain merkleChain;
    private final LogSerializer serializer;
    private final ResilientLogTransport transport;

    public LogProcessor(
            SecureLogConfig config,
            PiiMasker piiMasker,
            EnvelopeEncryption encryption,
            MerkleChain merkleChain,
            LogSerializer serializer,
            ResilientLogTransport transport
    ) {
        this.config = config;
        this.piiMasker = piiMasker;
        this.encryption = encryption;
        this.merkleChain = merkleChain;
        this.serializer = serializer;
        this.transport = transport;
    }

    /**
     * Process a log entry through the full pipeline.
     */
    public void process(LogEntry entry) {
        LogEntry maskedEntry = null;
        try {
            // Step 1: PII Masking - do this early and store reference for error handling
            maskedEntry = entry;
            if (config.isPiiMaskingEnabled()) {
                maskedEntry = piiMasker.mask(entry);
            }

            // Step 2: Merkle Chain Integrity
            LogEntry chainedEntry = maskedEntry;
            if (config.isIntegrityEnabled()) {
                chainedEntry = merkleChain.addToChain(maskedEntry);
            }

            // Step 3: Envelope Encryption
            LogEntry encryptedEntry = chainedEntry;
            if (config.isEncryptionEnabled()) {
                encryptedEntry = encryption.encrypt(chainedEntry);
            }

            // Step 4: Serialize (Zstd compression)
            byte[] serialized = serializer.serialize(encryptedEntry);

            // Step 5: Transport (Kafka or Fallback)
            transport.send(serialized);

        } catch (Exception e) {
            log.error("Error processing log entry", e);
            // Use masked entry if available, otherwise mask now to prevent PII leak to fallback
            LogEntry safeEntry = (maskedEntry != null) ? maskedEntry : piiMasker.mask(entry);
            handleProcessingError(safeEntry, e);
        }
    }

    private void handleProcessingError(LogEntry entry, Exception error) {
        try {
            transport.sendToFallback(entry);
        } catch (Exception fallbackError) {
            log.error("Failed to write to fallback", fallbackError);
        }
    }

    /**
     * Process a log entry directly to fallback storage.
     * Used during shutdown to ensure no events are lost when buffer cannot be fully drained.
     *
     * <p>Security: Both PII masking and encryption are applied to prevent plaintext
     * sensitive data from being stored on disk. Integrity chain is skipped as it
     * requires sequential state management.</p>
     *
     * @param entry the log entry to send to fallback
     */
    public void processFallback(LogEntry entry) {
        try {
            LogEntry processedEntry = entry;

            // Step 1: PII Masking (critical for compliance)
            if (config.isPiiMaskingEnabled()) {
                processedEntry = piiMasker.mask(entry);
            }

            // Step 2: Encryption (critical for data protection)
            if (config.isEncryptionEnabled()) {
                processedEntry = encryption.encrypt(processedEntry);
            }

            transport.sendToFallback(processedEntry);
        } catch (Exception e) {
            log.error("Failed to process entry to fallback", e);
        }
    }

    /**
     * Flush pending operations.
     */
    public void flush() {
        // No-op after deduplicator removal
    }
}
