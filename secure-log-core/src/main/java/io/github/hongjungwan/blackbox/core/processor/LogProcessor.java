package io.github.hongjungwan.blackbox.core.processor;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.masking.PiiMasker;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.integrity.MerkleChain;
import io.github.hongjungwan.blackbox.core.deduplication.SemanticDeduplicator;
import io.github.hongjungwan.blackbox.core.serialization.LogSerializer;
import io.github.hongjungwan.blackbox.core.transport.LogTransport;
import lombok.extern.slf4j.Slf4j;

/**
 * Main log processing pipeline
 */
@Slf4j
public class LogProcessor {

    private final SecureLogConfig config;
    private final PiiMasker piiMasker;
    private final EnvelopeEncryption encryption;
    private final MerkleChain merkleChain;
    private final SemanticDeduplicator deduplicator;
    private final LogSerializer serializer;
    private final LogTransport transport;

    public LogProcessor(
            SecureLogConfig config,
            PiiMasker piiMasker,
            EnvelopeEncryption encryption,
            MerkleChain merkleChain,
            SemanticDeduplicator deduplicator,
            LogSerializer serializer,
            LogTransport transport
    ) {
        this.config = config;
        this.piiMasker = piiMasker;
        this.encryption = encryption;
        this.merkleChain = merkleChain;
        this.deduplicator = deduplicator;
        this.serializer = serializer;
        this.transport = transport;
    }

    /**
     * Process a log entry through the full pipeline
     */
    public void process(LogEntry entry) {
        try {
            // Step 1: Semantic Deduplication (FEAT-02)
            if (config.isDeduplicationEnabled()) {
                if (deduplicator.isDuplicate(entry)) {
                    // Silently skip, counter incremented in deduplicator
                    return;
                }
            }

            // Step 2: PII Masking (FEAT-01)
            LogEntry maskedEntry = entry;
            if (config.isPiiMaskingEnabled()) {
                maskedEntry = piiMasker.mask(entry);
            }

            // Step 3: Merkle Chain Integrity (FEAT-04)
            LogEntry chainedEntry = maskedEntry;
            if (config.isIntegrityEnabled()) {
                chainedEntry = merkleChain.addToChain(maskedEntry);
            }

            // Step 4: Envelope Encryption (FEAT-04)
            LogEntry encryptedEntry = chainedEntry;
            if (config.isEncryptionEnabled()) {
                encryptedEntry = encryption.encrypt(chainedEntry);
            }

            // Step 5: Serialize (Zstd compression)
            byte[] serialized = serializer.serialize(encryptedEntry);

            // Step 6: Transport (Kafka or Fallback)
            transport.send(serialized);

        } catch (Exception e) {
            log.error("Error processing log entry", e);
            // Fallback handling
            handleProcessingError(entry, e);
        }
    }

    private void handleProcessingError(LogEntry entry, Exception error) {
        // FEAT-05: Circuit Breaker Fallback
        try {
            transport.sendToFallback(entry);
        } catch (Exception fallbackError) {
            log.error("Failed to write to fallback", fallbackError);
        }
    }
}
