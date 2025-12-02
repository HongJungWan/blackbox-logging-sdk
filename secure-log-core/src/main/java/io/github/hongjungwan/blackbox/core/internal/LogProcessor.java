package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import io.github.hongjungwan.blackbox.core.internal.SemanticDeduplicator;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.internal.ResilientLogTransport;
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
    private final ResilientLogTransport transport;

    public LogProcessor(
            SecureLogConfig config,
            PiiMasker piiMasker,
            EnvelopeEncryption encryption,
            MerkleChain merkleChain,
            SemanticDeduplicator deduplicator,
            LogSerializer serializer,
            ResilientLogTransport transport
    ) {
        this.config = config;
        this.piiMasker = piiMasker;
        this.encryption = encryption;
        this.merkleChain = merkleChain;
        this.deduplicator = deduplicator;
        this.serializer = serializer;
        this.transport = transport;

        // Register callback for deduplication summary logs
        // When deduplication window expires, summary logs are processed through the pipeline
        if (config.isDeduplicationEnabled()) {
            deduplicator.setSummaryCallback(this::processSummaryEntry);
        }
    }

    /**
     * Process a summary entry from deduplication (skips deduplication step)
     */
    private void processSummaryEntry(LogEntry summaryEntry) {
        try {
            // Summary entries bypass deduplication (Step 1 skipped)

            // Step 2: PII Masking
            LogEntry maskedEntry = summaryEntry;
            if (config.isPiiMaskingEnabled()) {
                maskedEntry = piiMasker.mask(summaryEntry);
            }

            // Step 3: Merkle Chain Integrity
            LogEntry chainedEntry = maskedEntry;
            if (config.isIntegrityEnabled()) {
                chainedEntry = merkleChain.addToChain(maskedEntry);
            }

            // Step 4: Envelope Encryption
            LogEntry encryptedEntry = chainedEntry;
            if (config.isEncryptionEnabled()) {
                encryptedEntry = encryption.encrypt(chainedEntry);
            }

            // Step 5: Serialize
            byte[] serialized = serializer.serialize(encryptedEntry);

            // Step 6: Transport
            transport.send(serialized);

            log.debug("Emitted deduplication summary log with repeat_count={}", summaryEntry.getRepeatCount());

        } catch (Exception e) {
            log.error("Error processing deduplication summary entry", e);
            handleProcessingError(summaryEntry, e);
        }
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
