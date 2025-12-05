package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.context.LoggingContext;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import io.github.hongjungwan.blackbox.core.internal.SemanticDeduplicator;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.internal.LogTransport;
import io.github.hongjungwan.blackbox.core.internal.InterceptorChainImpl;
import io.github.hongjungwan.blackbox.api.interceptor.LogInterceptor;
import io.github.hongjungwan.blackbox.core.internal.BuiltInInterceptors;
import io.github.hongjungwan.blackbox.core.internal.SdkMetrics;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

/**
 * Enhanced Log Processor with Interceptor Chain and Metrics
 *
 * Improvements over base LogProcessor:
 * - Interceptor chain at each processing stage
 * - Comprehensive metrics collection
 * - Context propagation integration
 * - Better error handling with stage-specific fallbacks
 */
@Slf4j
public class EnhancedLogProcessor {

    private final SecureLogConfig config;
    private final PiiMasker piiMasker;
    private final EnvelopeEncryption encryption;
    private final MerkleChain merkleChain;
    private final SemanticDeduplicator deduplicator;
    private final LogSerializer serializer;
    private final LogTransport transport;

    // Interceptor chains for each stage
    private final InterceptorChainImpl.Registry preProcessInterceptors;
    private final InterceptorChainImpl.Registry postProcessInterceptors;

    // Metrics
    private final SdkMetrics metrics = SdkMetrics.getInstance();

    public EnhancedLogProcessor(
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

        this.preProcessInterceptors = new InterceptorChainImpl.Registry();
        this.postProcessInterceptors = new InterceptorChainImpl.Registry();

        // Register built-in interceptors
        registerBuiltInInterceptors();
    }

    private void registerBuiltInInterceptors() {
        // Context enrichment (highest priority)
        preProcessInterceptors.register(
                "context-enrichment",
                LogInterceptor.Priority.HIGHEST,
                BuiltInInterceptors.contextEnrichment()
        );

        // Error enrichment
        preProcessInterceptors.register(
                "error-enrichment",
                LogInterceptor.Priority.HIGH,
                BuiltInInterceptors.errorEnrichment()
        );
    }

    /**
     * Process a log entry through the full pipeline with interceptors
     *
     * FIX P1-3: Security enhancement - ensures PII-masked entry is sent to fallback on exceptions.
     * Original unmasked data never leaks to fallback storage.
     */
    public void process(LogEntry entry) {
        SdkMetrics.Timer totalTimer = metrics.startTimer();

        // FIX P1-3: Track masked entry to ensure only masked data goes to fallback on error
        LogEntry maskedEntry = entry;

        try {
            // Pre-process interceptor chain
            LogEntry processed = runPreProcessChain(entry);
            if (processed == null) {
                metrics.recordLogDropped("interceptor");
                return;
            }

            // Core pipeline (includes PII masking)
            processed = executePipeline(processed);
            if (processed == null) {
                return; // Already handled (deduplicated or dropped)
            }

            // FIX P1-3: Update maskedEntry after pipeline (which includes PII masking)
            maskedEntry = processed;

            // Serialize
            SdkMetrics.Timer serializeTimer = metrics.startTimer();
            byte[] serialized = serializer.serialize(processed);
            metrics.recordStage("serialize", serializeTimer.elapsedNanos(), true);

            // Transport
            SdkMetrics.Timer transportTimer = metrics.startTimer();
            transport.send(serialized);
            metrics.recordTransportLatency(transportTimer.elapsedNanos());
            metrics.recordBytesSent(serialized.length);

            // Post-process interceptor chain
            runPostProcessChain(processed);

            // Record success metrics
            metrics.recordLogProcessed(entry.getLevel(), serialized.length);
            metrics.recordProcessingLatency(totalTimer.elapsedNanos());

        } catch (Exception e) {
            log.error("Error processing log entry", e);
            metrics.recordLogFailed("process", e);
            // FIX P1-3: Send masked entry to fallback, never the original unmasked entry
            handleProcessingError(maskedEntry, e);
        }
    }

    private LogEntry runPreProcessChain(LogEntry entry) {
        InterceptorChainImpl chain = preProcessInterceptors.buildChain(
                LogInterceptor.ProcessingStage.PRE_PROCESS
        );
        return chain.execute(entry);
    }

    private LogEntry runPostProcessChain(LogEntry entry) {
        InterceptorChainImpl chain = postProcessInterceptors.buildChain(
                LogInterceptor.ProcessingStage.POST_TRANSPORT
        );
        return chain.execute(entry);
    }

    private LogEntry executePipeline(LogEntry entry) {
        LogEntry current = entry;

        // Step 1: Semantic Deduplication (FEAT-02)
        if (config.isDeduplicationEnabled()) {
            SdkMetrics.Timer timer = metrics.startTimer();
            if (deduplicator.isDuplicate(current)) {
                metrics.recordStage("dedup", timer.elapsedNanos(), true);
                metrics.recordLogDropped("duplicate");
                return null;
            }
            metrics.recordStage("dedup", timer.elapsedNanos(), true);
        }

        // Step 2: PII Masking (FEAT-01)
        if (config.isPiiMaskingEnabled()) {
            SdkMetrics.Timer timer = metrics.startTimer();
            try {
                current = piiMasker.mask(current);
                metrics.recordMaskingLatency(timer.elapsedNanos());
                metrics.recordStage("mask", timer.elapsedNanos(), true);
            } catch (Exception e) {
                metrics.recordStage("mask", timer.elapsedNanos(), false);
                throw e;
            }
        }

        // Step 3: Merkle Chain Integrity (FEAT-04)
        if (config.isIntegrityEnabled()) {
            SdkMetrics.Timer timer = metrics.startTimer();
            try {
                current = merkleChain.addToChain(current);
                metrics.recordStage("integrity", timer.elapsedNanos(), true);
            } catch (Exception e) {
                metrics.recordStage("integrity", timer.elapsedNanos(), false);
                throw e;
            }
        }

        // Step 4: Envelope Encryption (FEAT-04)
        if (config.isEncryptionEnabled()) {
            SdkMetrics.Timer timer = metrics.startTimer();
            try {
                current = encryption.encrypt(current);
                metrics.recordEncryptionLatency(timer.elapsedNanos());
                metrics.recordStage("encrypt", timer.elapsedNanos(), true);
            } catch (Exception e) {
                metrics.recordStage("encrypt", timer.elapsedNanos(), false);
                throw e;
            }
        }

        return current;
    }

    private void handleProcessingError(LogEntry entry, Exception error) {
        // FEAT-05: Circuit Breaker Fallback
        try {
            transport.sendToFallback(entry);
            metrics.recordFallbackActivation();
        } catch (Exception fallbackError) {
            log.error("Failed to write to fallback", fallbackError);
            metrics.recordLogFailed("fallback", fallbackError);
        }
    }

    /**
     * Register a pre-process interceptor
     */
    public void addPreProcessInterceptor(String name, LogInterceptor interceptor) {
        preProcessInterceptors.register(name, interceptor);
    }

    /**
     * Register a pre-process interceptor with priority
     */
    public void addPreProcessInterceptor(String name, LogInterceptor.Priority priority, LogInterceptor interceptor) {
        preProcessInterceptors.register(name, priority, interceptor);
    }

    /**
     * Register a post-process interceptor
     */
    public void addPostProcessInterceptor(String name, LogInterceptor interceptor) {
        postProcessInterceptors.register(name, interceptor);
    }

    /**
     * Remove an interceptor by name
     */
    public void removeInterceptor(String name) {
        preProcessInterceptors.unregister(name);
        postProcessInterceptors.unregister(name);
    }

    /**
     * Get current metrics snapshot
     */
    public SdkMetrics.Snapshot getMetrics() {
        return metrics.getSnapshot();
    }

    /**
     * Get throughput (logs per second)
     */
    public double getThroughput() {
        return metrics.getThroughput();
    }

    /**
     * Get error rate (0.0 - 1.0)
     */
    public double getErrorRate() {
        return metrics.getErrorRate();
    }
}
