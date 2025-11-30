package io.github.hongjungwan.blackbox.core.processor;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.context.LoggingContext;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.masking.PiiMasker;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.integrity.MerkleChain;
import io.github.hongjungwan.blackbox.core.deduplication.SemanticDeduplicator;
import io.github.hongjungwan.blackbox.core.serialization.LogSerializer;
import io.github.hongjungwan.blackbox.core.transport.LogTransport;
import io.github.hongjungwan.blackbox.core.interceptor.InterceptorChain;
import io.github.hongjungwan.blackbox.core.interceptor.LogInterceptor;
import io.github.hongjungwan.blackbox.core.interceptor.BuiltInInterceptors;
import io.github.hongjungwan.blackbox.core.metrics.SdkMetrics;
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
    private final InterceptorChain.Registry preProcessInterceptors;
    private final InterceptorChain.Registry postProcessInterceptors;

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

        this.preProcessInterceptors = new InterceptorChain.Registry();
        this.postProcessInterceptors = new InterceptorChain.Registry();

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
     */
    public void process(LogEntry entry) {
        SdkMetrics.Timer totalTimer = metrics.startTimer();

        try {
            // Pre-process interceptor chain
            LogEntry processed = runPreProcessChain(entry);
            if (processed == null) {
                metrics.recordLogDropped("interceptor");
                return;
            }

            // Core pipeline
            processed = executePipeline(processed);
            if (processed == null) {
                return; // Already handled (deduplicated or dropped)
            }

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
            handleProcessingError(entry, e);
        }
    }

    private LogEntry runPreProcessChain(LogEntry entry) {
        InterceptorChain chain = preProcessInterceptors.buildChain(
                LogInterceptor.ProcessingStage.PRE_PROCESS
        );
        return chain.execute(entry);
    }

    private LogEntry runPostProcessChain(LogEntry entry) {
        InterceptorChain chain = postProcessInterceptors.buildChain(
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
