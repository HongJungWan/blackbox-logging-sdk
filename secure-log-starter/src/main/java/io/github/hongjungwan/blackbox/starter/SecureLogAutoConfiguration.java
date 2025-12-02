package io.github.hongjungwan.blackbox.starter;

import io.github.hongjungwan.blackbox.core.internal.VirtualAsyncAppender;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.internal.SemanticDeduplicator;
import io.github.hongjungwan.blackbox.core.internal.SecureLogDoctor;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.internal.LogProcessor;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.security.KmsClient;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.internal.ResilientLogTransport;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;

/**
 * FEAT-06: Spring Boot AutoConfiguration
 *
 * Auto-configures SecureHR Logging SDK components
 * Profile-aware: 'prod' profile enables ASYNC + Binary mode automatically
 */
@AutoConfiguration
@EnableConfigurationProperties(SecureLogProperties.class)
@ConditionalOnProperty(prefix = "secure-hr.logging", name = "enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class SecureLogAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecureLogConfig secureLogConfig(SecureLogProperties properties) {
        return SecureLogConfig.builder()
                .mode(properties.getMode())
                .bufferSize(properties.getBufferSize())
                .piiMaskingEnabled(properties.getPiiMasking().isEnabled())
                .piiPatterns(properties.getPiiMasking().getPatterns())
                .encryptionEnabled(properties.getSecurity().isEncryptionEnabled())
                .kmsEndpoint(properties.getSecurity().getKmsEndpoint())
                .kmsTimeoutMs(properties.getSecurity().getKmsTimeoutMs())
                .deduplicationEnabled(properties.isDeduplicationEnabled())
                .deduplicationWindowMs(properties.getDeduplicationWindowMs())
                .kafkaBootstrapServers(properties.getKafka().getBootstrapServers())
                .kafkaTopic(properties.getKafka().getTopic())
                .kafkaRetries(properties.getKafka().getRetries())
                .fallbackDirectory(properties.getFallbackDirectory())
                .integrityEnabled(properties.getSecurity().isIntegrityEnabled())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public PiiMasker piiMasker(SecureLogConfig config) {
        return new PiiMasker(config);
    }

    @Bean
    @ConditionalOnMissingBean
    public KmsClient kmsClient(SecureLogConfig config) {
        return new KmsClient(config);
    }

    @Bean
    @ConditionalOnMissingBean
    public EnvelopeEncryption envelopeEncryption(SecureLogConfig config, KmsClient kmsClient) {
        return new EnvelopeEncryption(config, kmsClient);
    }

    @Bean
    @ConditionalOnMissingBean
    public MerkleChain merkleChain() {
        return new MerkleChain();
    }

    @Bean
    @ConditionalOnMissingBean
    public SemanticDeduplicator semanticDeduplicator(SecureLogConfig config) {
        return new SemanticDeduplicator(config);
    }

    @Bean
    @ConditionalOnMissingBean
    public LogSerializer logSerializer() {
        return new LogSerializer();
    }

    @Bean
    @ConditionalOnMissingBean
    public ResilientLogTransport logTransport(SecureLogConfig config, LogSerializer serializer) {
        return new ResilientLogTransport(config, serializer);
    }

    @Bean
    @ConditionalOnMissingBean
    public LogProcessor logProcessor(
            SecureLogConfig config,
            PiiMasker piiMasker,
            EnvelopeEncryption encryption,
            MerkleChain merkleChain,
            SemanticDeduplicator deduplicator,
            LogSerializer serializer,
            ResilientLogTransport transport
    ) {
        return new LogProcessor(config, piiMasker, encryption, merkleChain, deduplicator, serializer, transport);
    }

    @Bean
    @ConditionalOnMissingBean
    public VirtualAsyncAppender virtualAsyncAppender(SecureLogConfig config, LogProcessor processor) {
        return new VirtualAsyncAppender(config, processor);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecureLogDoctor secureLogDoctor(SecureLogConfig config) {
        return new SecureLogDoctor(config);
    }

    /**
     * Lifecycle manager for SDK initialization and diagnostics
     */
    @Bean
    public SecureLogLifecycle secureLogLifecycle(
            SecureLogDoctor doctor,
            VirtualAsyncAppender appender,
            SecureLogConfig config,
            MerkleChain merkleChain
    ) {
        return new SecureLogLifecycle(doctor, appender, config, merkleChain);
    }

    /**
     * SmartLifecycle implementation for SDK initialization
     */
    static class SecureLogLifecycle implements SmartLifecycle {

        private static final String MERKLE_CHAIN_STATE_FILE = ".secure-hr-merkle-chain-state";

        private final SecureLogDoctor doctor;
        private final VirtualAsyncAppender appender;
        private final SecureLogConfig config;
        private final MerkleChain merkleChain;
        private volatile boolean running = false;

        SecureLogLifecycle(SecureLogDoctor doctor, VirtualAsyncAppender appender, SecureLogConfig config, MerkleChain merkleChain) {
            this.doctor = doctor;
            this.appender = appender;
            this.config = config;
            this.merkleChain = merkleChain;
        }

        @Override
        public void start() {
            log.info("Starting SecureHR Logging SDK v8.0.0...");

            // Run diagnostics
            SecureLogDoctor.DiagnosticReport report = doctor.diagnose();

            if (report.hasFailures()) {
                log.warn("Diagnostic failures detected - Consider switching to FALLBACK mode");
            }

            // Restore MerkleChain state if integrity is enabled
            if (config.isIntegrityEnabled()) {
                Path chainStatePath = getMerkleChainStatePath();
                boolean loaded = merkleChain.tryLoadState(chainStatePath);
                if (loaded) {
                    log.info("MerkleChain state restored from: {}", chainStatePath);
                } else {
                    log.info("MerkleChain starting with genesis state (no previous state found)");
                }

                // Log distributed deployment warning
                log.warn("IMPORTANT: MerkleChain provides per-instance integrity only. " +
                        "In distributed deployments, each instance maintains its own chain. " +
                        "Consider using a centralized integrity service for cross-instance verification.");
            }

            // Start appender
            appender.start();

            running = true;
            log.info("SecureHR Logging SDK started successfully in {} mode", config.getMode());
        }

        @Override
        public void stop() {
            log.info("Stopping SecureHR Logging SDK...");

            // Stop appender gracefully
            appender.stop();

            // Persist MerkleChain state if integrity is enabled
            if (config.isIntegrityEnabled()) {
                Path chainStatePath = getMerkleChainStatePath();
                try {
                    // Ensure parent directory exists
                    Path parentDir = chainStatePath.getParent();
                    if (parentDir != null && !Files.exists(parentDir)) {
                        Files.createDirectories(parentDir);
                    }

                    merkleChain.saveState(chainStatePath);
                    log.info("MerkleChain state persisted to: {}", chainStatePath);
                } catch (IOException e) {
                    log.error("Failed to persist MerkleChain state to: {}", chainStatePath, e);
                }
            }

            running = false;
            log.info("SecureHR Logging SDK stopped");
        }

        /**
         * Get the path for MerkleChain state file.
         * Uses fallback directory if configured, otherwise user home.
         */
        private Path getMerkleChainStatePath() {
            String fallbackDir = config.getFallbackDirectory();
            if (fallbackDir != null && !fallbackDir.isBlank()) {
                return Paths.get(fallbackDir, MERKLE_CHAIN_STATE_FILE);
            }
            return Paths.get(System.getProperty("user.home"), MERKLE_CHAIN_STATE_FILE);
        }

        @Override
        public boolean isRunning() {
            return running;
        }

        @Override
        public int getPhase() {
            // Start early in the lifecycle
            return Integer.MIN_VALUE + 100;
        }
    }
}
