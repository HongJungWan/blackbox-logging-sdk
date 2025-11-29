package io.github.hongjungwan.blackbox.starter;

import io.github.hongjungwan.blackbox.core.appender.VirtualAsyncAppender;
import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.deduplication.SemanticDeduplicator;
import io.github.hongjungwan.blackbox.core.diagnostics.SecureLogDoctor;
import io.github.hongjungwan.blackbox.core.integrity.MerkleChain;
import io.github.hongjungwan.blackbox.core.masking.PiiMasker;
import io.github.hongjungwan.blackbox.core.processor.LogProcessor;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.security.KmsClient;
import io.github.hongjungwan.blackbox.core.serialization.LogSerializer;
import io.github.hongjungwan.blackbox.core.transport.LogTransport;
import lombok.extern.slf4j.Slf4j;
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
    public LogTransport logTransport(SecureLogConfig config, LogSerializer serializer) {
        return new LogTransport(config, serializer);
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
            LogTransport transport
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
            SecureLogConfig config
    ) {
        return new SecureLogLifecycle(doctor, appender, config);
    }

    /**
     * SmartLifecycle implementation for SDK initialization
     */
    static class SecureLogLifecycle implements SmartLifecycle {

        private final SecureLogDoctor doctor;
        private final VirtualAsyncAppender appender;
        private final SecureLogConfig config;
        private volatile boolean running = false;

        SecureLogLifecycle(SecureLogDoctor doctor, VirtualAsyncAppender appender, SecureLogConfig config) {
            this.doctor = doctor;
            this.appender = appender;
            this.config = config;
        }

        @Override
        public void start() {
            log.info("Starting SecureHR Logging SDK v8.0.0...");

            // Run diagnostics
            SecureLogDoctor.DiagnosticReport report = doctor.diagnose();

            if (report.hasFailures()) {
                log.warn("Diagnostic failures detected - Consider switching to FALLBACK mode");
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

            running = false;
            log.info("SecureHR Logging SDK stopped");
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
