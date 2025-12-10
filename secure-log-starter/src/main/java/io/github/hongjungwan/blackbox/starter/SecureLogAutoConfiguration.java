package io.github.hongjungwan.blackbox.starter;

import io.github.hongjungwan.blackbox.api.SecureLogger;
import io.github.hongjungwan.blackbox.api.SecureLoggerFactory;
import io.github.hongjungwan.blackbox.core.internal.VirtualAsyncAppender;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.internal.SecureLogDoctor;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import io.github.hongjungwan.blackbox.core.security.AnnotationMaskingProcessor;
import io.github.hongjungwan.blackbox.core.security.EmergencyEncryptor;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.internal.LogProcessor;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.security.LocalKeyManager;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.internal.ResilientLogTransport;
import io.github.hongjungwan.blackbox.starter.aop.AuditContextAspect;
import io.github.hongjungwan.blackbox.starter.aop.AuditUserExtractor;
import io.github.hongjungwan.blackbox.starter.aop.SecurityContextUserExtractor;
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
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * SecureHR Logging SDK Spring Boot 자동 설정.
 */
@AutoConfiguration
@EnableConfigurationProperties(SecureLogProperties.class)
@ConditionalOnProperty(prefix = "secure-hr.logging", name = "enabled", havingValue = "true", matchIfMissing = true)
@Import(SecureLogAutoConfiguration.AuditContextConfiguration.class)
@Slf4j
public class SecureLogAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecureLogConfig secureLogConfig(SecureLogProperties properties) {
        return SecureLogConfig.builder()
                .mode(properties.getMode())
                .bufferSize(properties.getBufferSize())
                .consumerThreads(properties.getConsumerThreads())
                .piiMaskingEnabled(properties.getPiiMasking().isEnabled())
                .piiPatterns(properties.getPiiMasking().getPatterns())
                .encryptionEnabled(properties.getSecurity().isEncryptionEnabled())
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
    public AnnotationMaskingProcessor annotationMaskingProcessor(SecureLogProperties properties) {
        AnnotationMaskingProcessor processor = new AnnotationMaskingProcessor();

        // 비상 모드 설정
        String emergencyPublicKey = properties.getSecurity().getEmergencyPublicKey();
        if (emergencyPublicKey != null && !emergencyPublicKey.isBlank()) {
            try {
                EmergencyEncryptor encryptor = EmergencyEncryptor.fromBase64(emergencyPublicKey);
                processor.setEmergencyEncryptor(encryptor);
                log.info("Emergency mode encryption configured for AnnotationMaskingProcessor");
            } catch (Exception e) {
                log.warn("Failed to configure emergency encryption: {}", e.getMessage());
            }
        }

        return processor;
    }

    @Bean
    @ConditionalOnMissingBean
    public SecureLogger secureLogger() {
        return SecureLoggerFactory.getLogger(SecureLogAutoConfiguration.class);
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    public LocalKeyManager localKeyManager(SecureLogConfig config) {
        return new LocalKeyManager(config);
    }

    @Bean
    @ConditionalOnMissingBean
    public EnvelopeEncryption envelopeEncryption(SecureLogConfig config, LocalKeyManager keyManager) {
        return new EnvelopeEncryption(config, keyManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public MerkleChain merkleChain() {
        return new MerkleChain();
    }

    @Bean
    @ConditionalOnMissingBean
    public LogSerializer logSerializer() {
        return new LogSerializer();
    }

    @Bean(destroyMethod = "close")
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
            LogSerializer serializer,
            ResilientLogTransport transport
    ) {
        return new LogProcessor(config, piiMasker, encryption, merkleChain, serializer, transport);
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
     * SDK 초기화 및 종료를 관리하는 SmartLifecycle 구현체.
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

            SecureLogDoctor.DiagnosticReport report = doctor.diagnose();

            if (report.hasFailures()) {
                log.warn("Diagnostic failures detected - Consider switching to FALLBACK mode");
            }

            if (config.isIntegrityEnabled()) {
                Path chainStatePath = getMerkleChainStatePath();
                boolean loaded = merkleChain.tryLoadState(chainStatePath);
                if (loaded) {
                    log.info("MerkleChain state restored from: {}", chainStatePath);
                } else {
                    log.info("MerkleChain starting with genesis state (no previous state found)");
                }

                log.warn("IMPORTANT: MerkleChain provides per-instance integrity only. " +
                        "In distributed deployments, each instance maintains its own chain. " +
                        "Consider using a centralized integrity service for cross-instance verification.");
            }

            try {
                appender.start();
                log.info("VirtualAsyncAppender started successfully");
            } catch (Exception e) {
                log.error("Failed to start VirtualAsyncAppender", e);
                throw new IllegalStateException("SDK initialization failed", e);
            }

            running = true;
            log.info("SecureHR Logging SDK started successfully in {} mode", config.getMode());
        }

        @Override
        public void stop() {
            log.info("Stopping SecureHR Logging SDK...");

            appender.stop();

            if (config.isIntegrityEnabled()) {
                Path chainStatePath = getMerkleChainStatePath();
                try {
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
            return Integer.MIN_VALUE + 100;
        }
    }

    /**
     * AOP 기반 @AuditContext 지원 설정.
     * secure-hr.logging.audit.enabled=true 시 활성화 (기본값: true)
     */
    @Configuration
    @ConditionalOnProperty(prefix = "secure-hr.logging.audit", name = "enabled", havingValue = "true", matchIfMissing = true)
    static class AuditContextConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public AuditUserExtractor auditUserExtractor() {
            return new SecurityContextUserExtractor();
        }

        @Bean
        @ConditionalOnMissingBean
        public AuditContextAspect auditContextAspect(SecureLogger secureLogger, AuditUserExtractor userExtractor) {
            log.info("AuditContextAspect enabled - @AuditContext annotations will be processed");
            return new AuditContextAspect(secureLogger, userExtractor);
        }
    }
}
