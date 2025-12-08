package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import lombok.extern.slf4j.Slf4j;

/**
 * 로그 처리 파이프라인. PII 마스킹 -> 무결성 체인 -> 암호화 -> 직렬화 -> 전송.
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

    /** 로그 엔트리를 전체 파이프라인으로 처리 */
    public void process(LogEntry entry) {
        LogEntry maskedEntry = null;
        try {
            // 1단계: PII 마스킹 (오류 발생 시에도 마스킹된 데이터 사용을 위해 먼저 수행)
            maskedEntry = entry;
            if (config.isPiiMaskingEnabled()) {
                maskedEntry = piiMasker.mask(entry);
            }

            // 2단계: Merkle Chain 무결성
            LogEntry chainedEntry = maskedEntry;
            if (config.isIntegrityEnabled()) {
                chainedEntry = merkleChain.addToChain(maskedEntry);
            }

            // 3단계: Envelope 암호화
            LogEntry encryptedEntry = chainedEntry;
            if (config.isEncryptionEnabled()) {
                encryptedEntry = encryption.encrypt(chainedEntry);
            }

            // 4단계: 직렬화 (Zstd 압축)
            byte[] serialized = serializer.serialize(encryptedEntry);

            // 5단계: 전송 (Kafka 또는 Fallback)
            transport.send(serialized);

        } catch (Exception e) {
            log.error("Error processing log entry", e);
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
     * Fallback 저장소로 직접 전송. 종료 시 버퍼 드레인 불가 시 사용.
     * PII 마스킹 + 암호화 적용 (무결성 체인은 순차 처리 필요하여 생략).
     */
    public void processFallback(LogEntry entry) {
        try {
            LogEntry processedEntry = entry;

            // 1단계: PII 마스킹 (컴플라이언스 필수)
            if (config.isPiiMaskingEnabled()) {
                processedEntry = piiMasker.mask(entry);
            }

            // 2단계: 암호화 (데이터 보호 필수)
            if (config.isEncryptionEnabled()) {
                processedEntry = encryption.encrypt(processedEntry);
            }

            transport.sendToFallback(processedEntry);
        } catch (Exception e) {
            log.error("Failed to process entry to fallback", e);
        }
    }

    /** 대기 중인 작업 플러시 (현재 no-op) */
    public void flush() {
    }
}
