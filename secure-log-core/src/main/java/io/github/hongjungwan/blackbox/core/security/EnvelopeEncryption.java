package io.github.hongjungwan.blackbox.core.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 봉투 암호화(DEK + KEK) 구현. DEK 1시간 자동 갱신, Crypto-Shredding 지원.
 */
@Slf4j
public class EnvelopeEncryption {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int KEY_SIZE = 256;

    // JSON 직렬화용 ObjectMapper (스레드 안전, 재사용)
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<>() {};

    private final SecureLogConfig config;
    private final KmsClient kmsClient;
    private final SecureRandom secureRandom;
    private final ReentrantLock rotationLock = new ReentrantLock();

    // 현재 DEK (1시간마다 갱신)
    private volatile SecretKey currentDek;
    private volatile long dekCreationTime;
    private static final long DEK_ROTATION_INTERVAL_MS = 3600_000;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public EnvelopeEncryption(SecureLogConfig config, KmsClient kmsClient) {
        this.config = config;
        this.kmsClient = kmsClient;
        this.secureRandom = new SecureRandom();
        this.currentDek = generateDek();
        this.dekCreationTime = System.currentTimeMillis();
    }

    /**
     * 로그 엔트리 암호화. payload를 DEK로 암호화하고, DEK는 KEK로 암호화.
     */
    public LogEntry encrypt(LogEntry entry) {
        if (entry == null) {
            throw new EncryptionException("Cannot encrypt null entry");
        }
        if (entry.getMessage() == null) {
            throw new EncryptionException("Cannot encrypt entry with null message");
        }

        try {
            rotateDekIfNeeded();

            SecretKey dek = currentDek;
            String payloadJson = serializePayload(entry.getPayload());
            byte[] encryptedPayload = encryptWithDek(payloadJson.getBytes(), dek);
            byte[] encryptedDek = encryptDekWithKek(dek);

            return LogEntry.builder()
                    .timestamp(entry.getTimestamp())
                    .level(entry.getLevel())
                    .traceId(entry.getTraceId())
                    .spanId(entry.getSpanId())
                    .context(entry.getContext())
                    .message(entry.getMessage())
                    .payload(Map.of("encrypted", Base64.getEncoder().encodeToString(encryptedPayload)))
                    .integrity(entry.getIntegrity())
                    .encryptedDek(Base64.getEncoder().encodeToString(encryptedDek))
                    .repeatCount(entry.getRepeatCount())
                    .throwable(entry.getThrowable())
                    .build();

        } catch (Exception e) {
            log.error("Encryption failed", e);
            throw new EncryptionException("Failed to encrypt log entry", e);
        }
    }

    /** AES-GCM으로 데이터 암호화. IV + 암호문 반환. */
    private byte[] encryptWithDek(byte[] data, SecretKey dek) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, dek, gcmSpec);

        byte[] ciphertext = cipher.doFinal(data);

        byte[] result = new byte[GCM_IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
        System.arraycopy(ciphertext, 0, result, GCM_IV_LENGTH, ciphertext.length);

        return result;
    }

    /** KEK로 DEK 암호화. */
    private byte[] encryptDekWithKek(SecretKey dek) throws Exception {
        SecretKey kek = kmsClient.getKek();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, kek, gcmSpec);

        byte[] encryptedDek = cipher.doFinal(dek.getEncoded());

        byte[] result = new byte[GCM_IV_LENGTH + encryptedDek.length];
        System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedDek, 0, result, GCM_IV_LENGTH, encryptedDek.length);

        return result;
    }

    /** SecureRandom으로 새 DEK 생성. */
    private SecretKey generateDek() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE, secureRandom);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new EncryptionException("Failed to generate DEK", e);
        }
    }

    /**
     * DEK 갱신 필요 시 수행. ReentrantLock 사용 (Virtual Thread 호환).
     * TOCTOU 방지를 위해 시간 체크를 락 내부에서 수행.
     */
    private void rotateDekIfNeeded() {
        rotationLock.lock();
        try {
            long now = System.currentTimeMillis();
            if (now - dekCreationTime > DEK_ROTATION_INTERVAL_MS) {
                SecretKey oldDek = currentDek;
                currentDek = generateDek();
                dekCreationTime = now;
                destroyKey(oldDek);

                log.info("DEK rotated successfully");
            }
        } finally {
            rotationLock.unlock();
        }
    }

    /**
     * 키 삭제 (best-effort). JVM 한계로 완전 삭제 불가.
     * 진정한 Crypto-Shredding은 KMS의 KEK 삭제에 의존.
     */
    private void destroyKey(SecretKey key) {
        if (key == null) {
            return;
        }

        try {
            if (key instanceof javax.security.auth.Destroyable) {
                javax.security.auth.Destroyable destroyable = (javax.security.auth.Destroyable) key;
                if (!destroyable.isDestroyed()) {
                    try {
                        destroyable.destroy();
                        log.debug("Key destroyed via Destroyable interface");
                        return;
                    } catch (javax.security.auth.DestroyFailedException e) {
                        log.trace("Destroyable.destroy() failed, using best-effort approach");
                    }
                }
            }

            // 키 바이트 복사본 제로화 (best-effort, 원본 불변)
            byte[] keyBytes = key.getEncoded();
            if (keyBytes != null) {
                java.util.Arrays.fill(keyBytes, (byte) 0);
            }

        } catch (Exception e) {
            log.warn("Failed to destroy key: {}", e.getMessage());
        }
    }

    /** payload를 JSON 문자열로 직렬화. */
    private String serializePayload(Map<String, Object> payload) {
        if (payload == null || payload.isEmpty()) {
            return "{}";
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize payload to JSON", e);
            throw new EncryptionException("Failed to serialize payload", e);
        }
    }

    /**
     * 암호화된 로그 엔트리 복호화. 권한 있는 접근만 허용.
     */
    public LogEntry decrypt(LogEntry encryptedEntry) {
        try {
            String encryptedDekStr = encryptedEntry.getEncryptedDek();
            if (encryptedDekStr == null || encryptedDekStr.isEmpty()) {
                throw new EncryptionException("Missing encrypted DEK");
            }

            byte[] encryptedDek = Base64.getDecoder().decode(encryptedDekStr);

            // IV(12) + 암호화 키(32+) + 태그(16) = 60 bytes
            if (encryptedDek.length < 60) {
                throw new EncryptionException("Invalid encrypted DEK: too short (possible corruption)");
            }

            SecretKey dek = decryptDekWithKek(encryptedDek);

            Map<String, Object> payload = encryptedEntry.getPayload();
            if (payload == null) {
                throw new EncryptionException("Encrypted entry has no payload", null);
            }
            Object encryptedObj = payload.get("encrypted");
            if (encryptedObj == null) {
                throw new EncryptionException("Encrypted payload missing 'encrypted' field", null);
            }
            String encryptedPayloadStr = (String) encryptedObj;
            byte[] encryptedPayload = Base64.getDecoder().decode(encryptedPayloadStr);
            byte[] decryptedPayload = decryptWithDek(encryptedPayload, dek);

            return LogEntry.builder()
                    .timestamp(encryptedEntry.getTimestamp())
                    .level(encryptedEntry.getLevel())
                    .traceId(encryptedEntry.getTraceId())
                    .spanId(encryptedEntry.getSpanId())
                    .context(encryptedEntry.getContext())
                    .message(encryptedEntry.getMessage())
                    .payload(deserializePayload(new String(decryptedPayload)))
                    .integrity(encryptedEntry.getIntegrity())
                    .repeatCount(encryptedEntry.getRepeatCount())
                    .throwable(encryptedEntry.getThrowable())
                    .build();

        } catch (Exception e) {
            log.error("Decryption failed", e);
            throw new EncryptionException("Failed to decrypt log entry", e);
        }
    }

    /** KEK로 암호화된 DEK 복호화. */
    private SecretKey decryptDekWithKek(byte[] encryptedDek) throws Exception {
        SecretKey kek = kmsClient.getKek();

        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[encryptedDek.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedDek, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedDek, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, kek, gcmSpec);

        byte[] dekBytes = cipher.doFinal(ciphertext);
        return new SecretKeySpec(dekBytes, ALGORITHM);
    }

    /** DEK로 데이터 복호화. */
    private byte[] decryptWithDek(byte[] encryptedData, SecretKey dek) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[encryptedData.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedData, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, dek, gcmSpec);

        return cipher.doFinal(ciphertext);
    }

    /** JSON 문자열을 payload Map으로 역직렬화. */
    private Map<String, Object> deserializePayload(String json) {
        if (json == null || json.isBlank() || "{}".equals(json)) {
            return Map.of();
        }
        try {
            return OBJECT_MAPPER.readValue(json, MAP_TYPE_REF);
        } catch (JsonProcessingException e) {
            log.error("Failed to deserialize payload from JSON: {}", json, e);
            throw new EncryptionException("Failed to deserialize payload", e);
        }
    }

    public static class EncryptionException extends RuntimeException {
        public EncryptionException(String message) {
            super(message);
        }

        public EncryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
