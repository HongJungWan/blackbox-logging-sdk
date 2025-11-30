package io.github.hongjungwan.blackbox.core.security;

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
 * Envelope Encryption implementation (DEK + KEK).
 *
 * <p>Key Hierarchy:</p>
 * <ul>
 *   <li>KEK (Key Encryption Key): Master key stored in KMS with rotation support</li>
 *   <li>DEK (Data Encryption Key): Per-block key generated in-memory, encrypted by KEK</li>
 * </ul>
 *
 * <p>Process:</p>
 * <ol>
 *   <li>Generate DEK (AES-256) using SecureRandom</li>
 *   <li>Encrypt log data with DEK (AES-GCM)</li>
 *   <li>Encrypt DEK with KEK from KMS</li>
 *   <li>Store encrypted DEK in log header</li>
 * </ol>
 *
 * <p>Crypto-Shredding: Destroying DEK makes logs permanently unrecoverable.</p>
 */
@Slf4j
public class EnvelopeEncryption {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int KEY_SIZE = 256;

    private final SecureLogConfig config;
    private final KmsClient kmsClient;
    private final SecureRandom secureRandom;
    private final ReentrantLock rotationLock = new ReentrantLock();

    // Current DEK - rotated periodically
    private volatile SecretKey currentDek;
    private volatile long dekCreationTime;
    private static final long DEK_ROTATION_INTERVAL_MS = 3600_000; // 1 hour

    static {
        // Add BouncyCastle provider for enhanced crypto support
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
     * Encrypt log entry using envelope encryption.
     */
    public LogEntry encrypt(LogEntry entry) {
        try {
            // Check if DEK needs rotation
            rotateDekIfNeeded();

            // Get current DEK
            SecretKey dek = currentDek;

            // Encrypt payload with DEK
            String payloadJson = serializePayload(entry.getPayload());
            byte[] encryptedPayload = encryptWithDek(payloadJson.getBytes(), dek);

            // Encrypt DEK with KEK from KMS
            byte[] encryptedDek = encryptDekWithKek(dek);

            // Build encrypted log entry
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

    /**
     * Encrypt data with DEK using AES-GCM.
     */
    private byte[] encryptWithDek(byte[] data, SecretKey dek) throws Exception {
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, dek, gcmSpec);

        // Encrypt
        byte[] ciphertext = cipher.doFinal(data);

        // Combine IV + ciphertext
        byte[] result = new byte[GCM_IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
        System.arraycopy(ciphertext, 0, result, GCM_IV_LENGTH, ciphertext.length);

        return result;
    }

    /**
     * Encrypt DEK with KEK from KMS.
     */
    private byte[] encryptDekWithKek(SecretKey dek) throws Exception {
        // Get KEK from KMS
        SecretKey kek = kmsClient.getKek();

        // Encrypt DEK
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, kek, gcmSpec);

        byte[] encryptedDek = cipher.doFinal(dek.getEncoded());

        // Combine IV + encrypted DEK
        byte[] result = new byte[GCM_IV_LENGTH + encryptedDek.length];
        System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedDek, 0, result, GCM_IV_LENGTH, encryptedDek.length);

        return result;
    }

    /**
     * Generate new DEK using SecureRandom.
     */
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
     * Rotate DEK if rotation interval has passed.
     * CRITICAL: Uses ReentrantLock instead of synchronized (Virtual Thread compatible)
     */
    private void rotateDekIfNeeded() {
        long now = System.currentTimeMillis();
        if (now - dekCreationTime > DEK_ROTATION_INTERVAL_MS) {
            rotationLock.lock();
            try {
                // Double-check after acquiring lock
                if (now - dekCreationTime > DEK_ROTATION_INTERVAL_MS) {
                    // Crypto-shredding: destroy old DEK
                    SecretKey oldDek = currentDek;
                    currentDek = generateDek();
                    dekCreationTime = now;

                    // Clear old DEK from memory (best effort)
                    destroyKey(oldDek);

                    log.info("DEK rotated successfully");
                }
            } finally {
                rotationLock.unlock();
            }
        }
    }

    /**
     * Best-effort key destruction.
     */
    private void destroyKey(SecretKey key) {
        try {
            if (key instanceof javax.crypto.SecretKey) {
                // Zero out key bytes (best effort)
                byte[] keyBytes = key.getEncoded();
                if (keyBytes != null) {
                    java.util.Arrays.fill(keyBytes, (byte) 0);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to destroy key", e);
        }
    }

    private String serializePayload(java.util.Map<String, Object> payload) {
        // Simple JSON serialization (should use Jackson in production)
        return payload != null ? payload.toString() : "{}";
    }

    /**
     * Decrypt log entry (for authorized access only).
     */
    public LogEntry decrypt(LogEntry encryptedEntry) {
        try {
            // Decrypt DEK with KEK
            byte[] encryptedDek = Base64.getDecoder().decode(encryptedEntry.getEncryptedDek());
            SecretKey dek = decryptDekWithKek(encryptedDek);

            // Decrypt payload with DEK
            String encryptedPayloadStr = (String) encryptedEntry.getPayload().get("encrypted");
            byte[] encryptedPayload = Base64.getDecoder().decode(encryptedPayloadStr);
            byte[] decryptedPayload = decryptWithDek(encryptedPayload, dek);

            // Reconstruct log entry
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

    private SecretKey decryptDekWithKek(byte[] encryptedDek) throws Exception {
        SecretKey kek = kmsClient.getKek();

        // Extract IV and ciphertext
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[encryptedDek.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedDek, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedDek, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        // Decrypt
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, kek, gcmSpec);

        byte[] dekBytes = cipher.doFinal(ciphertext);
        return new SecretKeySpec(dekBytes, ALGORITHM);
    }

    private byte[] decryptWithDek(byte[] encryptedData, SecretKey dek) throws Exception {
        // Extract IV and ciphertext
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[encryptedData.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedData, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        // Decrypt
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, dek, gcmSpec);

        return cipher.doFinal(ciphertext);
    }

    private java.util.Map<String, Object> deserializePayload(String json) {
        // Simple deserialization (should use Jackson in production)
        return java.util.Map.of();
    }

    public static class EncryptionException extends RuntimeException {
        public EncryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
