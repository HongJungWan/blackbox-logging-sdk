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

    // Jackson ObjectMapper for JSON serialization (thread-safe, reusable)
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<>() {};

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
     *
     * FIX P3 #21: Add input validation for null entry and null message.
     *
     * @param entry the log entry to encrypt
     * @return a new LogEntry with encrypted payload and encrypted DEK
     * @throws EncryptionException if encryption fails or input is invalid
     */
    public LogEntry encrypt(LogEntry entry) {
        // FIX P3 #21: Validate input
        if (entry == null) {
            throw new EncryptionException("Cannot encrypt null entry");
        }
        if (entry.getMessage() == null) {
            throw new EncryptionException("Cannot encrypt entry with null message");
        }

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
     *
     * FIX P0 #1: Move the initial time check INSIDE the lock to prevent TOCTOU race condition.
     * Previously, the volatile dekCreationTime was read BEFORE acquiring the lock, which could
     * allow multiple threads to pass the initial check and queue up for rotation.
     */
    private void rotateDekIfNeeded() {
        rotationLock.lock();
        try {
            long now = System.currentTimeMillis();
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

    /**
     * Best-effort key destruction for crypto-shredding.
     *
     * <h2>JVM Limitation Warning</h2>
     * <p>This method performs best-effort key destruction, but has inherent JVM limitations:</p>
     * <ul>
     *   <li>{@code key.getEncoded()} returns a <em>copy</em> of the key bytes, not the original.
     *       Zeroing this copy does not affect the key material stored inside the SecretKey object.</li>
     *   <li>The actual key material in {@code SecretKeySpec} is stored in a private final byte array
     *       that cannot be directly accessed or zeroed without reflection.</li>
     *   <li>Even with reflection, the JVM may have cached copies of the key in various places.</li>
     * </ul>
     *
     * <h2>Mitigation Strategies</h2>
     * <ul>
     *   <li>The key is dereferenced and will be garbage collected, eventually overwritten</li>
     *   <li>For true crypto-shredding, rely on KMS-managed DEK destruction</li>
     *   <li>The encrypted DEK stored in logs becomes unrecoverable once the KEK is rotated/destroyed in KMS</li>
     *   <li>For high-security requirements, consider using HSM-backed keys or off-heap memory</li>
     * </ul>
     *
     * @param key the secret key to destroy
     */
    private void destroyKey(SecretKey key) {
        if (key == null) {
            return;
        }

        try {
            // Try to use the Destroyable interface if the key supports it
            if (key instanceof javax.security.auth.Destroyable) {
                javax.security.auth.Destroyable destroyable = (javax.security.auth.Destroyable) key;
                if (!destroyable.isDestroyed()) {
                    try {
                        destroyable.destroy();
                        log.debug("Key destroyed via Destroyable interface");
                        return;
                    } catch (javax.security.auth.DestroyFailedException e) {
                        // SecretKeySpec.destroy() throws DestroyFailedException by default
                        // Fall through to best-effort approach
                        log.trace("Destroyable.destroy() failed, using best-effort approach");
                    }
                }
            }

            // Best-effort: zero out the copy of key bytes
            // NOTE: This zeros a copy, not the original key material (see Javadoc above)
            byte[] keyBytes = key.getEncoded();
            if (keyBytes != null) {
                java.util.Arrays.fill(keyBytes, (byte) 0);
            }

            // The key object will be garbage collected and eventually overwritten
            // For stronger guarantees, use KMS key rotation to invalidate encrypted DEKs

        } catch (Exception e) {
            log.warn("Failed to destroy key: {}", e.getMessage());
        }
    }

    /**
     * Serialize payload to JSON string using Jackson.
     */
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
     * Decrypt log entry (for authorized access only).
     *
     * FIX P1 #11: Add validation of encryptedDek field before decryption.
     *
     * @param encryptedEntry the encrypted log entry to decrypt
     * @return a new LogEntry with decrypted payload
     * @throws EncryptionException if decryption fails or encrypted DEK is invalid
     */
    public LogEntry decrypt(LogEntry encryptedEntry) {
        try {
            // FIX P1 #11: Validate encryptedDek before decryption
            String encryptedDekStr = encryptedEntry.getEncryptedDek();
            if (encryptedDekStr == null || encryptedDekStr.isEmpty()) {
                throw new EncryptionException("Missing encrypted DEK");
            }

            // Decrypt DEK with KEK
            byte[] encryptedDek = Base64.getDecoder().decode(encryptedDekStr);

            // FIX P1 #11: Validate minimum length: IV (12 bytes) + encrypted key (32+ bytes) + auth tag (16 bytes) = minimum 60 bytes
            if (encryptedDek.length < 60) {
                throw new EncryptionException("Invalid encrypted DEK: too short (possible corruption)");
            }

            SecretKey dek = decryptDekWithKek(encryptedDek);

            // Decrypt payload with DEK
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

    /**
     * Deserialize JSON string to payload Map using Jackson.
     */
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
