package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.model.*;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantLock;

/**
 * AWS KMS Client for Key Management.
 *
 * <p>Retrieves KEK (Key Encryption Key) from AWS KMS.</p>
 *
 * <p>CRITICAL: Uses ReentrantLock instead of synchronized (Virtual Thread compatible)</p>
 */
@Slf4j
public class KmsClient implements AutoCloseable {

    private final SecureLogConfig config;
    private final software.amazon.awssdk.services.kms.KmsClient awsKmsClient;
    private final ReentrantLock lock = new ReentrantLock();
    private final boolean isAwsKmsConfigured;

    // Cached KEK (with TTL)
    private volatile SecretKey cachedKek;
    private volatile long kekCacheTime;
    private static final long KEK_CACHE_TTL_MS = 300_000; // 5 minutes

    // Fallback KEK persistence
    private static final String FALLBACK_KEK_FILENAME = ".secure-hr-fallback-kek";
    private static final String FALLBACK_SEED_FILENAME = ".secure-hr-fallback-seed";
    private volatile SecretKey persistedFallbackKek;

    public KmsClient(SecureLogConfig config) {
        this.config = config;
        this.isAwsKmsConfigured = config.getKmsKeyId() != null && !config.getKmsKeyId().isBlank();

        if (isAwsKmsConfigured) {
            this.awsKmsClient = createAwsKmsClient(config);
            log.info("AWS KMS client initialized: region={}, keyId={}",
                    config.getKmsRegion(), maskKeyId(config.getKmsKeyId()));
        } else {
            this.awsKmsClient = null;
            log.warn("AWS KMS not configured. Using fallback mode (NOT secure for production)");
        }
    }

    private software.amazon.awssdk.services.kms.KmsClient createAwsKmsClient(SecureLogConfig config) {
        software.amazon.awssdk.services.kms.KmsClientBuilder builder =
                software.amazon.awssdk.services.kms.KmsClient.builder()
                .region(Region.of(config.getKmsRegion()))
                .httpClientBuilder(UrlConnectionHttpClient.builder()
                        .connectionTimeout(Duration.ofMillis(config.getKmsTimeoutMs()))
                        .socketTimeout(Duration.ofMillis(config.getKmsTimeoutMs())));

        // Handle cross-account access with role assumption
        if (config.getKmsRoleArn() != null && !config.getKmsRoleArn().isBlank()) {
            builder.credentialsProvider(createAssumedRoleCredentials(config));
        }

        return builder.build();
    }

    private StaticCredentialsProvider createAssumedRoleCredentials(SecureLogConfig config) {
        try (StsClient stsClient = StsClient.builder()
                .region(Region.of(config.getKmsRegion()))
                .build()) {

            AssumeRoleResponse response = stsClient.assumeRole(AssumeRoleRequest.builder()
                    .roleArn(config.getKmsRoleArn())
                    .roleSessionName("SecureHRLoggingSDK")
                    .durationSeconds(3600)
                    .build());

            return StaticCredentialsProvider.create(
                    AwsSessionCredentials.create(
                            response.credentials().accessKeyId(),
                            response.credentials().secretAccessKey(),
                            response.credentials().sessionToken()));
        }
    }

    /**
     * Get KEK from KMS (with caching).
     * Uses ReentrantLock instead of synchronized for Virtual Thread compatibility.
     */
    public SecretKey getKek() {
        // Check cache first
        if (isCacheValid()) {
            return cachedKek;
        }

        // Acquire lock (Virtual Thread compatible)
        lock.lock();
        try {
            // Double-check after acquiring lock
            if (isCacheValid()) {
                return cachedKek;
            }

            SecretKey kek;
            if (isAwsKmsConfigured) {
                kek = fetchKekFromAwsKms();
            } else if (config.isKmsFallbackEnabled()) {
                log.warn("Using fallback embedded KEK - THIS IS NOT SECURE FOR PRODUCTION");
                kek = generateFallbackKek();
            } else {
                throw new KmsException("AWS KMS not configured and fallback is disabled");
            }

            cachedKek = kek;
            kekCacheTime = System.currentTimeMillis();
            return kek;

        } catch (KmsException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to fetch KEK from AWS KMS", e);

            if (config.isKmsFallbackEnabled()) {
                log.warn("Falling back to embedded KEK - THIS IS NOT SECURE FOR PRODUCTION");
                return generateFallbackKek();
            }
            throw new KmsException("Failed to fetch KEK from KMS", e);

        } finally {
            lock.unlock();
        }
    }

    private boolean isCacheValid() {
        return cachedKek != null &&
                (System.currentTimeMillis() - kekCacheTime) < KEK_CACHE_TTL_MS;
    }

    /**
     * Fetch KEK from AWS KMS using GenerateDataKey.
     */
    private SecretKey fetchKekFromAwsKms() {
        GenerateDataKeyResponse response = awsKmsClient.generateDataKey(
                GenerateDataKeyRequest.builder()
                        .keyId(config.getKmsKeyId())
                        .keySpec(DataKeySpec.AES_256)
                        .build());

        byte[] plaintext = response.plaintext().asByteArray();

        try {
            SecretKey key = new SecretKeySpec(plaintext, "AES");
            log.debug("Successfully generated data key from AWS KMS");
            return key;
        } finally {
            // Zero out plaintext array for security
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /**
     * Encrypt a data key using AWS KMS.
     */
    public byte[] encryptDataKey(byte[] dataKey) {
        if (!isAwsKmsConfigured) {
            log.warn("Skipping KMS encryption - not configured");
            return dataKey;
        }

        EncryptResponse response = awsKmsClient.encrypt(
                EncryptRequest.builder()
                        .keyId(config.getKmsKeyId())
                        .plaintext(SdkBytes.fromByteArray(dataKey))
                        .build());

        return response.ciphertextBlob().asByteArray();
    }

    /**
     * Decrypt a data key using AWS KMS.
     */
    public byte[] decryptDataKey(byte[] encryptedDataKey) {
        if (!isAwsKmsConfigured) {
            log.warn("Skipping KMS decryption - not configured");
            return encryptedDataKey;
        }

        DecryptResponse response = awsKmsClient.decrypt(
                DecryptRequest.builder()
                        .keyId(config.getKmsKeyId())
                        .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey))
                        .build());

        return response.plaintext().asByteArray();
    }

    /**
     * Generate or load fallback KEK for development/testing.
     * WARNING: NOT secure for production use.
     *
     * This implementation persists the fallback KEK to prevent data loss across restarts.
     * On startup, it tries to load an existing KEK before generating a new one.
     */
    private SecretKey generateFallbackKek() {
        // Return cached fallback KEK if available
        if (persistedFallbackKek != null) {
            return persistedFallbackKek;
        }

        lock.lock();
        try {
            // Double-check after acquiring lock
            if (persistedFallbackKek != null) {
                return persistedFallbackKek;
            }

            // Try to load existing fallback KEK from file
            SecretKey loadedKek = loadFallbackKek();
            if (loadedKek != null) {
                persistedFallbackKek = loadedKek;
                log.warn("Loaded existing fallback KEK from file - THIS IS NOT SECURE FOR PRODUCTION");
                return persistedFallbackKek;
            }

            // Generate new fallback KEK using deterministic key derivation from seed
            SecretKey newKek = generateAndPersistFallbackKek();
            persistedFallbackKek = newKek;
            return persistedFallbackKek;

        } finally {
            lock.unlock();
        }
    }

    /**
     * Load fallback KEK from persistent storage.
     */
    private SecretKey loadFallbackKek() {
        Path kekPath = getFallbackKekPath();
        if (!Files.exists(kekPath)) {
            return null;
        }

        try {
            byte[] keyBytes = Files.readAllBytes(kekPath);
            if (keyBytes.length != 32) { // AES-256 = 32 bytes
                log.warn("Invalid fallback KEK file size, will regenerate");
                return null;
            }
            return new SecretKeySpec(keyBytes, "AES");
        } catch (IOException e) {
            log.warn("Failed to load fallback KEK from file: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Generate new fallback KEK and persist it to file.
     */
    private SecretKey generateAndPersistFallbackKek() {
        try {
            // Try to use seed-based derivation for consistency
            Path seedPath = getFallbackSeedPath();
            byte[] seed;

            if (Files.exists(seedPath)) {
                seed = Files.readAllBytes(seedPath);
            } else {
                // Generate new seed
                seed = new byte[32];
                new SecureRandom().nextBytes(seed);
                Files.write(seedPath, seed,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING);
                log.warn("Created new fallback seed file at: {} - PROTECT THIS FILE", seedPath);
            }

            // Derive key from seed using simple HKDF-like expansion
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom seededRandom = SecureRandom.getInstance("SHA1PRNG");
            seededRandom.setSeed(seed);
            keyGen.init(256, seededRandom);
            SecretKey key = keyGen.generateKey();

            // Persist the KEK
            Path kekPath = getFallbackKekPath();
            Files.write(kekPath, key.getEncoded(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);

            log.warn("Generated and persisted new fallback KEK to: {} - THIS IS NOT SECURE FOR PRODUCTION", kekPath);
            return key;

        } catch (NoSuchAlgorithmException | IOException e) {
            // Last resort: generate ephemeral key (will cause data loss on restart)
            log.error("Failed to persist fallback KEK, using ephemeral key - DATA LOSS ON RESTART", e);
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                return keyGen.generateKey();
            } catch (NoSuchAlgorithmException ex) {
                throw new KmsException("Failed to generate fallback KEK", ex);
            }
        }
    }

    /**
     * Get path for fallback KEK file.
     */
    private Path getFallbackKekPath() {
        String fallbackDir = config.getFallbackDirectory();
        if (fallbackDir != null && !fallbackDir.isBlank()) {
            return Paths.get(fallbackDir, FALLBACK_KEK_FILENAME);
        }
        return Paths.get(System.getProperty("user.home"), FALLBACK_KEK_FILENAME);
    }

    /**
     * Get path for fallback seed file.
     */
    private Path getFallbackSeedPath() {
        String fallbackDir = config.getFallbackDirectory();
        if (fallbackDir != null && !fallbackDir.isBlank()) {
            return Paths.get(fallbackDir, FALLBACK_SEED_FILENAME);
        }
        return Paths.get(System.getProperty("user.home"), FALLBACK_SEED_FILENAME);
    }

    /**
     * Rotate KEK (trigger key rotation in AWS KMS).
     */
    public void rotateKek() {
        lock.lock();
        try {
            cachedKek = null;
            kekCacheTime = 0;

            if (isAwsKmsConfigured) {
                log.info("KEK cache invalidated. Next getKek() will fetch fresh key from AWS KMS");
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Invalidate the cached KEK.
     */
    public void invalidateCache() {
        lock.lock();
        try {
            cachedKek = null;
            kekCacheTime = 0;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Check if AWS KMS is configured.
     */
    public boolean isAwsKmsConfigured() {
        return isAwsKmsConfigured;
    }

    private String maskKeyId(String keyId) {
        if (keyId == null || keyId.length() < 8) {
            return "***";
        }
        return keyId.substring(0, 4) + "..." + keyId.substring(keyId.length() - 4);
    }

    @Override
    public void close() {
        if (awsKmsClient != null) {
            try {
                awsKmsClient.close();
                log.info("AWS KMS client closed");
            } catch (Exception e) {
                log.warn("Error closing AWS KMS client: {}", e.getMessage());
            }
        }
    }

    /**
     * Exception thrown when KMS operation fails.
     */
    public static class KmsException extends RuntimeException {
        public KmsException(String message) {
            super(message);
        }

        public KmsException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
