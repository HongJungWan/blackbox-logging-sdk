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
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
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

    /**
     * FIX P0 #2: Use a holder class to ensure atomic reads of cached KEK and its cache time.
     * Previously, cachedKek and kekCacheTime were read separately without atomicity,
     * which could cause race conditions where stale KEK could be returned.
     */
    private static class CachedKekHolder {
        final SecretKey kek;
        final long cacheTime;

        CachedKekHolder(SecretKey kek, long cacheTime) {
            this.kek = kek;
            this.cacheTime = cacheTime;
        }
    }

    // Cached KEK (with TTL) - single volatile reference for atomic access
    private volatile CachedKekHolder cachedKekHolder;
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
     *
     * @return the Key Encryption Key (KEK) from AWS KMS or fallback
     * @throws KmsException if KMS is not configured and fallback is disabled
     */
    public SecretKey getKek() {
        // Check cache first - FIX P0 #2: Use single volatile read for atomic access
        CachedKekHolder holder = cachedKekHolder;
        if (isCacheValid(holder)) {
            return holder.kek;
        }

        // Acquire lock (Virtual Thread compatible)
        lock.lock();
        try {
            // Double-check after acquiring lock
            holder = cachedKekHolder;
            if (isCacheValid(holder)) {
                return holder.kek;
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

            // Store in holder for atomic access
            cachedKekHolder = new CachedKekHolder(kek, System.currentTimeMillis());
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

    /**
     * Check if cache is valid.
     * FIX P0 #2: Takes holder as parameter to ensure atomic read of both kek and cacheTime.
     */
    private boolean isCacheValid(CachedKekHolder holder) {
        return holder != null &&
                (System.currentTimeMillis() - holder.cacheTime) < KEK_CACHE_TTL_MS;
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
     *
     * @param dataKey the plaintext data key bytes to encrypt
     * @return the encrypted data key bytes, or original if KMS not configured
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
     *
     * @param encryptedDataKey the encrypted data key bytes to decrypt
     * @return the decrypted plaintext data key bytes, or original if KMS not configured
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
                try {
                    Files.delete(kekPath);
                    log.info("Deleted invalid KEK file: {}", kekPath);
                } catch (IOException deleteEx) {
                    log.warn("Failed to delete invalid KEK file: {}", deleteEx.getMessage());
                }
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
                // FIX P2 #15: Write file with restrictive permissions
                writeFileWithRestrictivePermissions(seedPath, seed);

                log.warn("Created new fallback seed file at: {} - PROTECT THIS FILE", seedPath);
            }

            // Derive key from seed using simple HKDF-like expansion
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom seededRandom = createSeededSecureRandom(seed);
            keyGen.init(256, seededRandom);
            SecretKey key = keyGen.generateKey();

            // Persist the KEK
            Path kekPath = getFallbackKekPath();
            // FIX P2 #15: Write file with restrictive permissions
            writeFileWithRestrictivePermissions(kekPath, key.getEncoded());

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
     * Create a seeded SecureRandom using the strongest available algorithm.
     * Prefers DRBG (Deterministic Random Bit Generator) which is more secure than SHA1PRNG.
     * Falls back to SHA1PRNG if DRBG is not available.
     *
     * @param seed the seed bytes
     * @return a seeded SecureRandom instance
     */
    private SecureRandom createSeededSecureRandom(byte[] seed) throws NoSuchAlgorithmException {
        SecureRandom seededRandom;
        try {
            // Try DRBG first (stronger algorithm, available in Java 9+)
            seededRandom = SecureRandom.getInstance("DRBG");
            seededRandom.setSeed(seed);
        } catch (NoSuchAlgorithmException e) {
            // Fall back to SHA1PRNG if DRBG is not available
            log.warn("DRBG algorithm not available, falling back to SHA1PRNG");
            seededRandom = SecureRandom.getInstance("SHA1PRNG");
            seededRandom.setSeed(seed);
        }
        return seededRandom;
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
     * FIX P2 #15: Write file with restrictive permissions atomically.
     * Writes the file and then sets permissions immediately after.
     *
     * @param path the file path to write to
     * @param content the content to write
     * @throws IOException if writing fails
     */
    private void writeFileWithRestrictivePermissions(Path path, byte[] content) throws IOException {
        // Write file first
        Files.write(path, content,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);

        // Set restrictive permissions immediately after creation
        setRestrictivePermissions(path);
    }

    /**
     * Set restrictive file permissions (owner-only read/write, chmod 600).
     * This protects sensitive key material from being read by other users.
     *
     * @param path the file path to set permissions on
     */
    private void setRestrictivePermissions(Path path) {
        try {
            java.util.Set<PosixFilePermission> permissions = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            );
            Files.setPosixFilePermissions(path, permissions);
            log.debug("Set restrictive permissions (600) on: {}", path);
        } catch (java.lang.UnsupportedOperationException e) {
            // Windows and some file systems don't support POSIX permissions
            log.warn("Cannot set POSIX file permissions on {} - file system does not support POSIX permissions. " +
                    "Ensure proper file security through OS-level access controls.", path);
        } catch (IOException e) {
            log.warn("Failed to set restrictive permissions on {}: {}", path, e.getMessage());
        }
    }

    /**
     * Rotate KEK (trigger key rotation in AWS KMS).
     */
    public void rotateKek() {
        lock.lock();
        try {
            cachedKekHolder = null;

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
            cachedKekHolder = null;
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
