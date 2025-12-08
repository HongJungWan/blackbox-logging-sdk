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
 * AWS KMS 클라이언트. KEK 조회 및 캐싱, Fallback 지원. ReentrantLock 사용 (Virtual Thread 호환).
 */
@Slf4j
public class KmsClient implements AutoCloseable {

    private final SecureLogConfig config;
    private final software.amazon.awssdk.services.kms.KmsClient awsKmsClient;
    private final ReentrantLock lock = new ReentrantLock();
    private final boolean isAwsKmsConfigured;

    /** KEK와 캐시 시간을 원자적으로 관리하는 홀더 클래스. */
    private static class CachedKekHolder {
        final SecretKey kek;
        final long cacheTime;

        CachedKekHolder(SecretKey kek, long cacheTime) {
            this.kek = kek;
            this.cacheTime = cacheTime;
        }
    }

    // 캐싱된 KEK (TTL 5분)
    private volatile CachedKekHolder cachedKekHolder;
    private static final long KEK_CACHE_TTL_MS = 300_000;

    // Fallback KEK 파일 경로
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

        // 크로스 계정 접근을 위한 역할 위임
        if (config.getKmsRoleArn() != null && !config.getKmsRoleArn().isBlank()) {
            builder.credentialsProvider(createAssumedRoleCredentials(config));
        }

        return builder.build();
    }

    /** STS AssumeRole로 임시 자격 증명 생성. */
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
     * KMS에서 KEK 조회 (캐싱 적용). 캐시 유효하면 즉시 반환.
     */
    public SecretKey getKek() {
        CachedKekHolder holder = cachedKekHolder;
        if (isCacheValid(holder)) {
            return holder.kek;
        }

        lock.lock();
        try {
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

    /** 캐시 유효성 검사. */
    private boolean isCacheValid(CachedKekHolder holder) {
        return holder != null &&
                (System.currentTimeMillis() - holder.cacheTime) < KEK_CACHE_TTL_MS;
    }

    /** AWS KMS GenerateDataKey API로 KEK 조회. */
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
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    /** AWS KMS로 데이터 키 암호화. */
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

    /** AWS KMS로 데이터 키 복호화. */
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
     * Fallback KEK 생성 또는 로드. 개발/테스트용 - 프로덕션 사용 금지.
     * 재시작 시 데이터 손실 방지를 위해 파일 영속화.
     */
    private SecretKey generateFallbackKek() {
        if (persistedFallbackKek != null) {
            return persistedFallbackKek;
        }

        lock.lock();
        try {
            if (persistedFallbackKek != null) {
                return persistedFallbackKek;
            }

            SecretKey loadedKek = loadFallbackKek();
            if (loadedKek != null) {
                persistedFallbackKek = loadedKek;
                log.warn("Loaded existing fallback KEK from file - THIS IS NOT SECURE FOR PRODUCTION");
                return persistedFallbackKek;
            }

            SecretKey newKek = generateAndPersistFallbackKek();
            persistedFallbackKek = newKek;
            return persistedFallbackKek;

        } finally {
            lock.unlock();
        }
    }

    /** 파일에서 Fallback KEK 로드. */
    private SecretKey loadFallbackKek() {
        Path kekPath = getFallbackKekPath();
        if (!Files.exists(kekPath)) {
            return null;
        }

        try {
            byte[] keyBytes = Files.readAllBytes(kekPath);
            if (keyBytes.length != 32) {
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

    /** Fallback KEK 생성 후 파일에 저장. */
    private SecretKey generateAndPersistFallbackKek() {
        try {
            Path seedPath = getFallbackSeedPath();
            byte[] seed;

            if (Files.exists(seedPath)) {
                seed = Files.readAllBytes(seedPath);
            } else {
                seed = new byte[32];
                new SecureRandom().nextBytes(seed);
                writeFileWithRestrictivePermissions(seedPath, seed);
                log.warn("Created new fallback seed file at: {} - PROTECT THIS FILE", seedPath);
            }

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom seededRandom = createSeededSecureRandom(seed);
            keyGen.init(256, seededRandom);
            SecretKey key = keyGen.generateKey();

            Path kekPath = getFallbackKekPath();
            writeFileWithRestrictivePermissions(kekPath, key.getEncoded());

            log.warn("Generated and persisted new fallback KEK to: {} - THIS IS NOT SECURE FOR PRODUCTION", kekPath);
            return key;

        } catch (NoSuchAlgorithmException | IOException e) {
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

    /** 시드 기반 SecureRandom 생성. DRBG 우선, 불가 시 SHA1PRNG 폴백. */
    private SecureRandom createSeededSecureRandom(byte[] seed) throws NoSuchAlgorithmException {
        SecureRandom seededRandom;
        try {
            seededRandom = SecureRandom.getInstance("DRBG");
            seededRandom.setSeed(seed);
        } catch (NoSuchAlgorithmException e) {
            log.warn("DRBG algorithm not available, falling back to SHA1PRNG");
            seededRandom = SecureRandom.getInstance("SHA1PRNG");
            seededRandom.setSeed(seed);
        }
        return seededRandom;
    }

    /** Fallback KEK 파일 경로. */
    private Path getFallbackKekPath() {
        String fallbackDir = config.getFallbackDirectory();
        if (fallbackDir != null && !fallbackDir.isBlank()) {
            return Paths.get(fallbackDir, FALLBACK_KEK_FILENAME);
        }
        return Paths.get(System.getProperty("user.home"), FALLBACK_KEK_FILENAME);
    }

    /** Fallback 시드 파일 경로. */
    private Path getFallbackSeedPath() {
        String fallbackDir = config.getFallbackDirectory();
        if (fallbackDir != null && !fallbackDir.isBlank()) {
            return Paths.get(fallbackDir, FALLBACK_SEED_FILENAME);
        }
        return Paths.get(System.getProperty("user.home"), FALLBACK_SEED_FILENAME);
    }

    /** 제한적 권한(chmod 600)으로 파일 쓰기. */
    private void writeFileWithRestrictivePermissions(Path path, byte[] content) throws IOException {
        Files.write(path, content,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);
        setRestrictivePermissions(path);
    }

    /** 파일 권한을 owner-only(600)로 설정. */
    private void setRestrictivePermissions(Path path) {
        try {
            java.util.Set<PosixFilePermission> permissions = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            );
            Files.setPosixFilePermissions(path, permissions);
            log.debug("Set restrictive permissions (600) on: {}", path);
        } catch (java.lang.UnsupportedOperationException e) {
            log.warn("Cannot set POSIX file permissions on {} - OS does not support", path);
        } catch (IOException e) {
            log.warn("Failed to set restrictive permissions on {}: {}", path, e.getMessage());
        }
    }

    /** KEK 캐시 무효화. 다음 조회 시 KMS에서 새로 가져옴. */
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

    /** KEK 캐시 무효화. */
    public void invalidateCache() {
        lock.lock();
        try {
            cachedKekHolder = null;
        } finally {
            lock.unlock();
        }
    }

    /** AWS KMS 설정 여부. */
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

    /** KMS 작업 실패 예외. */
    public static class KmsException extends RuntimeException {
        public KmsException(String message) {
            super(message);
        }

        public KmsException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
