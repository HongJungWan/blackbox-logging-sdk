package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 로컬 KEK(Key Encryption Key) 관리자.
 *
 * <p>파일 기반으로 KEK를 영속화하여 재시작 시에도 동일한 키 사용.
 * 프로덕션 환경에서는 적절한 파일 시스템 보안 적용 필요.
 */
@Slf4j
public class LocalKeyManager implements AutoCloseable {

    private static final String KEK_FILENAME = ".secure-hr-kek";
    private static final String SEED_FILENAME = ".secure-hr-seed";
    private static final long KEK_CACHE_TTL_MS = 300_000; // 5분

    private final SecureLogConfig config;
    private final ReentrantLock lock = new ReentrantLock();

    private volatile CachedKekHolder cachedKekHolder;
    private volatile SecretKey persistedKek;

    /** KEK와 캐시 시간을 원자적으로 관리하는 홀더 클래스. */
    private static class CachedKekHolder {
        final SecretKey kek;
        final long cacheTime;

        CachedKekHolder(SecretKey kek, long cacheTime) {
            this.kek = kek;
            this.cacheTime = cacheTime;
        }
    }

    public LocalKeyManager(SecureLogConfig config) {
        this.config = config;
        log.info("LocalKeyManager initialized");
    }

    /**
     * KEK 조회 (캐싱 적용).
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

            SecretKey kek = loadOrGenerateKek();
            cachedKekHolder = new CachedKekHolder(kek, System.currentTimeMillis());
            return kek;

        } finally {
            lock.unlock();
        }
    }

    /** 캐시 유효성 검사. */
    private boolean isCacheValid(CachedKekHolder holder) {
        return holder != null &&
                (System.currentTimeMillis() - holder.cacheTime) < KEK_CACHE_TTL_MS;
    }

    /** KEK 로드 또는 신규 생성. */
    private SecretKey loadOrGenerateKek() {
        if (persistedKek != null) {
            return persistedKek;
        }

        SecretKey loadedKek = loadKekFromFile();
        if (loadedKek != null) {
            persistedKek = loadedKek;
            log.info("Loaded existing KEK from file");
            return persistedKek;
        }

        SecretKey newKek = generateAndPersistKek();
        persistedKek = newKek;
        return persistedKek;
    }

    /** 파일에서 KEK 로드. */
    private SecretKey loadKekFromFile() {
        Path kekPath = getKekPath();
        if (!Files.exists(kekPath)) {
            return null;
        }

        try {
            byte[] keyBytes = Files.readAllBytes(kekPath);
            if (keyBytes.length != 32) {
                log.warn("Invalid KEK file size (expected 32 bytes), will regenerate");
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
            log.warn("Failed to load KEK from file: {}", e.getMessage());
            return null;
        }
    }

    /** KEK 생성 후 파일에 저장. */
    private SecretKey generateAndPersistKek() {
        try {
            Path seedPath = getSeedPath();
            byte[] seed;

            if (Files.exists(seedPath)) {
                seed = Files.readAllBytes(seedPath);
            } else {
                seed = new byte[32];
                new SecureRandom().nextBytes(seed);
                writeFileWithRestrictivePermissions(seedPath, seed);
                log.info("Created new seed file at: {}", seedPath);
            }

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom seededRandom = createSeededSecureRandom(seed);
            keyGen.init(256, seededRandom);
            SecretKey key = keyGen.generateKey();

            Path kekPath = getKekPath();
            writeFileWithRestrictivePermissions(kekPath, key.getEncoded());

            log.info("Generated and persisted new KEK to: {}", kekPath);
            return key;

        } catch (NoSuchAlgorithmException | IOException e) {
            log.error("Failed to persist KEK, using ephemeral key - DATA LOSS ON RESTART", e);
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                return keyGen.generateKey();
            } catch (NoSuchAlgorithmException ex) {
                throw new KeyManagementException("Failed to generate KEK", ex);
            }
        }
    }

    /** 시드 기반 SecureRandom 생성. */
    private SecureRandom createSeededSecureRandom(byte[] seed) throws NoSuchAlgorithmException {
        SecureRandom seededRandom;
        try {
            seededRandom = SecureRandom.getInstance("DRBG");
            seededRandom.setSeed(seed);
        } catch (NoSuchAlgorithmException e) {
            log.debug("DRBG algorithm not available, using SHA1PRNG");
            seededRandom = SecureRandom.getInstance("SHA1PRNG");
            seededRandom.setSeed(seed);
        }
        return seededRandom;
    }

    /** KEK 파일 경로. */
    private Path getKekPath() {
        String fallbackDir = config.getFallbackDirectory();
        if (fallbackDir != null && !fallbackDir.isBlank()) {
            return Paths.get(fallbackDir, KEK_FILENAME);
        }
        return Paths.get(System.getProperty("user.home"), KEK_FILENAME);
    }

    /** 시드 파일 경로. */
    private Path getSeedPath() {
        String fallbackDir = config.getFallbackDirectory();
        if (fallbackDir != null && !fallbackDir.isBlank()) {
            return Paths.get(fallbackDir, SEED_FILENAME);
        }
        return Paths.get(System.getProperty("user.home"), SEED_FILENAME);
    }

    /** 제한적 권한(chmod 600)으로 파일 쓰기. */
    private void writeFileWithRestrictivePermissions(Path path, byte[] content) throws IOException {
        Path parentDir = path.getParent();
        if (parentDir != null && !Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }

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
            log.debug("Cannot set POSIX file permissions - OS does not support");
        } catch (IOException e) {
            log.warn("Failed to set restrictive permissions on {}: {}", path, e.getMessage());
        }
    }

    /** KEK 로테이션 (캐시 무효화 후 재생성). */
    public void rotateKek() {
        lock.lock();
        try {
            cachedKekHolder = null;
            persistedKek = null;

            // 기존 파일 삭제
            try {
                Files.deleteIfExists(getKekPath());
                Files.deleteIfExists(getSeedPath());
            } catch (IOException e) {
                log.warn("Failed to delete old KEK files: {}", e.getMessage());
            }

            log.info("KEK rotated. New KEK will be generated on next access");
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

    @Override
    public void close() {
        log.debug("LocalKeyManager closed");
    }

    /** 키 관리 예외. */
    public static class KeyManagementException extends RuntimeException {
        public KeyManagementException(String message) {
            super(message);
        }

        public KeyManagementException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
