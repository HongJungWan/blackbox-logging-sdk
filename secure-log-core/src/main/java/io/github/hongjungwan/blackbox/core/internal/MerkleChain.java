package io.github.hongjungwan.blackbox.core.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Merkle Chain 기반 무결성 검증. 각 로그에 이전 해시를 포함하여 변조 방지.
 * 분산 환경에서는 인스턴스별 독립 체인 (교차 검증 불가).
 */
public class MerkleChain {

    private static final String HASH_ALGORITHM = "SHA-256";

    private static final ObjectMapper CANONICAL_MAPPER = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private final ReentrantLock lock = new ReentrantLock();
    private volatile String previousHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public LogEntry addToChain(LogEntry entry) {
        lock.lock();
        try {
            String currentHash = calculateHash(entry, previousHash);
            previousHash = currentHash;

            return LogEntry.builder()
                    .timestamp(entry.getTimestamp())
                    .level(entry.getLevel())
                    .traceId(entry.getTraceId())
                    .spanId(entry.getSpanId())
                    .context(entry.getContext())
                    .message(entry.getMessage())
                    .payload(entry.getPayload())
                    .integrity("sha256:" + currentHash)
                    .encryptedDek(entry.getEncryptedDek())
                    .repeatCount(entry.getRepeatCount())
                    .throwable(entry.getThrowable())
                    .build();

        } finally {
            lock.unlock();
        }
    }

    private String calculateHash(LogEntry entry, String previousHash) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + HASH_ALGORITHM, e);
        }

        digest.update(String.valueOf(entry.getTimestamp()).getBytes(StandardCharsets.UTF_8));
        digest.update(entry.getLevel().getBytes(StandardCharsets.UTF_8));
        digest.update(entry.getMessage().getBytes(StandardCharsets.UTF_8));
        digest.update(previousHash.getBytes(StandardCharsets.UTF_8));

        if (entry.getPayload() != null) {
            try {
                String canonicalJson = CANONICAL_MAPPER.writeValueAsString(entry.getPayload());
                digest.update(canonicalJson.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                digest.update(entry.getPayload().toString().getBytes(StandardCharsets.UTF_8));
            }
        }

        byte[] hashBytes = digest.digest();
        return HexFormat.of().formatHex(hashBytes);
    }

    public boolean verifyChain(LogEntry entry, String expectedPreviousHash) {
        if (entry.getIntegrity() == null) {
            return false;
        }
        String reconstructedHash = calculateHash(entry, expectedPreviousHash);
        String storedHash = entry.getIntegrity().replace("sha256:", "");

        return reconstructedHash.equals(storedHash);
    }

    public void reset() {
        lock.lock();
        try {
            previousHash = "0000000000000000000000000000000000000000000000000000000000000000";
        } finally {
            lock.unlock();
        }
    }

    /** 체인 상태 저장 */
    public void saveState(Path path) throws IOException {
        lock.lock();
        try {
            String state = previousHash;
            Files.writeString(path, state,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
        } finally {
            lock.unlock();
        }
    }

    /** 체인 상태 로드 */
    public void loadState(Path path) throws IOException {
        lock.lock();
        try {
            if (!Files.exists(path)) {
                throw new IOException("Chain state file not found: " + path);
            }

            String state = Files.readString(path, StandardCharsets.UTF_8).trim();

            // SHA-256 해시 형식 검증 (64 hex 문자)
            if (state.length() != 64 || !state.matches("[0-9a-fA-F]+")) {
                throw new IOException("Invalid chain state format: expected 64 hex characters");
            }

            previousHash = state.toLowerCase();
        } finally {
            lock.unlock();
        }
    }

    /** 체인 상태 로드 시도 (실패 시 false) */
    public boolean tryLoadState(Path path) {
        lock.lock();
        try {
            if (!Files.exists(path)) {
                return false;
            }

            String state = Files.readString(path, StandardCharsets.UTF_8).trim();

            if (state.length() != 64 || !state.matches("[0-9a-fA-F]+")) {
                return false;
            }

            previousHash = state.toLowerCase();
            return true;

        } catch (IOException e) {
            return false;
        } finally {
            lock.unlock();
        }
    }

    public String getCurrentHash() {
        lock.lock();
        try {
            return previousHash;
        } finally {
            lock.unlock();
        }
    }
}
