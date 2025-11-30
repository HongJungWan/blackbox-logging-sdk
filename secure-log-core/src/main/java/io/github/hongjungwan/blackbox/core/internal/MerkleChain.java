package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Merkle Tree-based integrity chain
 * Each log block includes hash of previous block (blockchain-style)
 * Prevents tampering and provides audit trail
 *
 * Uses ReentrantLock for Virtual Thread compatibility
 */
public class MerkleChain {

    private static final String HASH_ALGORITHM = "SHA-256";

    private final ReentrantLock lock = new ReentrantLock();
    private volatile String previousHash = "0000000000000000000000000000000000000000000000000000000000000000";

    /**
     * Add log entry to chain with integrity hash
     */
    public LogEntry addToChain(LogEntry entry) {
        lock.lock();
        try {
            // Calculate hash of current entry + previous hash
            String currentHash = calculateHash(entry, previousHash);

            // Update previous hash for next entry
            previousHash = currentHash;

            // Return entry with integrity hash
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

    /**
     * Calculate SHA-256 hash of log entry
     */
    private String calculateHash(LogEntry entry, String previousHash) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);

            // Hash components
            digest.update(String.valueOf(entry.getTimestamp()).getBytes(StandardCharsets.UTF_8));
            digest.update(entry.getLevel().getBytes(StandardCharsets.UTF_8));
            digest.update(entry.getMessage().getBytes(StandardCharsets.UTF_8));
            digest.update(previousHash.getBytes(StandardCharsets.UTF_8));

            if (entry.getPayload() != null) {
                digest.update(entry.getPayload().toString().getBytes(StandardCharsets.UTF_8));
            }

            byte[] hashBytes = digest.digest();
            return HexFormat.of().formatHex(hashBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + HASH_ALGORITHM, e);
        }
    }

    /**
     * Verify integrity chain
     */
    public boolean verifyChain(LogEntry entry, String expectedPreviousHash) {
        String reconstructedHash = calculateHash(entry, expectedPreviousHash);
        String storedHash = entry.getIntegrity().replace("sha256:", "");

        return reconstructedHash.equals(storedHash);
    }

    /**
     * Reset chain (for testing)
     */
    public void reset() {
        lock.lock();
        try {
            previousHash = "0000000000000000000000000000000000000000000000000000000000000000";
        } finally {
            lock.unlock();
        }
    }
}
