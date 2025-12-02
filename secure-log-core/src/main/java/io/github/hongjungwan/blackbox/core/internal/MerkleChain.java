package io.github.hongjungwan.blackbox.core.internal;

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
 * Merkle Tree-based integrity chain.
 *
 * <p>Each log block includes hash of previous block (blockchain-style).
 * Prevents tampering and provides audit trail.</p>
 *
 * <p>Uses ReentrantLock for Virtual Thread compatibility.</p>
 *
 * <h2>Important: Distributed Deployment Limitation</h2>
 * <p>This implementation provides <strong>per-instance integrity only</strong>.
 * In distributed deployments with multiple application instances:</p>
 * <ul>
 *   <li>Each instance maintains its own independent chain</li>
 *   <li>Cross-instance verification is NOT supported</li>
 *   <li>Logs from different instances have separate integrity chains</li>
 * </ul>
 *
 * <p>For cross-instance integrity verification in distributed systems, consider:</p>
 * <ul>
 *   <li>Using a centralized integrity service (e.g., dedicated Merkle tree service)</li>
 *   <li>Including instance ID in log entries for per-instance chain identification</li>
 *   <li>Using a distributed ledger or blockchain for enterprise-grade integrity</li>
 * </ul>
 *
 * <h2>State Persistence</h2>
 * <p>Use {@link #saveState(Path)} on shutdown and {@link #tryLoadState(Path)} on startup
 * to maintain chain continuity across application restarts.</p>
 *
 * @since 8.0.0
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

    /**
     * Save the current chain state to a file.
     * This allows preserving chain integrity across restarts.
     *
     * @param path the path to save the state to
     * @throws IOException if writing fails
     */
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

    /**
     * Load the chain state from a file.
     * This restores the chain to continue from where it left off.
     *
     * @param path the path to load the state from
     * @throws IOException if reading fails or file doesn't exist
     */
    public void loadState(Path path) throws IOException {
        lock.lock();
        try {
            if (!Files.exists(path)) {
                throw new IOException("Chain state file not found: " + path);
            }

            String state = Files.readString(path, StandardCharsets.UTF_8).trim();

            // Validate hash format (64 hex characters for SHA-256)
            if (state.length() != 64 || !state.matches("[0-9a-fA-F]+")) {
                throw new IOException("Invalid chain state format: expected 64 hex characters");
            }

            previousHash = state.toLowerCase();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Try to load chain state from file, returning true if successful.
     * If the file doesn't exist or is invalid, the chain is reset to genesis state.
     *
     * @param path the path to load the state from
     * @return true if state was loaded successfully, false if chain was reset
     */
    public boolean tryLoadState(Path path) {
        lock.lock();
        try {
            if (!Files.exists(path)) {
                return false;
            }

            String state = Files.readString(path, StandardCharsets.UTF_8).trim();

            // Validate hash format (64 hex characters for SHA-256)
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

    /**
     * Get the current chain hash (for inspection/debugging).
     *
     * @return the current previous hash value
     */
    public String getCurrentHash() {
        lock.lock();
        try {
            return previousHash;
        } finally {
            lock.unlock();
        }
    }
}
