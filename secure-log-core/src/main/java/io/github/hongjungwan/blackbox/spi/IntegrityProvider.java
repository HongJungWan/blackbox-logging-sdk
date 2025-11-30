package io.github.hongjungwan.blackbox.spi;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;

/**
 * SPI for log integrity verification.
 *
 * <p>Implement this interface to provide custom integrity mechanisms
 * (hash chaining, digital signatures, etc.).</p>
 *
 * <h2>Built-in Implementation:</h2>
 * <p>MerkleChain: SHA-256 hash chaining where each log entry includes
 * a hash of the previous entry.</p>
 *
 * <h2>Implementation Example:</h2>
 * <pre>{@code
 * public class SignatureIntegrityProvider implements IntegrityProvider {
 *     private final PrivateKey signingKey;
 *
 *     @Override
 *     public String computeIntegrity(LogEntry entry, String previousHash) {
 *         byte[] data = serialize(entry);
 *         Signature sig = Signature.getInstance("SHA256withRSA");
 *         sig.initSign(signingKey);
 *         sig.update(data);
 *         sig.update(previousHash.getBytes());
 *         return Base64.encode(sig.sign());
 *     }
 * }
 * }</pre>
 *
 * @since 8.0.0
 */
public interface IntegrityProvider {

    /**
     * Get the provider name.
     */
    String getName();

    /**
     * Compute integrity hash for a log entry.
     *
     * @param entry The log entry
     * @param previousHash Hash of the previous entry (for chaining)
     * @return Integrity hash string (e.g., "sha256:abc123...")
     */
    String computeIntegrity(LogEntry entry, String previousHash);

    /**
     * Verify integrity of a log entry.
     *
     * @param entry The log entry with integrity hash
     * @param previousHash Hash of the previous entry
     * @return true if integrity is valid
     */
    boolean verifyIntegrity(LogEntry entry, String previousHash);

    /**
     * Get the genesis (initial) hash for the chain.
     */
    default String getGenesisHash() {
        return "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    }
}
