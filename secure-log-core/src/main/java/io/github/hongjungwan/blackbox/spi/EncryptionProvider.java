package io.github.hongjungwan.blackbox.spi;

import javax.crypto.SecretKey;

/**
 * SPI for encryption key management.
 *
 * <p>Implement this interface to integrate with different key management
 * systems (AWS KMS, HashiCorp Vault, Azure Key Vault, etc.).</p>
 *
 * <h2>Envelope Encryption Model:</h2>
 * <ul>
 *   <li>KEK (Key Encryption Key): Master key stored in KMS</li>
 *   <li>DEK (Data Encryption Key): Per-block key for actual encryption</li>
 * </ul>
 *
 * <h2>Implementation Example:</h2>
 * <pre>{@code
 * public class VaultEncryptionProvider implements EncryptionProvider {
 *     private final VaultClient vault;
 *
 *     @Override
 *     public byte[] encryptDek(SecretKey dek) {
 *         return vault.encrypt("transit/keys/logging", dek.getEncoded());
 *     }
 *
 *     @Override
 *     public SecretKey decryptDek(byte[] encryptedDek) {
 *         byte[] decrypted = vault.decrypt("transit/keys/logging", encryptedDek);
 *         return new SecretKeySpec(decrypted, "AES");
 *     }
 * }
 * }</pre>
 *
 * @since 8.0.0
 */
public interface EncryptionProvider {

    /**
     * Get the provider name.
     *
     * @return the unique name identifying this provider
     */
    String getName();

    /**
     * Generate a new Data Encryption Key (DEK).
     *
     * @return a new AES-256 secret key
     */
    SecretKey generateDek();

    /**
     * Encrypt a DEK with the Key Encryption Key (KEK).
     *
     * @param dek The data encryption key to encrypt
     * @return Encrypted DEK bytes
     */
    byte[] encryptDek(SecretKey dek);

    /**
     * Decrypt a DEK using the KEK.
     *
     * @param encryptedDek The encrypted DEK bytes
     * @return The decrypted DEK
     */
    SecretKey decryptDek(byte[] encryptedDek);

    /**
     * Check if this provider is available (e.g., KMS is reachable).
     *
     * @return true if the provider is ready to perform encryption operations
     */
    boolean isAvailable();

    /**
     * Rotate the KEK (if supported).
     *
     * @return true if rotation was successful
     */
    default boolean rotateKek() {
        return false;
    }

    /**
     * Destroy (crypto-shred) a DEK.
     *
     * @param dek The key to destroy
     */
    default void destroyDek(SecretKey dek) {
        try {
            dek.destroy();
        } catch (Exception ignored) {
            // Best effort
        }
    }
}
