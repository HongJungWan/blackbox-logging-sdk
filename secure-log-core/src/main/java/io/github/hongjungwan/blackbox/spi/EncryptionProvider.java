package io.github.hongjungwan.blackbox.spi;

import javax.crypto.SecretKey;

/**
 * 암호화 키 관리 SPI. AWS KMS, HashiCorp Vault 등 다양한 KMS 연동 시 구현.
 */
public interface EncryptionProvider {

    /** Provider 식별자 반환 */
    String getName();

    /** 새로운 DEK(Data Encryption Key) 생성 */
    SecretKey generateDek();

    /** KEK로 DEK 암호화 */
    byte[] encryptDek(SecretKey dek);

    /** 암호화된 DEK 복호화 */
    SecretKey decryptDek(byte[] encryptedDek);

    /** Provider 사용 가능 여부 확인 */
    boolean isAvailable();

    /** KEK 로테이션 (지원 시) */
    default boolean rotateKek() {
        return false;
    }

    /** DEK 파기 (crypto-shred) */
    default void destroyDek(SecretKey dek) {
        try {
            dek.destroy();
        } catch (Exception ignored) {
        }
    }
}
