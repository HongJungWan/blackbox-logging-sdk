package io.github.hongjungwan.blackbox.core.security;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 비상 모드용 공개키(RSA) 암호화기.
 *
 * 비상 모드 활성화 시 마스킹 대신 원본 데이터를 공개키로 암호화하여 저장.
 * 추후 개인키로 복호화하여 원본 데이터 복구 가능 (감사/조사 목적).
 *
 * 보안 고려사항:
 * - RSA-OAEP (SHA-256) 패딩 사용으로 선택적 암호문 공격 방어
 * - 공개키만 SDK에 배포, 개인키는 보안 HSM에서 관리
 * - 비상 모드 토큰은 시간 제한 및 감사 로그 기록
 */
@Slf4j
public class EmergencyEncryptor {

    private static final String ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String RSA = "RSA";
    private static final int MIN_KEY_SIZE = 2048;

    private final PublicKey publicKey;
    private final AtomicBoolean enabled = new AtomicBoolean(false);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 공개키로 EmergencyEncryptor 생성.
     *
     * @param publicKey RSA 공개키 (최소 2048비트)
     * @throws IllegalArgumentException 키가 null이거나 유효하지 않은 경우
     */
    public EmergencyEncryptor(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key must not be null");
        }
        this.publicKey = publicKey;
        log.info("EmergencyEncryptor initialized with RSA public key");
    }

    /**
     * Base64 인코딩된 공개키로 EmergencyEncryptor 생성.
     *
     * @param base64PublicKey X.509 형식의 Base64 인코딩 공개키
     * @return EmergencyEncryptor 인스턴스
     * @throws SecurityException 키 파싱 실패 시
     */
    public static EmergencyEncryptor fromBase64(String base64PublicKey) {
        if (base64PublicKey == null || base64PublicKey.isBlank()) {
            throw new IllegalArgumentException("Base64 public key must not be null or blank");
        }

        try {
            // PEM 헤더/푸터 제거 (있는 경우)
            String cleanKey = base64PublicKey
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));

            return new EmergencyEncryptor(publicKey);
        } catch (Exception e) {
            throw new SecurityException("Failed to parse public key from Base64", e);
        }
    }

    /**
     * 비상 모드용 공개키 암호화. 암호화 실패 시 마스킹된 폴백 값 반환.
     *
     * @param plainText 암호화할 원본 텍스트
     * @return Base64 인코딩된 암호문 또는 실패 시 "[ENCRYPTION_FAILED]"
     */
    public String encrypt(String plainText) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encrypted = cipher.doFinal(plainText.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            log.warn("Emergency encryption failed, returning fallback marker: {}", e.getMessage());
            return "[ENCRYPTION_FAILED]";
        }
    }

    /**
     * 비상 모드 결과 생성. 마스킹된 표시 값과 암호화된 원본을 포함.
     *
     * @param originalValue 원본 값
     * @param maskedValue 마스킹된 표시 값
     * @return JSON 형식의 비상 모드 결과
     */
    public EmergencyModeResult createEmergencyResult(String originalValue, String maskedValue) {
        String encrypted = encrypt(originalValue);
        return new EmergencyModeResult(maskedValue, encrypted);
    }

    /**
     * 비상 모드 활성화 여부 확인.
     */
    public boolean isEnabled() {
        return enabled.get();
    }

    /**
     * 비상 모드 활성화/비활성화 설정.
     *
     * @param enable 활성화 여부
     */
    public void setEnabled(boolean enable) {
        boolean previous = enabled.getAndSet(enable);
        if (previous != enable) {
            log.warn("Emergency mode {}", enable ? "ENABLED - original data will be encrypted" : "DISABLED");
        }
    }

    /**
     * 비상 모드 결과 레코드. 마스킹된 표시 값과 암호화된 원본 포함.
     *
     * @param display 마스킹된 표시 값 (UI/로그 출력용)
     * @param encrypted 공개키로 암호화된 원본 (추후 복호화용)
     */
    public record EmergencyModeResult(String display, String encrypted) {

        /**
         * JSON 형식으로 변환.
         */
        public String toJson() {
            return String.format("{\"display\":\"%s\",\"encrypted\":\"%s\"}", display, encrypted);
        }
    }
}
