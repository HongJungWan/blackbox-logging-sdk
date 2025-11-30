package io.github.hongjungwan.blackbox.core.integration;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.security.KmsClient;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

import javax.crypto.SecretKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.testcontainers.containers.localstack.LocalStackContainer.Service.KMS;

/**
 * AWS KMS Integration Tests using LocalStack
 */
@Testcontainers
@DisplayName("AWS KMS 통합 테스트 (LocalStack)")
class KmsIntegrationTest {

    @Container
    static LocalStackContainer localstack = new LocalStackContainer(
            DockerImageName.parse("localstack/localstack:3.0")
    ).withServices(KMS);

    private static String testKeyId;
    private static software.amazon.awssdk.services.kms.KmsClient awsKmsClient;

    @BeforeAll
    static void setUpKms() {
        // Create KMS client for LocalStack
        awsKmsClient = software.amazon.awssdk.services.kms.KmsClient.builder()
                .endpointOverride(localstack.getEndpointOverride(KMS))
                .region(Region.of(localstack.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(
                                localstack.getAccessKey(),
                                localstack.getSecretKey()
                        )
                ))
                .build();

        // Create a test KMS key
        CreateKeyResponse keyResponse = awsKmsClient.createKey(CreateKeyRequest.builder()
                .keySpec(KeySpec.SYMMETRIC_DEFAULT)
                .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                .description("Test key for SecureHR SDK")
                .build());

        testKeyId = keyResponse.keyMetadata().keyId();
    }

    @AfterAll
    static void tearDownKms() {
        if (awsKmsClient != null) {
            awsKmsClient.close();
        }
    }

    @Nested
    @DisplayName("폴백 모드 테스트")
    class FallbackModeTests {

        @Test
        @DisplayName("AWS KMS 없이 폴백 키를 생성할 수 있어야 한다")
        void shouldGenerateFallbackKey() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            // when
            try (KmsClient kmsClient = new KmsClient(config)) {
                SecretKey kek = kmsClient.getKek();

                // then
                assertThat(kek).isNotNull();
                assertThat(kek.getAlgorithm()).isEqualTo("AES");
                assertThat(kek.getEncoded()).hasSize(32);
            }
        }

        @Test
        @DisplayName("폴백 모드에서 동일한 키가 캐시되어야 한다")
        void shouldCacheFallbackKey() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            // when
            try (KmsClient kmsClient = new KmsClient(config)) {
                SecretKey key1 = kmsClient.getKek();
                SecretKey key2 = kmsClient.getKek();

                // then
                assertThat(key1).isSameAs(key2);
            }
        }
    }

    @Nested
    @DisplayName("데이터 키 암호화")
    class DataKeyEncryptionTests {

        @Test
        @DisplayName("폴백 모드에서 데이터 키가 그대로 반환되어야 한다")
        void shouldReturnDataKeyAsIsInFallback() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                byte[] originalKey = new byte[32];
                for (int i = 0; i < 32; i++) {
                    originalKey[i] = (byte) i;
                }

                // when
                byte[] encrypted = kmsClient.encryptDataKey(originalKey);
                byte[] decrypted = kmsClient.decryptDataKey(encrypted);

                // then
                assertThat(decrypted).isEqualTo(originalKey);
            }
        }
    }

    @Nested
    @DisplayName("캐시 관리")
    class CacheManagementTests {

        @Test
        @DisplayName("캐시 무효화 후 새 키가 생성되어야 한다")
        void shouldGenerateNewKeyAfterInvalidation() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                SecretKey key1 = kmsClient.getKek();

                // when
                kmsClient.invalidateCache();
                SecretKey key2 = kmsClient.getKek();

                // then
                assertThat(key1).isNotSameAs(key2);
            }
        }

        @Test
        @DisplayName("로테이션 후 새 키가 반환되어야 한다")
        void shouldReturnNewKeyAfterRotation() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                SecretKey key1 = kmsClient.getKek();

                // when
                kmsClient.rotateKek();
                SecretKey key2 = kmsClient.getKek();

                // then
                assertThat(key1).isNotSameAs(key2);
            }
        }
    }

    @Nested
    @DisplayName("동시성 테스트")
    class ConcurrencyTests {

        @Test
        @DisplayName("동시 접근에서도 안전해야 한다")
        void shouldBeThreadSafe() throws InterruptedException {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                Thread[] threads = new Thread[10];
                SecretKey[] keys = new SecretKey[10];

                // when
                for (int i = 0; i < 10; i++) {
                    final int index = i;
                    threads[i] = new Thread(() -> keys[index] = kmsClient.getKek());
                    threads[i].start();
                }

                for (Thread thread : threads) {
                    thread.join();
                }

                // then - all should be the same cached key
                SecretKey firstKey = keys[0];
                for (SecretKey key : keys) {
                    assertThat(key).isSameAs(firstKey);
                }
            }
        }
    }
}
