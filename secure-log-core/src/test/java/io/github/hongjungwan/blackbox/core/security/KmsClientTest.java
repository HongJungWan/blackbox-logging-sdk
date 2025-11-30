package io.github.hongjungwan.blackbox.core.security;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import org.junit.jupiter.api.*;

import javax.crypto.SecretKey;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("KmsClient 테스트")
class KmsClientTest {

    @Nested
    @DisplayName("폴백 모드")
    class FallbackModeTests {

        @Test
        @DisplayName("AWS KMS가 구성되지 않으면 폴백 키를 생성해야 한다")
        void shouldGenerateFallbackKeyWhenAwsKmsNotConfigured() {
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
                assertThat(kek.getEncoded()).hasSize(32); // 256 bits
            }
        }

        @Test
        @DisplayName("폴백이 비활성화되고 AWS KMS가 구성되지 않으면 예외가 발생해야 한다")
        void shouldThrowExceptionWhenFallbackDisabledAndAwsKmsNotConfigured() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(false)
                    .build();

            // when/then
            try (KmsClient kmsClient = new KmsClient(config)) {
                assertThatThrownBy(kmsClient::getKek)
                        .isInstanceOf(KmsClient.KmsException.class)
                        .hasMessageContaining("not configured");
            }
        }
    }

    @Nested
    @DisplayName("KEK 캐싱")
    class KekCachingTests {

        @Test
        @DisplayName("동일한 KEK가 캐시에서 반환되어야 한다")
        void shouldReturnSameKekFromCache() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                // when
                SecretKey kek1 = kmsClient.getKek();
                SecretKey kek2 = kmsClient.getKek();

                // then
                assertThat(kek1).isSameAs(kek2);
            }
        }

        @Test
        @DisplayName("캐시 무효화 후 새 KEK가 반환되어야 한다")
        void shouldReturnNewKekAfterCacheInvalidation() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                SecretKey kek1 = kmsClient.getKek();

                // when
                kmsClient.invalidateCache();
                SecretKey kek2 = kmsClient.getKek();

                // then - new key generated (fallback mode)
                assertThat(kek1).isNotSameAs(kek2);
            }
        }
    }

    @Nested
    @DisplayName("KEK 로테이션")
    class KekRotationTests {

        @Test
        @DisplayName("로테이션 후 캐시가 무효화되어야 한다")
        void shouldInvalidateCacheOnRotation() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                SecretKey kek1 = kmsClient.getKek();

                // when
                kmsClient.rotateKek();
                SecretKey kek2 = kmsClient.getKek();

                // then
                assertThat(kek1).isNotSameAs(kek2);
            }
        }
    }

    @Nested
    @DisplayName("스레드 안전성")
    class ThreadSafetyTests {

        @Test
        @DisplayName("동시 접근에서도 동일한 KEK가 반환되어야 한다")
        void shouldReturnSameKekUnderConcurrentAccess() throws InterruptedException {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                int threadCount = 10;
                CountDownLatch startLatch = new CountDownLatch(1);
                CountDownLatch endLatch = new CountDownLatch(threadCount);
                AtomicReference<SecretKey> firstKey = new AtomicReference<>();
                ExecutorService executor = Executors.newFixedThreadPool(threadCount);

                // when
                for (int i = 0; i < threadCount; i++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await();
                            SecretKey kek = kmsClient.getKek();
                            firstKey.compareAndSet(null, kek);
                            assertThat(kek).isSameAs(firstKey.get());
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } finally {
                            endLatch.countDown();
                        }
                    });
                }

                startLatch.countDown();
                endLatch.await();
                executor.shutdown();

                // then - no exception thrown
            }
        }
    }

    @Nested
    @DisplayName("데이터 키 암호화/복호화")
    class DataKeyEncryptionTests {

        @Test
        @DisplayName("폴백 모드에서 데이터 키가 그대로 반환되어야 한다")
        void shouldReturnDataKeyAsIsInFallbackMode() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            try (KmsClient kmsClient = new KmsClient(config)) {
                byte[] dataKey = new byte[]{1, 2, 3, 4, 5};

                // when - fallback mode doesn't actually encrypt
                byte[] encrypted = kmsClient.encryptDataKey(dataKey);
                byte[] decrypted = kmsClient.decryptDataKey(encrypted);

                // then
                assertThat(decrypted).isEqualTo(dataKey);
            }
        }
    }

    @Nested
    @DisplayName("AWS KMS 구성 상태")
    class AwsKmsConfigurationTests {

        @Test
        @DisplayName("AWS KMS가 구성되지 않으면 false를 반환해야 한다")
        void shouldReturnFalseWhenAwsKmsNotConfigured() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();

            // when
            try (KmsClient kmsClient = new KmsClient(config)) {
                // then
                assertThat(kmsClient.isAwsKmsConfigured()).isFalse();
            }
        }

        @Test
        @DisplayName("빈 문자열 KMS Key ID는 구성되지 않은 것으로 처리해야 한다")
        void shouldTreatEmptyKmsKeyIdAsNotConfigured() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsKeyId("")
                    .kmsFallbackEnabled(true)
                    .build();

            // when
            try (KmsClient kmsClient = new KmsClient(config)) {
                // then
                assertThat(kmsClient.isAwsKmsConfigured()).isFalse();
            }
        }

        @Test
        @DisplayName("공백만 있는 KMS Key ID는 구성되지 않은 것으로 처리해야 한다")
        void shouldTreatBlankKmsKeyIdAsNotConfigured() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsKeyId("   ")
                    .kmsFallbackEnabled(true)
                    .build();

            // when
            try (KmsClient kmsClient = new KmsClient(config)) {
                // then
                assertThat(kmsClient.isAwsKmsConfigured()).isFalse();
            }
        }
    }

    @Nested
    @DisplayName("리소스 정리")
    class ResourceCleanupTests {

        @Test
        @DisplayName("close()를 여러 번 호출해도 안전해야 한다")
        void shouldBeSafeToCallCloseMultipleTimes() {
            // given
            SecureLogConfig config = SecureLogConfig.builder()
                    .kmsFallbackEnabled(true)
                    .build();
            KmsClient kmsClient = new KmsClient(config);

            // when/then - should not throw
            kmsClient.close();
            kmsClient.close();
        }
    }
}
