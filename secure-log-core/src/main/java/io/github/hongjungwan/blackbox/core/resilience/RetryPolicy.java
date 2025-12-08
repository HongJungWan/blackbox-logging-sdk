package io.github.hongjungwan.blackbox.core.resilience;

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * RetryPolicy - 간단한 고정 간격 재시도 정책
 *
 * 주니어 면접용으로 단순화된 구현.
 * Exponential backoff, jitter 제거 - 고정 간격 재시도.
 */
@Slf4j
public final class RetryPolicy {

    private final int maxAttempts;
    private final long delayMs;
    private final Predicate<Exception> retryPredicate;
    private final Set<Class<? extends Exception>> retryableExceptions;

    private RetryPolicy(Builder builder) {
        this.maxAttempts = builder.maxAttempts;
        this.delayMs = builder.delayMs;
        this.retryPredicate = builder.retryPredicate;
        this.retryableExceptions = builder.retryableExceptions;
    }

    /**
     * 재시도 정책에 따라 작업 실행.
     *
     * @param <T> the return type
     * @param operation the operation to execute
     * @return the result if successful
     * @throws RetryExhaustedException if all retries exhausted
     */
    public <T> T execute(Supplier<T> operation) throws RetryExhaustedException {
        Exception lastException = null;
        int attempt = 0;

        while (attempt < maxAttempts) {
            try {
                return operation.get();
            } catch (Exception e) {
                lastException = e;
                attempt++;

                if (!shouldRetry(e, attempt)) {
                    throw new RetryExhaustedException("Non-retryable exception", e);
                }

                if (attempt < maxAttempts) {
                    log.debug("Retry attempt {}/{} after {}ms", attempt, maxAttempts, delayMs);
                    sleep(delayMs);
                }
            }
        }

        throw new RetryExhaustedException(
                String.format("Exhausted %d retry attempts", maxAttempts),
                lastException
        );
    }

    /**
     * Runnable 실행.
     */
    public void execute(Runnable operation) throws RetryExhaustedException {
        execute(() -> {
            operation.run();
            return null;
        });
    }

    /**
     * 딜레이 계산 (기존 API 호환 - 항상 고정 딜레이 반환).
     */
    Duration calculateDelay(int attempt) {
        return Duration.ofMillis(delayMs);
    }

    private boolean shouldRetry(Exception e, int attempt) {
        if (attempt >= maxAttempts) {
            return false;
        }

        // 커스텀 predicate 먼저 확인
        if (retryPredicate != null) {
            return retryPredicate.test(e);
        }

        // 지정된 예외 타입 확인
        if (!retryableExceptions.isEmpty()) {
            return retryableExceptions.stream()
                    .anyMatch(clazz -> clazz.isInstance(e));
        }

        // 기본: 모든 예외 재시도
        return true;
    }

    private void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 기본 정책 생성 (3회 재시도, 100ms 간격).
     */
    public static RetryPolicy defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder
     */
    public static class Builder {
        private int maxAttempts = 3;
        private long delayMs = 100;
        private Predicate<Exception> retryPredicate;
        private Set<Class<? extends Exception>> retryableExceptions = Set.of();

        /**
         * 최대 재시도 횟수 설정 (기본: 3).
         */
        public Builder maxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
            return this;
        }

        /**
         * 초기 딜레이 설정 (기존 API 호환 - 고정 딜레이로 사용).
         */
        public Builder initialDelay(Duration initialDelay) {
            this.delayMs = initialDelay.toMillis();
            return this;
        }

        /**
         * 고정 딜레이 설정.
         */
        public Builder fixedDelay(Duration delay) {
            this.delayMs = delay.toMillis();
            return this;
        }

        /**
         * 최대 딜레이 (무시됨 - API 호환용).
         */
        public Builder maxDelay(Duration maxDelay) {
            // 단순화로 인해 무시 - 고정 딜레이 사용
            return this;
        }

        /**
         * 배율 (무시됨 - API 호환용).
         */
        public Builder multiplier(double multiplier) {
            // 단순화로 인해 무시 - exponential backoff 없음
            return this;
        }

        /**
         * 지터 팩터 (무시됨 - API 호환용).
         */
        public Builder jitterFactor(double jitterFactor) {
            // 단순화로 인해 무시
            return this;
        }

        /**
         * 지터 비활성화 (무시됨 - API 호환용).
         */
        public Builder noJitter() {
            // 이미 jitter 없음
            return this;
        }

        /**
         * 재시도 조건 predicate 설정.
         */
        public Builder retryOn(Predicate<Exception> predicate) {
            this.retryPredicate = predicate;
            return this;
        }

        /**
         * 재시도할 예외 클래스 설정.
         */
        @SafeVarargs
        public final Builder retryOnExceptions(Class<? extends Exception>... exceptions) {
            this.retryableExceptions = Set.of(exceptions);
            return this;
        }

        public RetryPolicy build() {
            return new RetryPolicy(this);
        }
    }

    /**
     * 재시도 소진 시 던지는 예외
     */
    public static class RetryExhaustedException extends RuntimeException {
        public RetryExhaustedException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
