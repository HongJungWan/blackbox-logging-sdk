package io.github.hongjungwan.blackbox.core.resilience;

import lombok.extern.slf4j.Slf4j;

/**
 * Circuit Breaker - 간단한 연속 실패 기반 차단기
 *
 * N번 연속 실패 시 일정 시간 동안 fast-fail.
 * 주니어 면접용으로 단순화된 구현.
 */
@Slf4j
public final class CircuitBreaker {

    private final String name;
    private final int failureThreshold;
    private final long resetTimeoutMs;

    private int consecutiveFailures = 0;
    private long lastFailureTime = 0;

    // Listener for state changes
    private StateChangeListener stateChangeListener;

    public enum State {
        CLOSED,  // 정상 상태
        OPEN     // 차단 상태
    }

    private CircuitBreaker(Builder builder) {
        this.name = builder.name;
        this.failureThreshold = builder.failureThreshold;
        this.resetTimeoutMs = builder.resetTimeoutMs;
        this.stateChangeListener = builder.stateChangeListener;
    }

    /**
     * 현재 Circuit Breaker가 열려있는지 확인.
     *
     * @return true if open (should fail fast), false if closed (allow operation)
     */
    public synchronized boolean isOpen() {
        if (consecutiveFailures >= failureThreshold) {
            long elapsed = System.currentTimeMillis() - lastFailureTime;
            if (elapsed < resetTimeoutMs) {
                return true;  // 아직 차단 상태
            }
            // 타임아웃 경과 - 리셋
            reset();
        }
        return false;
    }

    /**
     * 호출 허용 여부 확인 (기존 API 호환).
     *
     * @return true if the call is permitted
     */
    public boolean tryAcquirePermission() {
        return !isOpen();
    }

    /**
     * 성공 기록 - 연속 실패 카운터 리셋.
     */
    public synchronized void onSuccess() {
        if (consecutiveFailures > 0) {
            State previousState = getState();
            consecutiveFailures = 0;
            notifyStateChange(previousState, State.CLOSED);
        }
    }

    /**
     * 실패 기록 - 연속 실패 카운터 증가.
     *
     * @param e the exception that caused the failure
     */
    public synchronized void onFailure(Exception e) {
        State previousState = getState();
        consecutiveFailures++;
        lastFailureTime = System.currentTimeMillis();

        if (consecutiveFailures >= failureThreshold && previousState == State.CLOSED) {
            log.warn("Circuit breaker '{}' OPEN after {} consecutive failures", name, failureThreshold);
            notifyStateChange(State.CLOSED, State.OPEN);
        }
    }

    /**
     * Circuit Breaker로 보호되는 작업 실행.
     *
     * @param <T> the return type
     * @param operation the operation to execute
     * @return the result of the operation
     * @throws CircuitBreakerOpenException if circuit is open
     */
    public <T> T execute(java.util.function.Supplier<T> operation) throws CircuitBreakerOpenException {
        if (isOpen()) {
            throw new CircuitBreakerOpenException(name);
        }

        try {
            T result = operation.get();
            onSuccess();
            return result;
        } catch (Exception e) {
            onFailure(e);
            throw e;
        }
    }

    /**
     * Runnable 실행 (기존 API 호환).
     */
    public void execute(Runnable operation) throws CircuitBreakerOpenException {
        execute(() -> {
            operation.run();
            return null;
        });
    }

    /**
     * 강제 리셋.
     */
    public synchronized void reset() {
        State previousState = getState();
        consecutiveFailures = 0;
        lastFailureTime = 0;

        if (previousState == State.OPEN) {
            log.info("Circuit breaker '{}' reset to CLOSED", name);
            notifyStateChange(previousState, State.CLOSED);
        }
    }

    /**
     * 현재 상태 조회.
     */
    public State getState() {
        return isOpenInternal() ? State.OPEN : State.CLOSED;
    }

    // 내부용 - synchronized 없이 상태 확인 (이미 synchronized 블록 내에서 호출)
    private boolean isOpenInternal() {
        if (consecutiveFailures >= failureThreshold) {
            long elapsed = System.currentTimeMillis() - lastFailureTime;
            return elapsed < resetTimeoutMs;
        }
        return false;
    }

    public String getName() {
        return name;
    }

    public int getFailureCount() {
        return consecutiveFailures;
    }

    /**
     * 메트릭 스냅샷 조회.
     */
    public Metrics getMetrics() {
        return new Metrics(name, getState(), consecutiveFailures);
    }

    private void notifyStateChange(State from, State to) {
        if (stateChangeListener != null && from != to) {
            try {
                stateChangeListener.onStateChange(name, from, to);
            } catch (Exception e) {
                log.warn("State change listener threw exception", e);
            }
        }
    }

    public static Builder builder(String name) {
        return new Builder(name);
    }

    /**
     * 메트릭 레코드 - 단순화됨
     */
    public record Metrics(
            String name,
            State state,
            int failureCount
    ) {}

    /**
     * State change listener
     */
    @FunctionalInterface
    public interface StateChangeListener {
        void onStateChange(String name, State from, State to);
    }

    /**
     * Builder
     */
    public static class Builder {
        private final String name;
        private int failureThreshold = 3;
        private long resetTimeoutMs = 30_000; // 30초
        private StateChangeListener stateChangeListener;

        public Builder(String name) {
            this.name = name;
        }

        /**
         * 실패 임계값 설정 (기본: 3회).
         */
        public Builder failureThreshold(int threshold) {
            this.failureThreshold = threshold;
            return this;
        }

        /**
         * 리셋 타임아웃 설정 (기본: 30초).
         * 기존 openDuration과 호환.
         */
        public Builder openDuration(java.time.Duration duration) {
            this.resetTimeoutMs = duration.toMillis();
            return this;
        }

        /**
         * 성공 임계값 (무시됨 - API 호환용).
         */
        public Builder successThreshold(int threshold) {
            // 단순화로 인해 무시 - HALF_OPEN 상태 없음
            return this;
        }

        /**
         * 최대 열림 기간 (무시됨 - API 호환용).
         */
        public Builder maxOpenDuration(java.time.Duration maxDuration) {
            // 단순화로 인해 무시 - exponential backoff 없음
            return this;
        }

        /**
         * 상태 변경 리스너 설정.
         */
        public Builder onStateChange(StateChangeListener listener) {
            this.stateChangeListener = listener;
            return this;
        }

        public CircuitBreaker build() {
            return new CircuitBreaker(this);
        }
    }

    /**
     * Circuit이 열려있을 때 던지는 예외
     */
    public static class CircuitBreakerOpenException extends RuntimeException {
        private final String circuitBreakerName;

        public CircuitBreakerOpenException(String name) {
            super("Circuit breaker '" + name + "' is OPEN");
            this.circuitBreakerName = name;
        }

        public String getCircuitBreakerName() {
            return circuitBreakerName;
        }
    }
}
