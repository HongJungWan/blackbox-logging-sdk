package io.github.hongjungwan.blackbox.core.resilience;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.locks.ReentrantLock;

/**
 * 연속 실패 기반 Circuit Breaker - N번 연속 실패 시 일정 시간 동안 fast-fail.
 *
 * ReentrantLock 기반 동기화로 Virtual Thread 호환성 확보.
 */
@Slf4j
public final class CircuitBreaker {

    private final String name;
    private final int failureThreshold;
    private final long resetTimeoutMs;
    private final ReentrantLock lock = new ReentrantLock();

    private int consecutiveFailures = 0;
    private long lastFailureTime = 0;

    private StateChangeListener stateChangeListener;

    /** CLOSED: 정상, OPEN: 차단 */
    public enum State {
        CLOSED,
        OPEN
    }

    private CircuitBreaker(Builder builder) {
        this.name = builder.name;
        this.failureThreshold = builder.failureThreshold;
        this.resetTimeoutMs = builder.resetTimeoutMs;
        this.stateChangeListener = builder.stateChangeListener;
    }

    /**
     * Circuit이 열려있는지 확인
     */
    public boolean isOpen() {
        lock.lock();
        try {
            if (consecutiveFailures >= failureThreshold) {
                long elapsed = System.currentTimeMillis() - lastFailureTime;
                if (elapsed < resetTimeoutMs) {
                    return true;
                }
                resetInternal();
            }
            return false;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 호출 허용 여부 확인
     */
    public boolean tryAcquirePermission() {
        return !isOpen();
    }

    /**
     * 성공 기록 - 연속 실패 카운터 리셋
     */
    public void onSuccess() {
        lock.lock();
        try {
            if (consecutiveFailures > 0) {
                State previousState = getStateInternal();
                consecutiveFailures = 0;
                notifyStateChange(previousState, State.CLOSED);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * 실패 기록 - 연속 실패 카운터 증가
     */
    public void onFailure(Exception e) {
        lock.lock();
        try {
            State previousState = getStateInternal();
            consecutiveFailures++;
            lastFailureTime = System.currentTimeMillis();

            if (consecutiveFailures >= failureThreshold && previousState == State.CLOSED) {
                log.warn("Circuit breaker '{}' OPEN after {} consecutive failures", name, failureThreshold);
                notifyStateChange(State.CLOSED, State.OPEN);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Circuit Breaker로 보호되는 작업 실행
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
     * Runnable 실행
     */
    public void execute(Runnable operation) throws CircuitBreakerOpenException {
        execute(() -> {
            operation.run();
            return null;
        });
    }

    /**
     * 강제 리셋
     */
    public void reset() {
        lock.lock();
        try {
            resetInternal();
        } finally {
            lock.unlock();
        }
    }

    /** 락 내부에서 호출되는 리셋 로직 */
    private void resetInternal() {
        State previousState = getStateInternal();
        consecutiveFailures = 0;
        lastFailureTime = 0;

        if (previousState == State.OPEN) {
            log.info("Circuit breaker '{}' reset to CLOSED", name);
            notifyStateChange(previousState, State.CLOSED);
        }
    }

    /**
     * 현재 상태 조회
     */
    public State getState() {
        lock.lock();
        try {
            return getStateInternal();
        } finally {
            lock.unlock();
        }
    }

    /** 락 내부에서 호출되는 상태 조회 로직 */
    private State getStateInternal() {
        return isOpenInternal() ? State.OPEN : State.CLOSED;
    }

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
     * 메트릭 스냅샷 조회
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
     * 메트릭 레코드
     */
    public record Metrics(
            String name,
            State state,
            int failureCount
    ) {}

    /**
     * 상태 변경 리스너
     */
    @FunctionalInterface
    public interface StateChangeListener {
        void onStateChange(String name, State from, State to);
    }

    public static class Builder {
        private final String name;
        private int failureThreshold = 3;
        private long resetTimeoutMs = 30_000;
        private StateChangeListener stateChangeListener;

        public Builder(String name) {
            this.name = name;
        }

        /**
         * 실패 임계값 설정 (기본: 3회)
         */
        public Builder failureThreshold(int threshold) {
            this.failureThreshold = threshold;
            return this;
        }

        /**
         * 리셋 타임아웃 설정 (기본: 30초)
         */
        public Builder openDuration(java.time.Duration duration) {
            this.resetTimeoutMs = duration.toMillis();
            return this;
        }

        /**
         * API 호환용 - 무시됨
         */
        public Builder successThreshold(int threshold) {
            return this;
        }

        /**
         * API 호환용 - 무시됨
         */
        public Builder maxOpenDuration(java.time.Duration maxDuration) {
            return this;
        }

        /**
         * 상태 변경 리스너 설정
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
     * Circuit 열림 시 발생하는 예외
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
