package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.api.interceptor.LogInterceptor;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 인터셉터 체인 구현. 우선순위 기반 정렬, fail-safe 처리.
 */
@Slf4j
public final class InterceptorChainImpl implements LogInterceptor.Chain {

    private final List<NamedInterceptor> interceptors;
    private final int index;
    private final LogInterceptor.ProcessingStage stage;
    private final long startTimeNanos;

    private InterceptorChainImpl(
            List<NamedInterceptor> interceptors,
            int index,
            LogInterceptor.ProcessingStage stage,
            long startTimeNanos) {
        this.interceptors = interceptors;
        this.index = index;
        this.stage = stage;
        this.startTimeNanos = startTimeNanos;
    }

    public static Builder builder() {
        return new Builder();
    }

    public LogEntry execute(LogEntry entry) {
        return new InterceptorChainImpl(interceptors, 0, stage, System.nanoTime())
                .proceed(entry);
    }

    @Override
    public LogEntry proceed(LogEntry entry) {
        if (index >= interceptors.size()) {
            return entry;
        }

        InterceptorChainImpl next = new InterceptorChainImpl(
                interceptors,
                index + 1,
                stage,
                startTimeNanos
        );

        NamedInterceptor current = interceptors.get(index);
        try {
            LogEntry result = current.interceptor.intercept(entry, next);
            if (result == null) {
                log.debug("Log entry dropped by interceptor: {}", current.name);
            }
            return result;
        } catch (Exception e) {
            log.error("Interceptor '{}' threw exception, continuing chain", current.name, e);
            return next.proceed(entry);
        }
    }

    @Override
    public LogInterceptor.ProcessingStage stage() {
        return stage;
    }

    @Override
    public LogInterceptor.ChainMetadata metadata() {
        return new LogInterceptor.ChainMetadata() {
            @Override
            public long startTimeNanos() {
                return startTimeNanos;
            }

            @Override
            public int interceptorCount() {
                return interceptors.size();
            }

            @Override
            public int currentIndex() {
                return index;
            }
        };
    }

    private record NamedInterceptor(
            String name,
            int priority,
            LogInterceptor interceptor
    ) implements Comparable<NamedInterceptor> {

        @Override
        public int compareTo(NamedInterceptor other) {
            return Integer.compare(this.priority, other.priority);
        }
    }

    public static class Builder {
        private final List<NamedInterceptor> interceptors = new ArrayList<>();
        private LogInterceptor.ProcessingStage stage = LogInterceptor.ProcessingStage.PRE_PROCESS;

        public Builder add(String name, LogInterceptor interceptor) {
            return add(name, LogInterceptor.Priority.NORMAL, interceptor);
        }

        public Builder add(String name, LogInterceptor.Priority priority, LogInterceptor interceptor) {
            return add(name, priority.value(), interceptor);
        }

        public Builder add(String name, int priority, LogInterceptor interceptor) {
            interceptors.add(new NamedInterceptor(name, priority, interceptor));
            return this;
        }

        public Builder stage(LogInterceptor.ProcessingStage stage) {
            this.stage = stage;
            return this;
        }

        public InterceptorChainImpl build() {
            List<NamedInterceptor> sorted = new ArrayList<>(interceptors);
            Collections.sort(sorted);

            return new InterceptorChainImpl(
                    Collections.unmodifiableList(sorted),
                    0,
                    stage,
                    0
            );
        }
    }

    public static class Registry {
        private final List<NamedInterceptor> interceptors = new CopyOnWriteArrayList<>();

        public void register(String name, LogInterceptor interceptor) {
            register(name, LogInterceptor.Priority.NORMAL, interceptor);
        }

        public void register(String name, LogInterceptor.Priority priority, LogInterceptor interceptor) {
            interceptors.add(new NamedInterceptor(name, priority.value(), interceptor));
            interceptors.sort(Comparator.naturalOrder());
        }

        public void unregister(String name) {
            interceptors.removeIf(i -> i.name.equals(name));
        }

        public InterceptorChainImpl buildChain(LogInterceptor.ProcessingStage stage) {
            return new InterceptorChainImpl(
                    new ArrayList<>(interceptors),
                    0,
                    stage,
                    0
            );
        }

        public int size() {
            return interceptors.size();
        }

        public void clear() {
            interceptors.clear();
        }
    }
}
