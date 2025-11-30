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
 * Thread-safe, ordered interceptor chain for log processing.
 *
 * <p>Supports priority-based ordering and runtime registration.</p>
 *
 * <p>Based on: OkHttp RealInterceptorChain</p>
 */
@Slf4j
public final class InterceptorChainImpl implements LogInterceptor.Chain {

    private final List<PrioritizedInterceptor> interceptors;
    private final int index;
    private final LogEntry originalEntry;
    private final LogInterceptor.ProcessingStage stage;
    private final long startTimeNanos;

    private InterceptorChainImpl(
            List<PrioritizedInterceptor> interceptors,
            int index,
            LogEntry entry,
            LogInterceptor.ProcessingStage stage,
            long startTimeNanos) {
        this.interceptors = interceptors;
        this.index = index;
        this.originalEntry = entry;
        this.stage = stage;
        this.startTimeNanos = startTimeNanos;
    }

    /**
     * Create a new chain builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Execute the chain starting from the first interceptor.
     */
    public LogEntry execute(LogEntry entry) {
        return new InterceptorChainImpl(interceptors, 0, entry, stage, System.nanoTime())
                .proceed(entry);
    }

    @Override
    public LogEntry proceed(LogEntry entry) {
        if (index >= interceptors.size()) {
            // End of chain, return the entry as-is
            return entry;
        }

        // Create next chain segment
        InterceptorChainImpl next = new InterceptorChainImpl(
                interceptors,
                index + 1,
                entry,
                stage,
                startTimeNanos
        );

        // Execute current interceptor
        PrioritizedInterceptor current = interceptors.get(index);
        try {
            LogEntry result = current.interceptor.intercept(entry, next);

            if (result == null) {
                log.debug("Log entry dropped by interceptor: {}", current.name);
            }

            return result;

        } catch (Exception e) {
            log.error("Interceptor '{}' threw exception, continuing chain", current.name, e);
            // Continue chain on error (fail-safe)
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

    /**
     * Named and prioritized interceptor wrapper.
     */
    private record PrioritizedInterceptor(
            String name,
            int priority,
            LogInterceptor interceptor
    ) implements Comparable<PrioritizedInterceptor> {

        @Override
        public int compareTo(PrioritizedInterceptor other) {
            return Integer.compare(this.priority, other.priority);
        }
    }

    /**
     * Builder for InterceptorChainImpl.
     */
    public static class Builder {
        private final List<PrioritizedInterceptor> interceptors = new CopyOnWriteArrayList<>();
        private LogInterceptor.ProcessingStage stage = LogInterceptor.ProcessingStage.PRE_PROCESS;

        public Builder add(String name, LogInterceptor interceptor) {
            return add(name, LogInterceptor.Priority.NORMAL, interceptor);
        }

        public Builder add(String name, LogInterceptor.Priority priority, LogInterceptor interceptor) {
            return add(name, priority.value(), interceptor);
        }

        public Builder add(String name, int priority, LogInterceptor interceptor) {
            interceptors.add(new PrioritizedInterceptor(name, priority, interceptor));
            return this;
        }

        public Builder stage(LogInterceptor.ProcessingStage stage) {
            this.stage = stage;
            return this;
        }

        public InterceptorChainImpl build() {
            // Sort by priority
            List<PrioritizedInterceptor> sorted = new ArrayList<>(interceptors);
            Collections.sort(sorted);

            return new InterceptorChainImpl(
                    Collections.unmodifiableList(sorted),
                    0,
                    null,
                    stage,
                    0
            );
        }
    }

    /**
     * Mutable registry for runtime interceptor management.
     */
    public static class Registry {
        private final List<PrioritizedInterceptor> interceptors = new CopyOnWriteArrayList<>();

        public void register(String name, LogInterceptor interceptor) {
            register(name, LogInterceptor.Priority.NORMAL, interceptor);
        }

        public void register(String name, LogInterceptor.Priority priority, LogInterceptor interceptor) {
            interceptors.add(new PrioritizedInterceptor(name, priority.value(), interceptor));
            // Re-sort on add
            interceptors.sort(Comparator.naturalOrder());
        }

        public void unregister(String name) {
            interceptors.removeIf(i -> i.name.equals(name));
        }

        public InterceptorChainImpl buildChain(LogInterceptor.ProcessingStage stage) {
            return new InterceptorChainImpl(
                    new ArrayList<>(interceptors),
                    0,
                    null,
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
