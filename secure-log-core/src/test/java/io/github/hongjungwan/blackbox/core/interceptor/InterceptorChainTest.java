package io.github.hongjungwan.blackbox.core.interceptor;

import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for InterceptorChain (FEAT-10: Interceptor System)
 */
@DisplayName("InterceptorChain")
class InterceptorChainTest {

    private LogEntry testEntry;

    @BeforeEach
    void setUp() {
        testEntry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("test message")
                .traceId("trace-123")
                .spanId("span-456")
                .payload(Map.of("key", "value"))
                .build();
    }

    @Nested
    @DisplayName("Chain Execution")
    class ChainExecutionTests {

        @Test
        @DisplayName("should execute interceptors in priority order")
        void shouldExecuteInPriorityOrder() {
            List<String> executionOrder = new ArrayList<>();

            InterceptorChain chain = InterceptorChain.builder()
                    .add("low", LogInterceptor.Priority.LOW, (entry, c) -> {
                        executionOrder.add("low");
                        return c.proceed(entry);
                    })
                    .add("high", LogInterceptor.Priority.HIGH, (entry, c) -> {
                        executionOrder.add("high");
                        return c.proceed(entry);
                    })
                    .add("normal", LogInterceptor.Priority.NORMAL, (entry, c) -> {
                        executionOrder.add("normal");
                        return c.proceed(entry);
                    })
                    .build();

            chain.execute(testEntry);

            assertThat(executionOrder).containsExactly("high", "normal", "low");
        }

        @Test
        @DisplayName("should pass modified entry through chain")
        void shouldPassModifiedEntry() {
            InterceptorChain chain = InterceptorChain.builder()
                    .add("modifier", (entry, c) -> {
                        LogEntry modified = LogEntry.builder()
                                .timestamp(entry.getTimestamp())
                                .level("DEBUG") // Changed
                                .message(entry.getMessage())
                                .traceId(entry.getTraceId())
                                .spanId(entry.getSpanId())
                                .payload(entry.getPayload())
                                .build();
                        return c.proceed(modified);
                    })
                    .add("verifier", (entry, c) -> {
                        assertThat(entry.getLevel()).isEqualTo("DEBUG");
                        return c.proceed(entry);
                    })
                    .build();

            LogEntry result = chain.execute(testEntry);

            assertThat(result.getLevel()).isEqualTo("DEBUG");
        }

        @Test
        @DisplayName("should return null when interceptor drops entry")
        void shouldReturnNullWhenDropped() {
            InterceptorChain chain = InterceptorChain.builder()
                    .add("dropper", (entry, c) -> null) // Drop
                    .add("never-called", (entry, c) -> {
                        fail("Should not be called");
                        return c.proceed(entry);
                    })
                    .build();

            LogEntry result = chain.execute(testEntry);

            assertThat(result).isNull();
        }

        @Test
        @DisplayName("should continue chain on interceptor exception")
        void shouldContinueOnException() {
            List<String> executionOrder = new ArrayList<>();

            InterceptorChain chain = InterceptorChain.builder()
                    .add("thrower", LogInterceptor.Priority.HIGH, (entry, c) -> {
                        executionOrder.add("thrower");
                        throw new RuntimeException("intentional");
                    })
                    .add("safe", LogInterceptor.Priority.LOW, (entry, c) -> {
                        executionOrder.add("safe");
                        return c.proceed(entry);
                    })
                    .build();

            LogEntry result = chain.execute(testEntry);

            assertThat(executionOrder).containsExactly("thrower", "safe");
            assertThat(result).isNotNull();
        }
    }

    @Nested
    @DisplayName("Registry")
    class RegistryTests {

        @Test
        @DisplayName("should register and unregister interceptors")
        void shouldRegisterAndUnregister() {
            InterceptorChain.Registry registry = new InterceptorChain.Registry();
            List<String> executionOrder = new ArrayList<>();

            registry.register("first", (entry, c) -> {
                executionOrder.add("first");
                return c.proceed(entry);
            });
            registry.register("second", (entry, c) -> {
                executionOrder.add("second");
                return c.proceed(entry);
            });

            assertThat(registry.size()).isEqualTo(2);

            registry.unregister("first");
            assertThat(registry.size()).isEqualTo(1);

            InterceptorChain chain = registry.buildChain(LogInterceptor.ProcessingStage.PRE_PROCESS);
            chain.execute(testEntry);

            assertThat(executionOrder).containsExactly("second");
        }

        @Test
        @DisplayName("should maintain priority order after registration")
        void shouldMaintainPriorityOrder() {
            InterceptorChain.Registry registry = new InterceptorChain.Registry();
            List<String> executionOrder = new ArrayList<>();

            registry.register("low", LogInterceptor.Priority.LOW, (entry, c) -> {
                executionOrder.add("low");
                return c.proceed(entry);
            });
            registry.register("high", LogInterceptor.Priority.HIGH, (entry, c) -> {
                executionOrder.add("high");
                return c.proceed(entry);
            });

            InterceptorChain chain = registry.buildChain(LogInterceptor.ProcessingStage.PRE_PROCESS);
            chain.execute(testEntry);

            assertThat(executionOrder).containsExactly("high", "low");
        }
    }

    @Nested
    @DisplayName("Chain Metadata")
    class MetadataTests {

        @Test
        @DisplayName("should provide metadata to interceptors")
        void shouldProvideMetadata() {
            java.util.concurrent.atomic.AtomicInteger interceptorCount = new java.util.concurrent.atomic.AtomicInteger(-1);

            InterceptorChain chain = InterceptorChain.builder()
                    .add("counter", (entry, c) -> {
                        interceptorCount.set(c.metadata().interceptorCount());
                        return c.proceed(entry);
                    })
                    .stage(LogInterceptor.ProcessingStage.PRE_PROCESS)
                    .build();

            chain.execute(testEntry);

            // Should have 1 interceptor
            assertThat(interceptorCount.get()).isEqualTo(1);
        }

        @Test
        @DisplayName("should track start time")
        void shouldTrackStartTime() {
            InterceptorChain chain = InterceptorChain.builder()
                    .add("timer", (entry, c) -> {
                        assertThat(c.metadata().startTimeNanos()).isGreaterThan(0);
                        return c.proceed(entry);
                    })
                    .build();

            chain.execute(testEntry);
        }

        @Test
        @DisplayName("should expose processing stage")
        void shouldExposeProcessingStage() {
            InterceptorChain chain = InterceptorChain.builder()
                    .add("stageChecker", (entry, c) -> {
                        assertThat(c.stage()).isEqualTo(LogInterceptor.ProcessingStage.POST_MASK);
                        return c.proceed(entry);
                    })
                    .stage(LogInterceptor.ProcessingStage.POST_MASK)
                    .build();

            chain.execute(testEntry);
        }
    }

    @Nested
    @DisplayName("Built-in Interceptors")
    class BuiltInInterceptorTests {

        @Test
        @DisplayName("sampling interceptor should drop based on rate")
        void samplingInterceptorShouldDrop() {
            // 0% sampling - drop all
            LogInterceptor sampler = BuiltInInterceptors.sampling(0);
            InterceptorChain chain = InterceptorChain.builder()
                    .add("sampler", sampler)
                    .build();

            LogEntry result = chain.execute(testEntry);

            assertThat(result).isNull();
        }

        @Test
        @DisplayName("sampling interceptor should keep all at 100%")
        void samplingInterceptorShouldKeepAll() {
            LogInterceptor sampler = BuiltInInterceptors.sampling(1.0);
            InterceptorChain chain = InterceptorChain.builder()
                    .add("sampler", sampler)
                    .build();

            LogEntry result = chain.execute(testEntry);

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("level filter should filter by level")
        void levelFilterShouldFilter() {
            LogInterceptor filter = BuiltInInterceptors.levelFilter(
                    java.util.Set.of("ERROR", "WARN")
            );
            InterceptorChain chain = InterceptorChain.builder()
                    .add("filter", filter)
                    .build();

            // INFO should be filtered
            LogEntry result = chain.execute(testEntry);
            assertThat(result).isNull();

            // ERROR should pass
            LogEntry errorEntry = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("ERROR")
                    .message("error message")
                    .build();
            result = chain.execute(errorEntry);
            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("field redaction should redact specified fields")
        void fieldRedactionShouldRedact() {
            LogEntry entryWithSensitive = LogEntry.builder()
                    .timestamp(System.currentTimeMillis())
                    .level("INFO")
                    .message("test")
                    .payload(Map.of("password", "secret123", "name", "John"))
                    .build();

            LogInterceptor redactor = BuiltInInterceptors.fieldRedaction(
                    java.util.Set.of("password")
            );
            InterceptorChain chain = InterceptorChain.builder()
                    .add("redactor", redactor)
                    .build();

            LogEntry result = chain.execute(entryWithSensitive);

            assertThat(result.getPayload().get("password")).isEqualTo("[REDACTED]");
            assertThat(result.getPayload().get("name")).isEqualTo("John");
        }
    }
}
