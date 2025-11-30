package io.github.hongjungwan.blackbox.core.context;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for LoggingContext (FEAT-09: Context Propagation)
 */
@DisplayName("LoggingContext")
class LoggingContextTest {

    @BeforeEach
    void setUp() {
        // Reset to empty context before each test
        LoggingContext.empty().makeCurrent().close();
    }

    @Nested
    @DisplayName("Builder")
    class BuilderTests {

        @Test
        @DisplayName("should generate traceId and spanId when not provided")
        void shouldGenerateIds() {
            LoggingContext ctx = LoggingContext.builder().build();

            assertThat(ctx.getTraceId()).isNotNull().isNotEmpty();
            assertThat(ctx.getSpanId()).isNotNull().isNotEmpty();
        }

        @Test
        @DisplayName("should use provided traceId and spanId")
        void shouldUseProvidedIds() {
            LoggingContext ctx = LoggingContext.builder()
                    .traceId("test-trace-id")
                    .spanId("test-span-id")
                    .build();

            assertThat(ctx.getTraceId()).isEqualTo("test-trace-id");
            assertThat(ctx.getSpanId()).isEqualTo("test-span-id");
        }

        @Test
        @DisplayName("should store baggage items")
        void shouldStoreBaggage() {
            LoggingContext ctx = LoggingContext.builder()
                    .addBaggage("user_id", "emp_1001")
                    .addBaggage("region", "KR")
                    .build();

            assertThat(ctx.getBaggage())
                    .containsEntry("user_id", "emp_1001")
                    .containsEntry("region", "KR");
        }

        @Test
        @DisplayName("should support HR domain helpers")
        void shouldSupportHrDomainHelpers() {
            LoggingContext ctx = LoggingContext.builder()
                    .userId("emp_1001")
                    .department("HR")
                    .operation("salary_update")
                    .build();

            assertThat(ctx.getBaggageItem("user_id")).contains("emp_1001");
            assertThat(ctx.getBaggageItem("department")).contains("HR");
            assertThat(ctx.getBaggageItem("operation")).contains("salary_update");
        }

        @Test
        @DisplayName("should create new trace with newTrace()")
        void shouldCreateNewTrace() {
            LoggingContext ctx = LoggingContext.builder()
                    .newTrace()
                    .build();

            assertThat(ctx.getTraceId()).isNotNull().hasSize(32); // 2 * 16 hex chars
            assertThat(ctx.getSpanId()).isNotNull();
            assertThat(ctx.getParentSpanId()).isNull();
        }
    }

    @Nested
    @DisplayName("ThreadLocal Scope")
    class ThreadLocalScopeTests {

        @Test
        @DisplayName("should make context current via ThreadLocal")
        void shouldMakeContextCurrent() {
            LoggingContext ctx = LoggingContext.builder()
                    .traceId("my-trace")
                    .build();

            try (LoggingContext.Scope ignored = ctx.makeCurrent()) {
                assertThat(LoggingContext.current().getTraceId()).isEqualTo("my-trace");
            }
        }

        @Test
        @DisplayName("should restore previous context on scope close")
        void shouldRestorePreviousContext() {
            LoggingContext outer = LoggingContext.builder().traceId("outer").build();
            LoggingContext inner = LoggingContext.builder().traceId("inner").build();

            try (LoggingContext.Scope outerScope = outer.makeCurrent()) {
                assertThat(LoggingContext.current().getTraceId()).isEqualTo("outer");

                try (LoggingContext.Scope innerScope = inner.makeCurrent()) {
                    assertThat(LoggingContext.current().getTraceId()).isEqualTo("inner");
                }

                assertThat(LoggingContext.current().getTraceId()).isEqualTo("outer");
            }
        }

        @Test
        @DisplayName("should isolate context between threads")
        void shouldIsolateContextBetweenThreads() throws Exception {
            LoggingContext ctx = LoggingContext.builder().traceId("main-thread").build();
            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<String> otherThreadTrace = new AtomicReference<>();

            try (LoggingContext.Scope ignored = ctx.makeCurrent()) {
                Thread thread = new Thread(() -> {
                    otherThreadTrace.set(LoggingContext.current().getTraceId());
                    latch.countDown();
                });
                thread.start();
                latch.await(1, TimeUnit.SECONDS);
            }

            // Other thread should not see main thread's context
            assertThat(otherThreadTrace.get()).isNotEqualTo("main-thread");
        }
    }

    @Nested
    @DisplayName("Context Propagation")
    class ContextPropagationTests {

        @Test
        @DisplayName("should wrap Runnable with context")
        void shouldWrapRunnableWithContext() throws Exception {
            LoggingContext ctx = LoggingContext.builder().traceId("wrapped-trace").build();
            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<String> capturedTrace = new AtomicReference<>();

            Runnable wrapped = ctx.wrap(() -> {
                capturedTrace.set(LoggingContext.current().getTraceId());
                latch.countDown();
            });

            // Run in different thread
            ExecutorService executor = Executors.newSingleThreadExecutor();
            executor.submit(wrapped);
            latch.await(1, TimeUnit.SECONDS);
            executor.shutdown();

            assertThat(capturedTrace.get()).isEqualTo("wrapped-trace");
        }

        @Test
        @DisplayName("should wrap Callable with context")
        void shouldWrapCallableWithContext() throws Exception {
            LoggingContext ctx = LoggingContext.builder().traceId("callable-trace").build();

            java.util.concurrent.Callable<String> wrapped = ctx.wrap(() ->
                    LoggingContext.current().getTraceId()
            );

            ExecutorService executor = Executors.newSingleThreadExecutor();
            String result = executor.submit(wrapped).get(1, TimeUnit.SECONDS);
            executor.shutdown();

            assertThat(result).isEqualTo("callable-trace");
        }

        @Test
        @DisplayName("should create child context with parent span id")
        void shouldCreateChildContext() {
            LoggingContext parent = LoggingContext.builder()
                    .traceId("parent-trace")
                    .spanId("parent-span")
                    .build();

            LoggingContext child = parent.createChild();

            assertThat(child.getTraceId()).isEqualTo("parent-trace");
            assertThat(child.getParentSpanId()).isEqualTo("parent-span");
            assertThat(child.getSpanId()).isNotEqualTo("parent-span");
        }
    }

    @Nested
    @DisplayName("W3C Trace Context")
    class W3CTraceContextTests {

        @Test
        @DisplayName("should export to W3C traceparent header")
        void shouldExportToTraceParent() {
            LoggingContext ctx = LoggingContext.builder()
                    .traceId("0af7651916cd43dd8448eb211c80319c")
                    .spanId("b7ad6b7169203331")
                    .build();

            String traceParent = ctx.toTraceParent();

            assertThat(traceParent).isEqualTo(
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
            );
        }

        @Test
        @DisplayName("should parse W3C traceparent header")
        void shouldParseTraceParent() {
            LoggingContext ctx = LoggingContext.fromTraceParent(
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
            );

            assertThat(ctx.getTraceId()).isEqualTo("0af7651916cd43dd8448eb211c80319c");
            assertThat(ctx.getParentSpanId()).isEqualTo("b7ad6b7169203331");
        }

        @Test
        @DisplayName("should export baggage to header")
        void shouldExportBaggageToHeader() {
            LoggingContext ctx = LoggingContext.builder()
                    .addBaggage("user_id", "emp_1001")
                    .addBaggage("region", "KR")
                    .build();

            String baggage = ctx.toBaggageHeader();

            assertThat(baggage).contains("user_id=emp_1001");
            assertThat(baggage).contains("region=KR");
        }
    }

    @Nested
    @DisplayName("MDC Export")
    class MdcExportTests {

        @Test
        @DisplayName("should export context to MDC map")
        void shouldExportToMdc() {
            LoggingContext ctx = LoggingContext.builder()
                    .traceId("mdc-trace")
                    .spanId("mdc-span")
                    .addBaggage("user_id", "emp_1001")
                    .build();

            Map<String, String> mdc = ctx.toMdc();

            assertThat(mdc)
                    .containsEntry("traceId", "mdc-trace")
                    .containsEntry("spanId", "mdc-span")
                    .containsEntry("user_id", "emp_1001");
        }
    }
}
