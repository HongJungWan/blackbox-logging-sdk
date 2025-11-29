package io.github.hongjungwan.blackbox.core.benchmark;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.core.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.masking.PiiMasker;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * JMH Benchmark for PII Masking
 *
 * Run with: ./gradlew :secure-log-core:test --tests "*PiiMaskerBenchmark*"
 * Or directly: java -jar benchmarks.jar PiiMaskerBenchmark
 */
@BenchmarkMode({Mode.Throughput, Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class PiiMaskerBenchmark {

    private PiiMasker masker;
    private LogEntry simpleEntry;
    private LogEntry complexEntry;
    private LogEntry nestedEntry;

    @Setup(Level.Trial)
    public void setup() {
        SecureLogConfig config = SecureLogConfig.builder()
                .piiMaskingEnabled(true)
                .build();
        masker = new PiiMasker(config);

        // Simple entry with one PII field
        simpleEntry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("User action")
                .payload(Map.of("password", "secret123"))
                .build();

        // Complex entry with multiple PII fields
        Map<String, Object> complexPayload = new HashMap<>();
        complexPayload.put("rrn", "123456-1234567");
        complexPayload.put("credit_card", "1234-5678-9012-3456");
        complexPayload.put("password", "mySecretPassword");
        complexPayload.put("ssn", "123-45-6789");
        complexPayload.put("name", "John Doe");
        complexPayload.put("amount", 1000);

        complexEntry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .traceId("trace-123")
                .spanId("span-456")
                .context(Map.of("userId", "user001"))
                .message("Payment processed")
                .payload(complexPayload)
                .build();

        // Nested entry
        Map<String, Object> nested = new HashMap<>();
        nested.put("rrn", "123456-1234567");
        nested.put("password", "innerSecret");

        Map<String, Object> nestedPayload = new HashMap<>();
        nestedPayload.put("user", nested);
        nestedPayload.put("credit_card", "9999-8888-7777-6666");

        nestedEntry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Nested data")
                .payload(nestedPayload)
                .build();
    }

    @Benchmark
    public void maskSimpleEntry(Blackhole bh) {
        bh.consume(masker.mask(simpleEntry));
    }

    @Benchmark
    public void maskComplexEntry(Blackhole bh) {
        bh.consume(masker.mask(complexEntry));
    }

    @Benchmark
    public void maskNestedEntry(Blackhole bh) {
        bh.consume(masker.mask(nestedEntry));
    }

    @Benchmark
    public void maskNullPayload(Blackhole bh) {
        LogEntry nullPayloadEntry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("No payload")
                .build();
        bh.consume(masker.mask(nullPayloadEntry));
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(PiiMaskerBenchmark.class.getSimpleName())
                .warmupIterations(3)
                .measurementIterations(5)
                .forks(1)
                .build();

        new Runner(opt).run();
    }
}
