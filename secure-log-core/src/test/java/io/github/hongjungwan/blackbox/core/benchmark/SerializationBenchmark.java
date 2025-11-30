package io.github.hongjungwan.blackbox.core.benchmark;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * JMH Benchmark for Serialization (JSON + Zstd compression)
 *
 * Target: GC allocation < 1MB/sec under load
 */
@BenchmarkMode({Mode.Throughput, Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 1, jvmArgs = {"-Xmx512m", "-Xms512m"})
public class SerializationBenchmark {

    private LogSerializer serializer;
    private LogSerializer highCompressionSerializer;
    private LogSerializer lowCompressionSerializer;
    private LogEntry smallEntry;
    private LogEntry largeEntry;
    private byte[] serializedSmall;
    private byte[] serializedLarge;

    @Setup(Level.Trial)
    public void setup() {
        serializer = new LogSerializer();  // Default compression level 3
        highCompressionSerializer = new LogSerializer(19);
        lowCompressionSerializer = new LogSerializer(1);

        // Small entry
        smallEntry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Small message")
                .build();

        // Large entry with substantial payload
        StringBuilder largeMessage = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            largeMessage.append("This is a test message for compression benchmark. ");
        }

        largeEntry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .traceId("0af7651916cd43dd8448eb211c80319c")
                .spanId("b7ad6b7169203331")
                .context(Map.of(
                        "userId", "emp_1001",
                        "region", "KR",
                        "department", "Engineering",
                        "requestId", "req-12345678"
                ))
                .message(largeMessage.toString())
                .payload(Map.of(
                        "action", "bulk_update",
                        "records", 1000,
                        "status", "SUCCESS",
                        "details", "Processed 1000 employee records"
                ))
                .integrity("sha256:abc123def456...")
                .encryptedDek("ENC(base64encodedkey...)")
                .repeatCount(1)
                .build();

        // Pre-serialize for deserialization benchmarks
        serializedSmall = serializer.serialize(smallEntry);
        serializedLarge = serializer.serialize(largeEntry);
    }

    // Serialization benchmarks

    @Benchmark
    public void serializeSmallEntry(Blackhole bh) {
        bh.consume(serializer.serialize(smallEntry));
    }

    @Benchmark
    public void serializeLargeEntry(Blackhole bh) {
        bh.consume(serializer.serialize(largeEntry));
    }

    @Benchmark
    public void serializeLargeHighCompression(Blackhole bh) {
        bh.consume(highCompressionSerializer.serialize(largeEntry));
    }

    @Benchmark
    public void serializeLargeLowCompression(Blackhole bh) {
        bh.consume(lowCompressionSerializer.serialize(largeEntry));
    }

    // Deserialization benchmarks

    @Benchmark
    public void deserializeSmallEntry(Blackhole bh) {
        bh.consume(serializer.deserialize(serializedSmall));
    }

    @Benchmark
    public void deserializeLargeEntry(Blackhole bh) {
        bh.consume(serializer.deserialize(serializedLarge));
    }

    // Round-trip benchmarks

    @Benchmark
    public void roundTripSmall(Blackhole bh) {
        byte[] serialized = serializer.serialize(smallEntry);
        LogEntry deserialized = serializer.deserialize(serialized);
        bh.consume(deserialized);
    }

    @Benchmark
    public void roundTripLarge(Blackhole bh) {
        byte[] serialized = serializer.serialize(largeEntry);
        LogEntry deserialized = serializer.deserialize(serialized);
        bh.consume(deserialized);
    }

    // Compression ratio analysis (not a benchmark, but useful)
    @Benchmark
    @BenchmarkMode(Mode.SingleShotTime)
    public void measureCompressionRatio(Blackhole bh) {
        byte[] serialized = serializer.serialize(largeEntry);
        // Original would be much larger without compression
        bh.consume(serialized.length);
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(SerializationBenchmark.class.getSimpleName())
                .warmupIterations(3)
                .measurementIterations(5)
                .forks(1)
                .jvmArgs("-Xmx512m", "-Xms512m")
                .build();

        new Runner(opt).run();
    }
}
