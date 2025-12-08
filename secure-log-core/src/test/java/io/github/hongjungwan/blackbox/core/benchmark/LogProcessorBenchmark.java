package io.github.hongjungwan.blackbox.core.benchmark;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import io.github.hongjungwan.blackbox.core.internal.LogProcessor;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.security.KmsClient;
import io.github.hongjungwan.blackbox.core.internal.LogSerializer;
import io.github.hongjungwan.blackbox.core.internal.ResilientLogTransport;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * JMH Benchmark for Log Processor Pipeline
 *
 * Target: 20,000 logs/sec per instance (4 vCPU)
 */
@BenchmarkMode({Mode.Throughput, Mode.AverageTime})
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class LogProcessorBenchmark {

    private LogProcessor processor;
    private LogProcessor minimalProcessor;
    private LogEntry sampleEntry;
    private Path tempDir;
    private AtomicLong messageCounter;
    private NoOpTransport noOpTransport;

    @Setup(Level.Trial)
    public void setup() throws IOException {
        tempDir = Files.createTempDirectory("benchmark");
        messageCounter = new AtomicLong(0);

        // Full pipeline
        SecureLogConfig fullConfig = SecureLogConfig.builder()
                .piiMaskingEnabled(true)
                .encryptionEnabled(true)
                .integrityEnabled(true)
                .kmsFallbackEnabled(true)
                .fallbackDirectory(tempDir.toString())
                .build();

        noOpTransport = new NoOpTransport();

        processor = new LogProcessor(
                fullConfig,
                new PiiMasker(fullConfig),
                new EnvelopeEncryption(fullConfig, new KmsClient(fullConfig)),
                new MerkleChain(),
                new LogSerializer(),
                noOpTransport
        );

        // Minimal pipeline
        SecureLogConfig minimalConfig = SecureLogConfig.builder()
                .piiMaskingEnabled(false)
                .encryptionEnabled(false)
                .integrityEnabled(false)
                .kmsFallbackEnabled(true)
                .fallbackDirectory(tempDir.toString())
                .build();

        minimalProcessor = new LogProcessor(
                minimalConfig,
                new PiiMasker(minimalConfig),
                new EnvelopeEncryption(minimalConfig, new KmsClient(minimalConfig)),
                new MerkleChain(),
                new LogSerializer(),
                noOpTransport
        );

        // Sample entry
        sampleEntry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .traceId("trace-bench-001")
                .spanId("span-bench-001")
                .context(Map.of("userId", "user001", "region", "KR"))
                .message("Benchmark test message")
                .payload(Map.of(
                        "rrn", "123456-1234567",
                        "password", "secret",
                        "amount", 1000
                ))
                .build();
    }

    @TearDown(Level.Trial)
    public void tearDown() throws IOException {
        if (tempDir != null) {
            Files.walk(tempDir)
                    .sorted((a, b) -> -a.compareTo(b))
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (Exception ignored) {
                        }
                    });
        }
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.SECONDS)
    public void fullPipelineThroughput(Blackhole bh) {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Benchmark message " + messageCounter.incrementAndGet())
                .payload(Map.of("rrn", "123456-1234567"))
                .build();
        processor.process(entry);
        bh.consume(entry);
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.SECONDS)
    public void minimalPipelineThroughput(Blackhole bh) {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Minimal benchmark " + messageCounter.incrementAndGet())
                .build();
        minimalProcessor.process(entry);
        bh.consume(entry);
    }

    @Benchmark
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    @BenchmarkMode(Mode.AverageTime)
    public void fullPipelineLatency(Blackhole bh) {
        LogEntry entry = LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .message("Latency test " + messageCounter.incrementAndGet())
                .payload(Map.of("password", "secret"))
                .build();
        processor.process(entry);
        bh.consume(entry);
    }

    /**
     * No-op transport for benchmarking (avoids I/O overhead)
     */
    static class NoOpTransport extends ResilientLogTransport {
        private final AtomicLong sendCount = new AtomicLong(0);

        NoOpTransport() throws IOException {
            super(SecureLogConfig.builder()
                            .fallbackDirectory(Files.createTempDirectory("noop").toString())
                            .build(),
                    new LogSerializer());
        }

        @Override
        public void send(byte[] data) {
            sendCount.incrementAndGet();
            // No-op - don't actually send
        }

        public long getSendCount() {
            return sendCount.get();
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(LogProcessorBenchmark.class.getSimpleName())
                .warmupIterations(3)
                .measurementIterations(5)
                .forks(1)
                .build();

        new Runner(opt).run();
    }
}
