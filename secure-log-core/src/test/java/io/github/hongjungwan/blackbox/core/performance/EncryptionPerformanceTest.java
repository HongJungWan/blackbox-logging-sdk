package io.github.hongjungwan.blackbox.core.performance;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.MerkleChain;
import io.github.hongjungwan.blackbox.core.security.EnvelopeEncryption;
import io.github.hongjungwan.blackbox.core.security.KmsClient;
import io.github.hongjungwan.blackbox.core.security.PiiMasker;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Performance tests for encryption and security pipeline components.
 *
 * <p>Goal: Encryption logic impact on API response time should be less than 4ms.</p>
 *
 * <p>Test categories:</p>
 * <ul>
 *   <li>Single encryption call latency</li>
 *   <li>Average encryption time over 1000 calls</li>
 *   <li>Full pipeline (masking + hash chain + encryption) latency</li>
 * </ul>
 *
 * @since 8.0.0
 */
@DisplayName("Encryption Performance Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EncryptionPerformanceTest {

    // Performance target: 4ms
    private static final long TARGET_LATENCY_MS = 4;
    private static final int WARMUP_ITERATIONS = 100;
    private static final int MEASUREMENT_ITERATIONS = 1000;

    private EnvelopeEncryption envelopeEncryption;
    private PiiMasker piiMasker;
    private MerkleChain merkleChain;
    private SecureLogConfig config;

    @BeforeAll
    void setUpAll() {
        config = SecureLogConfig.builder()
                .kmsFallbackEnabled(true)
                .piiPatterns(List.of("rrn", "credit_card", "password", "ssn"))
                .build();

        KmsClient kmsClient = new KmsClient(config);
        envelopeEncryption = new EnvelopeEncryption(config, kmsClient);
        piiMasker = new PiiMasker(config);
        merkleChain = new MerkleChain();

        // Warmup to trigger JIT compilation
        warmup();
    }

    @BeforeEach
    void setUp() {
        merkleChain.reset();
    }

    private void warmup() {
        LogEntry warmupEntry = createTestLogEntry();
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            envelopeEncryption.encrypt(warmupEntry);
            piiMasker.mask(warmupEntry);
            merkleChain.addToChain(warmupEntry);
            merkleChain.reset();
        }
    }

    private LogEntry createTestLogEntry() {
        return LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .traceId("trace-" + System.nanoTime())
                .spanId("span-" + System.nanoTime())
                .context(Map.of("userId", "user001", "region", "KR"))
                .message("Employee action logged for user")
                .payload(Map.of(
                        "employeeId", "EMP-12345",
                        "action", "LOGIN",
                        "department", "Engineering",
                        "ipAddress", "192.168.1.100"
                ))
                .build();
    }

    private LogEntry createLargePayloadLogEntry() {
        Map<String, Object> largePayload = new HashMap<>();
        for (int i = 0; i < 50; i++) {
            largePayload.put("field_" + i, "value_" + i + "_".repeat(20));
        }
        largePayload.put("nestedData", Map.of(
                "level1", Map.of(
                        "level2", Map.of(
                                "level3", "deep nested value"
                        )
                )
        ));

        return LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .traceId("trace-" + System.nanoTime())
                .spanId("span-" + System.nanoTime())
                .message("Large payload log entry")
                .payload(largePayload)
                .build();
    }

    private LogEntry createPiiLogEntry() {
        return LogEntry.builder()
                .timestamp(System.currentTimeMillis())
                .level("INFO")
                .traceId("trace-" + System.nanoTime())
                .message("Employee data with PII: RRN 123456-1234567, Card 1234-5678-9012-3456")
                .payload(Map.of(
                        "rrn", "123456-1234567",
                        "credit_card", "1234-5678-9012-3456",
                        "password", "secretPassword123",
                        "ssn", "123-45-6789",
                        "employeeName", "John Doe",
                        "email", "john.doe@example.com"
                ))
                .build();
    }

    @Nested
    @DisplayName("Single Call Latency Tests")
    class SingleCallLatencyTests {

        @Test
        @DisplayName("Encryption should complete within 4ms for standard payload")
        void encryptionShouldCompleteWithin4ms() {
            // Given
            LogEntry entry = createTestLogEntry();

            // When
            long start = System.nanoTime();
            LogEntry encrypted = envelopeEncryption.encrypt(entry);
            long elapsedNs = System.nanoTime() - start;
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNs);

            // Then
            assertThat(encrypted).isNotNull();
            assertThat(encrypted.getEncryptedDek()).isNotNull();
            assertThat(encrypted.getPayload()).containsKey("encrypted");

            System.out.println("[Single Encryption] Elapsed: " + elapsedMs + " ms (" + elapsedNs + " ns)");
            assertThat(elapsedMs).isLessThan(TARGET_LATENCY_MS);
        }

        @Test
        @DisplayName("Hash chain should complete within 4ms")
        void hashChainShouldCompleteWithin4ms() {
            // Given
            LogEntry entry = createTestLogEntry();

            // When
            long start = System.nanoTime();
            LogEntry chained = merkleChain.addToChain(entry);
            long elapsedNs = System.nanoTime() - start;
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNs);

            // Then
            assertThat(chained.getIntegrity()).isNotNull();
            assertThat(chained.getIntegrity()).startsWith("sha256:");

            System.out.println("[Single Hash Chain] Elapsed: " + elapsedMs + " ms (" + elapsedNs + " ns)");
            assertThat(elapsedMs).isLessThan(TARGET_LATENCY_MS);
        }

        @Test
        @DisplayName("PII masking should complete within 4ms")
        void piiMaskingShouldCompleteWithin4ms() {
            // Given
            LogEntry entry = createPiiLogEntry();

            // When
            long start = System.nanoTime();
            LogEntry masked = piiMasker.mask(entry);
            long elapsedNs = System.nanoTime() - start;
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNs);

            // Then
            assertThat(masked.getMessage()).doesNotContain("123456-1234567");
            assertThat(masked.getPayload().get("rrn").toString()).contains("*");

            System.out.println("[Single PII Masking] Elapsed: " + elapsedMs + " ms (" + elapsedNs + " ns)");
            assertThat(elapsedMs).isLessThan(TARGET_LATENCY_MS);
        }
    }

    @Nested
    @DisplayName("Average Latency Tests (1000 iterations)")
    class AverageLatencyTests {

        @Test
        @DisplayName("Average encryption time over 1000 calls should be under 4ms")
        void averageEncryptionTimeOver1000Calls() {
            // Given
            LogEntry entry = createTestLogEntry();
            List<Long> latencies = new ArrayList<>(MEASUREMENT_ITERATIONS);

            // When
            for (int i = 0; i < MEASUREMENT_ITERATIONS; i++) {
                long start = System.nanoTime();
                envelopeEncryption.encrypt(entry);
                latencies.add(System.nanoTime() - start);
            }

            // Then
            double avgNs = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            double avgMs = avgNs / 1_000_000.0;
            long maxNs = latencies.stream().mapToLong(Long::longValue).max().orElse(0);
            long minNs = latencies.stream().mapToLong(Long::longValue).min().orElse(0);
            double p99Ns = calculatePercentile(latencies, 99);

            System.out.println("\n=== Encryption Performance (1000 iterations) ===");
            System.out.printf("Average: %.3f ms%n", avgMs);
            System.out.printf("Min: %.3f ms%n", minNs / 1_000_000.0);
            System.out.printf("Max: %.3f ms%n", maxNs / 1_000_000.0);
            System.out.printf("P99: %.3f ms%n", p99Ns / 1_000_000.0);

            assertThat(avgMs).isLessThan(TARGET_LATENCY_MS);
        }

        @Test
        @DisplayName("Average hash chain time over 1000 calls should be under 4ms")
        void averageHashChainTimeOver1000Calls() {
            // Given
            List<Long> latencies = new ArrayList<>(MEASUREMENT_ITERATIONS);

            // When
            for (int i = 0; i < MEASUREMENT_ITERATIONS; i++) {
                LogEntry entry = createTestLogEntry();
                long start = System.nanoTime();
                merkleChain.addToChain(entry);
                latencies.add(System.nanoTime() - start);
            }

            // Then
            double avgNs = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            double avgMs = avgNs / 1_000_000.0;
            long maxNs = latencies.stream().mapToLong(Long::longValue).max().orElse(0);
            long minNs = latencies.stream().mapToLong(Long::longValue).min().orElse(0);
            double p99Ns = calculatePercentile(latencies, 99);

            System.out.println("\n=== Hash Chain Performance (1000 iterations) ===");
            System.out.printf("Average: %.3f ms%n", avgMs);
            System.out.printf("Min: %.3f ms%n", minNs / 1_000_000.0);
            System.out.printf("Max: %.3f ms%n", maxNs / 1_000_000.0);
            System.out.printf("P99: %.3f ms%n", p99Ns / 1_000_000.0);

            assertThat(avgMs).isLessThan(TARGET_LATENCY_MS);
        }

        @Test
        @DisplayName("Average PII masking time over 1000 calls should be under 4ms")
        void averagePiiMaskingTimeOver1000Calls() {
            // Given
            LogEntry entry = createPiiLogEntry();
            List<Long> latencies = new ArrayList<>(MEASUREMENT_ITERATIONS);

            // When
            for (int i = 0; i < MEASUREMENT_ITERATIONS; i++) {
                long start = System.nanoTime();
                piiMasker.mask(entry);
                latencies.add(System.nanoTime() - start);
            }

            // Then
            double avgNs = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            double avgMs = avgNs / 1_000_000.0;
            long maxNs = latencies.stream().mapToLong(Long::longValue).max().orElse(0);
            long minNs = latencies.stream().mapToLong(Long::longValue).min().orElse(0);
            double p99Ns = calculatePercentile(latencies, 99);

            System.out.println("\n=== PII Masking Performance (1000 iterations) ===");
            System.out.printf("Average: %.3f ms%n", avgMs);
            System.out.printf("Min: %.3f ms%n", minNs / 1_000_000.0);
            System.out.printf("Max: %.3f ms%n", maxNs / 1_000_000.0);
            System.out.printf("P99: %.3f ms%n", p99Ns / 1_000_000.0);

            assertThat(avgMs).isLessThan(TARGET_LATENCY_MS);
        }
    }

    @Nested
    @DisplayName("Full Pipeline Performance Tests")
    class FullPipelineTests {

        @Test
        @DisplayName("Full pipeline (masking + hash + encryption) should complete within 4ms")
        void fullPipelineShouldCompleteWithin4ms() {
            // Given
            LogEntry entry = createPiiLogEntry();
            merkleChain.reset();

            // When - Full pipeline: mask -> hash chain -> encrypt
            long start = System.nanoTime();

            LogEntry masked = piiMasker.mask(entry);
            LogEntry chained = merkleChain.addToChain(masked);
            LogEntry encrypted = envelopeEncryption.encrypt(chained);

            long elapsedNs = System.nanoTime() - start;
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNs);

            // Then
            assertThat(encrypted).isNotNull();
            assertThat(encrypted.getEncryptedDek()).isNotNull();
            assertThat(encrypted.getIntegrity()).isNotNull();

            System.out.println("\n[Full Pipeline Single Call] Elapsed: " + elapsedMs + " ms (" + elapsedNs + " ns)");
            assertThat(elapsedMs).isLessThan(TARGET_LATENCY_MS);
        }

        @Test
        @DisplayName("Average full pipeline time over 1000 calls should be under 4ms")
        void averageFullPipelineTimeOver1000Calls() {
            // Given
            List<Long> latencies = new ArrayList<>(MEASUREMENT_ITERATIONS);

            // When
            for (int i = 0; i < MEASUREMENT_ITERATIONS; i++) {
                LogEntry entry = createPiiLogEntry();

                long start = System.nanoTime();

                LogEntry masked = piiMasker.mask(entry);
                LogEntry chained = merkleChain.addToChain(masked);
                envelopeEncryption.encrypt(chained);

                latencies.add(System.nanoTime() - start);
            }

            // Then
            double avgNs = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            double avgMs = avgNs / 1_000_000.0;
            long maxNs = latencies.stream().mapToLong(Long::longValue).max().orElse(0);
            long minNs = latencies.stream().mapToLong(Long::longValue).min().orElse(0);
            double p99Ns = calculatePercentile(latencies, 99);

            System.out.println("\n=== Full Pipeline Performance (1000 iterations) ===");
            System.out.printf("Average: %.3f ms%n", avgMs);
            System.out.printf("Min: %.3f ms%n", minNs / 1_000_000.0);
            System.out.printf("Max: %.3f ms%n", maxNs / 1_000_000.0);
            System.out.printf("P99: %.3f ms%n", p99Ns / 1_000_000.0);

            assertThat(avgMs).isLessThan(TARGET_LATENCY_MS);
        }
    }

    @Nested
    @DisplayName("Large Payload Performance Tests")
    class LargePayloadTests {

        @Test
        @DisplayName("Encryption of large payload should complete within 4ms")
        void largePayloadEncryptionShouldCompleteWithin4ms() {
            // Given
            LogEntry entry = createLargePayloadLogEntry();

            // When
            long start = System.nanoTime();
            LogEntry encrypted = envelopeEncryption.encrypt(entry);
            long elapsedNs = System.nanoTime() - start;
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNs);

            // Then
            assertThat(encrypted).isNotNull();
            System.out.println("\n[Large Payload Encryption] Elapsed: " + elapsedMs + " ms (" + elapsedNs + " ns)");
            assertThat(elapsedMs).isLessThan(TARGET_LATENCY_MS);
        }

        @Test
        @DisplayName("Average large payload encryption over 1000 calls")
        void averageLargePayloadEncryptionTime() {
            // Given
            LogEntry entry = createLargePayloadLogEntry();
            List<Long> latencies = new ArrayList<>(MEASUREMENT_ITERATIONS);

            // When
            for (int i = 0; i < MEASUREMENT_ITERATIONS; i++) {
                long start = System.nanoTime();
                envelopeEncryption.encrypt(entry);
                latencies.add(System.nanoTime() - start);
            }

            // Then
            double avgNs = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            double avgMs = avgNs / 1_000_000.0;
            double p99Ns = calculatePercentile(latencies, 99);

            System.out.println("\n=== Large Payload Encryption Performance (1000 iterations) ===");
            System.out.printf("Average: %.3f ms%n", avgMs);
            System.out.printf("P99: %.3f ms%n", p99Ns / 1_000_000.0);

            assertThat(avgMs).isLessThan(TARGET_LATENCY_MS);
        }
    }

    @Nested
    @DisplayName("Performance Summary Report")
    class PerformanceSummaryReport {

        @Test
        @DisplayName("Generate comprehensive performance report")
        void generatePerformanceReport() {
            // Measure each component
            LogEntry piiEntry = createPiiLogEntry();
            LogEntry standardEntry = createTestLogEntry();

            // Collect metrics
            List<Long> encryptionLatencies = new ArrayList<>(MEASUREMENT_ITERATIONS);
            List<Long> hashLatencies = new ArrayList<>(MEASUREMENT_ITERATIONS);
            List<Long> maskingLatencies = new ArrayList<>(MEASUREMENT_ITERATIONS);
            List<Long> pipelineLatencies = new ArrayList<>(MEASUREMENT_ITERATIONS);

            for (int i = 0; i < MEASUREMENT_ITERATIONS; i++) {
                // Encryption
                long start = System.nanoTime();
                envelopeEncryption.encrypt(standardEntry);
                encryptionLatencies.add(System.nanoTime() - start);

                // Hash Chain
                start = System.nanoTime();
                merkleChain.addToChain(standardEntry);
                hashLatencies.add(System.nanoTime() - start);

                // PII Masking
                start = System.nanoTime();
                piiMasker.mask(piiEntry);
                maskingLatencies.add(System.nanoTime() - start);

                // Full Pipeline
                start = System.nanoTime();
                LogEntry masked = piiMasker.mask(piiEntry);
                LogEntry chained = merkleChain.addToChain(masked);
                envelopeEncryption.encrypt(chained);
                pipelineLatencies.add(System.nanoTime() - start);
            }

            // Generate report
            System.out.println("\n");
            System.out.println("=".repeat(60));
            System.out.println("          ENCRYPTION PERFORMANCE TEST RESULTS");
            System.out.println("=".repeat(60));
            System.out.println();

            printComponentMetrics("AES-256-GCM Encryption", encryptionLatencies);
            printComponentMetrics("SHA-256 Hash Chain", hashLatencies);
            printComponentMetrics("PII Masking", maskingLatencies);
            printComponentMetrics("Full Pipeline (Mask+Hash+Encrypt)", pipelineLatencies);

            System.out.println("-".repeat(60));

            double encryptionAvgMs = encryptionLatencies.stream().mapToLong(Long::longValue).average().orElse(0) / 1_000_000.0;
            double hashAvgMs = hashLatencies.stream().mapToLong(Long::longValue).average().orElse(0) / 1_000_000.0;
            double maskingAvgMs = maskingLatencies.stream().mapToLong(Long::longValue).average().orElse(0) / 1_000_000.0;
            double pipelineAvgMs = pipelineLatencies.stream().mapToLong(Long::longValue).average().orElse(0) / 1_000_000.0;

            boolean encryptionPassed = encryptionAvgMs < TARGET_LATENCY_MS;
            boolean hashPassed = hashAvgMs < TARGET_LATENCY_MS;
            boolean maskingPassed = maskingAvgMs < TARGET_LATENCY_MS;
            boolean pipelinePassed = pipelineAvgMs < TARGET_LATENCY_MS;

            System.out.println();
            System.out.println("TARGET: < " + TARGET_LATENCY_MS + " ms");
            System.out.println();
            System.out.printf("Encryption:    %.3f ms  [%s]%n", encryptionAvgMs, encryptionPassed ? "PASS" : "FAIL");
            System.out.printf("Hash Chain:    %.3f ms  [%s]%n", hashAvgMs, hashPassed ? "PASS" : "FAIL");
            System.out.printf("PII Masking:   %.3f ms  [%s]%n", maskingAvgMs, maskingPassed ? "PASS" : "FAIL");
            System.out.printf("Full Pipeline: %.3f ms  [%s]%n", pipelineAvgMs, pipelinePassed ? "PASS" : "FAIL");
            System.out.println();
            System.out.println("=".repeat(60));
            System.out.println("OVERALL RESULT: " + (encryptionPassed && hashPassed && maskingPassed && pipelinePassed ? "PASS" : "FAIL"));
            System.out.println("=".repeat(60));

            // Assert all pass
            assertThat(encryptionAvgMs).isLessThan(TARGET_LATENCY_MS);
            assertThat(hashAvgMs).isLessThan(TARGET_LATENCY_MS);
            assertThat(maskingAvgMs).isLessThan(TARGET_LATENCY_MS);
            assertThat(pipelineAvgMs).isLessThan(TARGET_LATENCY_MS);
        }

        private void printComponentMetrics(String componentName, List<Long> latencies) {
            double avgNs = latencies.stream().mapToLong(Long::longValue).average().orElse(0);
            double avgMs = avgNs / 1_000_000.0;
            long minNs = latencies.stream().mapToLong(Long::longValue).min().orElse(0);
            long maxNs = latencies.stream().mapToLong(Long::longValue).max().orElse(0);
            double p50Ns = calculatePercentile(latencies, 50);
            double p99Ns = calculatePercentile(latencies, 99);

            System.out.println(componentName + ":");
            System.out.printf("  Average: %.3f ms%n", avgMs);
            System.out.printf("  Min:     %.3f ms%n", minNs / 1_000_000.0);
            System.out.printf("  Max:     %.3f ms%n", maxNs / 1_000_000.0);
            System.out.printf("  P50:     %.3f ms%n", p50Ns / 1_000_000.0);
            System.out.printf("  P99:     %.3f ms%n", p99Ns / 1_000_000.0);
            System.out.println();
        }
    }

    private double calculatePercentile(List<Long> latencies, int percentile) {
        List<Long> sorted = new ArrayList<>(latencies);
        sorted.sort(Long::compareTo);
        int index = (int) Math.ceil(percentile / 100.0 * sorted.size()) - 1;
        return sorted.get(Math.max(0, index));
    }
}
