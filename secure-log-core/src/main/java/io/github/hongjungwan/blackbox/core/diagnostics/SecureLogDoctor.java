package io.github.hongjungwan.blackbox.core.diagnostics;

import io.github.hongjungwan.blackbox.core.config.SecureLogConfig;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Doctor Service - Self-diagnostics for SDK health
 *
 * Runs on initialization (SmartLifecycle.start) to verify:
 * 1. KMS connectivity
 * 2. Disk write permissions for fallback directory
 * 3. Off-heap memory allocation capability
 *
 * On failure: Logs warning and auto-switches to Fallback Mode
 */
@Slf4j
public class SecureLogDoctor {

    private final SecureLogConfig config;
    private final List<DiagnosticResult> results = new ArrayList<>();

    public SecureLogDoctor(SecureLogConfig config) {
        this.config = config;
    }

    /**
     * Run all diagnostic checks
     */
    public DiagnosticReport diagnose() {
        log.info("Running SecureLog diagnostic checks...");

        results.clear();

        // Check 1: KMS Connectivity
        results.add(checkKmsConnectivity());

        // Check 2: Disk Write Permission
        results.add(checkDiskWritePermission());

        // Check 3: Off-heap Memory Allocation
        results.add(checkOffHeapMemory());

        // Generate report
        DiagnosticReport report = new DiagnosticReport(results);

        if (report.hasFailures()) {
            log.warn("Diagnostic failures detected:");
            report.getFailedChecks().forEach(result ->
                    log.warn("  - {}: {}", result.getName(), result.getMessage())
            );
            log.warn("Recommendation: Switch to FALLBACK mode");
        } else {
            log.info("All diagnostic checks passed successfully");
        }

        return report;
    }

    /**
     * Check 1: KMS Connectivity
     */
    private DiagnosticResult checkKmsConnectivity() {
        if (config.getKmsEndpoint() == null) {
            return DiagnosticResult.warning("KMS Connectivity", "KMS endpoint not configured - using fallback encryption");
        }

        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(config.getKmsTimeoutMs()))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.getKmsEndpoint() + "/health"))
                    .timeout(Duration.ofMillis(config.getKmsTimeoutMs()))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return DiagnosticResult.success("KMS Connectivity", "Successfully connected to KMS");
            } else {
                return DiagnosticResult.failure("KMS Connectivity", "KMS returned status: " + response.statusCode());
            }

        } catch (Exception e) {
            return DiagnosticResult.failure("KMS Connectivity", "Failed to connect: " + e.getMessage());
        }
    }

    /**
     * Check 2: Disk Write Permission
     */
    private DiagnosticResult checkDiskWritePermission() {
        try {
            Path fallbackDir = Paths.get(config.getFallbackDirectory());

            // Create directory if it doesn't exist
            Files.createDirectories(fallbackDir);

            // Try writing a test file
            Path testFile = fallbackDir.resolve(".test-write");
            Files.writeString(testFile, "test");

            // Try reading back
            String content = Files.readString(testFile);

            // Cleanup
            Files.deleteIfExists(testFile);

            if ("test".equals(content)) {
                return DiagnosticResult.success("Disk Write Permission",
                        "Fallback directory writable: " + fallbackDir);
            } else {
                return DiagnosticResult.failure("Disk Write Permission",
                        "Write verification failed");
            }

        } catch (IOException e) {
            return DiagnosticResult.failure("Disk Write Permission",
                    "Cannot write to fallback directory: " + e.getMessage());
        }
    }

    /**
     * Check 3: Off-heap Memory Allocation
     */
    private DiagnosticResult checkOffHeapMemory() {
        try {
            // Try allocating a DirectByteBuffer (off-heap)
            int testSize = 1024 * 1024; // 1 MB
            ByteBuffer buffer = ByteBuffer.allocateDirect(testSize);

            // Verify allocation
            if (buffer.isDirect() && buffer.capacity() == testSize) {
                return DiagnosticResult.success("Off-heap Memory",
                        "Successfully allocated " + (testSize / 1024) + " KB off-heap");
            } else {
                return DiagnosticResult.failure("Off-heap Memory",
                        "Off-heap allocation verification failed");
            }

        } catch (OutOfMemoryError e) {
            return DiagnosticResult.failure("Off-heap Memory",
                    "Out of memory for off-heap allocation: " + e.getMessage());
        } catch (Exception e) {
            return DiagnosticResult.failure("Off-heap Memory",
                    "Failed to allocate off-heap memory: " + e.getMessage());
        }
    }

    /**
     * Diagnostic result
     */
    public static class DiagnosticResult {
        private final String name;
        private final Status status;
        private final String message;

        public enum Status {
            SUCCESS, WARNING, FAILURE
        }

        private DiagnosticResult(String name, Status status, String message) {
            this.name = name;
            this.status = status;
            this.message = message;
        }

        public static DiagnosticResult success(String name, String message) {
            return new DiagnosticResult(name, Status.SUCCESS, message);
        }

        public static DiagnosticResult warning(String name, String message) {
            return new DiagnosticResult(name, Status.WARNING, message);
        }

        public static DiagnosticResult failure(String name, String message) {
            return new DiagnosticResult(name, Status.FAILURE, message);
        }

        public String getName() {
            return name;
        }

        public Status getStatus() {
            return status;
        }

        public String getMessage() {
            return message;
        }

        public boolean isSuccess() {
            return status == Status.SUCCESS;
        }

        public boolean isFailure() {
            return status == Status.FAILURE;
        }
    }

    /**
     * Diagnostic report
     */
    public static class DiagnosticReport {
        private final List<DiagnosticResult> results;

        public DiagnosticReport(List<DiagnosticResult> results) {
            this.results = new ArrayList<>(results);
        }

        public boolean hasFailures() {
            return results.stream().anyMatch(DiagnosticResult::isFailure);
        }

        public List<DiagnosticResult> getFailedChecks() {
            return results.stream()
                    .filter(DiagnosticResult::isFailure)
                    .toList();
        }

        public List<DiagnosticResult> getAllResults() {
            return new ArrayList<>(results);
        }
    }
}
