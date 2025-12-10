package io.github.hongjungwan.blackbox.core.internal;

import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * SDK 자가 진단. 키 파일 접근, 디스크 쓰기 권한, Off-heap 메모리 할당 검사.
 */
@Slf4j
public class SecureLogDoctor {

    private final SecureLogConfig config;
    private final List<DiagnosticResult> results = new ArrayList<>();

    public SecureLogDoctor(SecureLogConfig config) {
        this.config = config;
    }

    /** 모든 진단 검사 실행 */
    public DiagnosticReport diagnose() {
        log.info("Running SecureLog diagnostic checks...");

        results.clear();

        results.add(checkKeyFileAccess());
        results.add(checkDiskWritePermission());
        results.add(checkOffHeapMemory());

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

    /** 검사 1: 키 파일 접근 가능 여부 */
    private DiagnosticResult checkKeyFileAccess() {
        try {
            Path keyDir = getKeyDirectory();

            if (!Files.exists(keyDir)) {
                Files.createDirectories(keyDir);
            }

            if (Files.isWritable(keyDir)) {
                return DiagnosticResult.success("Key File Access",
                        "Key directory is accessible: " + keyDir);
            } else {
                return DiagnosticResult.failure("Key File Access",
                        "Key directory is not writable: " + keyDir);
            }
        } catch (Exception e) {
            return DiagnosticResult.failure("Key File Access",
                    "Failed to access key directory: " + e.getMessage());
        }
    }

    private Path getKeyDirectory() {
        String fallbackDir = config.getFallbackDirectory();
        if (fallbackDir != null && !fallbackDir.isBlank()) {
            return Paths.get(fallbackDir);
        }
        return Paths.get(System.getProperty("user.home"));
    }

    /** 검사 2: 디스크 쓰기 권한 */
    private DiagnosticResult checkDiskWritePermission() {
        try {
            Path fallbackDir = Paths.get(config.getFallbackDirectory());

            Files.createDirectories(fallbackDir);

            Path testFile = fallbackDir.resolve(".test-write");
            Files.writeString(testFile, "test");
            String content = Files.readString(testFile);
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

    /** 검사 3: Off-heap 메모리 할당 */
    private DiagnosticResult checkOffHeapMemory() {
        try {
            int testSize = 1024 * 1024;
            ByteBuffer buffer = ByteBuffer.allocateDirect(testSize);

            if (buffer.isDirect() && buffer.capacity() == testSize) {
                return DiagnosticResult.success("Off-heap Memory",
                        "Successfully allocated " + (testSize / 1024) + " KB off-heap");
            } else {
                return DiagnosticResult.failure("Off-heap Memory", "Off-heap allocation verification failed");
            }
        } catch (OutOfMemoryError e) {
            return DiagnosticResult.failure("Off-heap Memory", "Out of memory: " + e.getMessage());
        } catch (Exception e) {
            return DiagnosticResult.failure("Off-heap Memory", "Failed to allocate: " + e.getMessage());
        }
    }

    /** 진단 결과 */
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

    /** 진단 리포트 */
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
