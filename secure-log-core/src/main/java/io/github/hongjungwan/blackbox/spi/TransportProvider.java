package io.github.hongjungwan.blackbox.spi;

import io.github.hongjungwan.blackbox.api.domain.LogEntry;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * 로그 전송 백엔드 SPI. Kafka, Elasticsearch 등 다양한 목적지 지원 시 구현.
 */
public interface TransportProvider {

    /** Transport 식별자 반환 */
    String getName();

    /** 단일 로그 엔트리 비동기 전송 */
    CompletableFuture<Void> send(LogEntry entry);

    /** 배치 전송 (기본: 개별 send 호출) */
    default CompletableFuture<Void> sendBatch(List<LogEntry> entries) {
        CompletableFuture<?>[] futures = entries.stream()
                .map(this::send)
                .toArray(CompletableFuture[]::new);
        return CompletableFuture.allOf(futures);
    }

    /** Transport 상태 확인 */
    boolean isHealthy();

    /** 대기 중인 엔트리 플러시 */
    void flush();

    /** 종료 (플러시 후 리소스 해제) */
    void close();

    /** Transport 메트릭 조회 */
    default TransportMetrics getMetrics() {
        return TransportMetrics.EMPTY;
    }

    /** Transport 메트릭 */
    interface TransportMetrics {
        long sentCount();
        long failedCount();
        long bytesWritten();
        double averageLatencyMs();

        TransportMetrics EMPTY = new TransportMetrics() {
            @Override public long sentCount() { return 0; }
            @Override public long failedCount() { return 0; }
            @Override public long bytesWritten() { return 0; }
            @Override public double averageLatencyMs() { return 0; }
        };
    }
}
