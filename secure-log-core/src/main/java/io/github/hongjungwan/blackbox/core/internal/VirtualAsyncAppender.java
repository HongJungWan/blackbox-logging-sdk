package io.github.hongjungwan.blackbox.core.internal;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.UnsynchronizedAppenderBase;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.LogProcessor;
import org.jctools.queues.MpscArrayQueue;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

/**
 * FEAT-03: Virtual Thread Async Appender
 *
 * High-performance async appender using Java 21 Virtual Threads and JCTools lock-free queue.
 *
 * CRITICAL CONSTRAINTS:
 * - NO synchronized keyword (causes carrier thread pinning)
 * - Uses ReentrantLock or lock-free structures only
 * - Non-blocking log event submission
 * - Virtual Thread consumer for I/O operations
 */
public class VirtualAsyncAppender extends UnsynchronizedAppenderBase<ILoggingEvent> {

    // Virtual Thread executor (Java 21)
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    // Lock-free MPSC (Multi-Producer Single-Consumer) queue from JCTools
    private final MpscArrayQueue<ILoggingEvent> buffer;

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final SecureLogConfig config;
    private final LogProcessor processor;

    // Consumer thread reference
    private Thread consumerThread;

    // Backpressure metrics - use AtomicLong to prevent race conditions
    private final AtomicLong droppedEvents = new AtomicLong(0);

    public VirtualAsyncAppender(SecureLogConfig config, LogProcessor processor) {
        this.config = config;
        this.processor = processor;
        this.buffer = new MpscArrayQueue<>(config.getBufferSize());
    }

    @Override
    public void start() {
        if (isRunning.compareAndSet(false, true)) {
            super.start();
            startConsumerLoop();
            addInfo("VirtualAsyncAppender started with buffer size: " + config.getBufferSize());
        }
    }

    @Override
    public void stop() {
        if (isRunning.compareAndSet(true, false)) {
            addInfo("VirtualAsyncAppender stopping...");

            // Wait for buffer to drain (max 10 seconds)
            // Use more robust draining with size check to detect stuck buffers
            int waitCount = 0;
            int previousSize = buffer.size();
            while (previousSize > 0 && waitCount < 100) {
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100));
                waitCount++;
                int currentSize = buffer.size();
                if (currentSize == previousSize) {
                    // No progress, buffer might be stuck
                    break;
                }
                previousSize = currentSize;
            }

            // Drain remaining events to fallback storage if buffer not fully drained
            int remaining = buffer.size();
            if (remaining > 0) {
                addWarn("Buffer not fully drained. Saving " + remaining + " events to fallback");
                ILoggingEvent event;
                while ((event = buffer.poll()) != null) {
                    try {
                        LogEntry logEntry = LogEntry.fromEvent(event);
                        processor.processFallback(logEntry);
                    } catch (Exception e) {
                        droppedEvents.incrementAndGet();
                        addError("Failed to save event to fallback during shutdown", e);
                    }
                }
            }

            // Flush processor to ensure pending deduplication summaries are emitted
            processor.flush();

            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }

            super.stop();
            addInfo("VirtualAsyncAppender stopped. Dropped events: " + droppedEvents.get());
        }
    }

    @Override
    protected void append(ILoggingEvent event) {
        if (!isRunning.get()) {
            return;
        }

        // Make event immutable for async processing
        event.prepareForDeferredProcessing();

        // Non-blocking offer to lock-free queue
        if (!buffer.offer(event)) {
            // Handle backpressure - drop event or fallback
            handleBackpressure(event);
        }
    }

    /**
     * Start consumer loop on Virtual Thread
     */
    private void startConsumerLoop() {
        executor.submit(() -> {
            consumerThread = Thread.currentThread();
            Thread.currentThread().setName("secure-log-consumer");

            while (isRunning.get() || !buffer.isEmpty()) {
                try {
                    processNextBatch();
                } catch (Exception e) {
                    addError("Error in consumer loop", e);
                }
            }
        });
    }

    /**
     * Process events in batch for efficiency
     * WARNING: Do NOT use 'synchronized' - uses lock-free polling
     */
    private void processNextBatch() {
        ILoggingEvent event;
        int batchSize = 0;
        final int maxBatchSize = 100;

        // Drain up to maxBatchSize events
        while (batchSize < maxBatchSize && (event = buffer.poll()) != null) {
            try {
                LogEntry logEntry = LogEntry.fromEvent(event);
                processor.process(logEntry);
                batchSize++;
            } catch (Exception e) {
                addError("Error processing log event", e);
            }
        }

        // If no events, park briefly to avoid busy-spin
        if (batchSize == 0) {
            LockSupport.parkNanos(TimeUnit.MICROSECONDS.toNanos(100));
        }
    }

    /**
     * Handle backpressure when buffer is full
     */
    private void handleBackpressure(ILoggingEvent event) {
        long dropped = droppedEvents.incrementAndGet();

        // Option 1: Drop (current implementation)
        // Option 2: Write to fallback file synchronously
        if (dropped % 1000 == 0) {
            addWarn("Buffer full. Dropped " + dropped + " events so far.");
        }

        // Enable fallback processing to prevent data loss
        processor.processFallback(LogEntry.fromEvent(event));
    }

    public long getDroppedEvents() {
        return droppedEvents.get();
    }

    public int getQueueSize() {
        return buffer.size();
    }

    public int getQueueCapacity() {
        return buffer.capacity();
    }
}
