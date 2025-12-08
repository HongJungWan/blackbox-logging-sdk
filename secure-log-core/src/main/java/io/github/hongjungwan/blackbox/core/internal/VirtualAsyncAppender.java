package io.github.hongjungwan.blackbox.core.internal;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.UnsynchronizedAppenderBase;
import io.github.hongjungwan.blackbox.api.config.SecureLogConfig;
import io.github.hongjungwan.blackbox.api.domain.LogEntry;
import io.github.hongjungwan.blackbox.core.internal.LogProcessor;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Async Appender for log event processing.
 *
 * Uses standard Java concurrent utilities for simplicity:
 * - ArrayBlockingQueue for bounded buffer
 * - Fixed thread pool for background processing
 * - Standard Thread.sleep() for waiting
 */
public class VirtualAsyncAppender extends UnsynchronizedAppenderBase<ILoggingEvent> {

    // Standard fixed thread pool for background processing
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    // Standard blocking queue from java.util.concurrent
    private final BlockingQueue<ILoggingEvent> buffer;

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final SecureLogConfig config;
    private final LogProcessor processor;

    // Consumer thread reference
    private Thread consumerThread;

    /**
     * FIX P1 #6: Use a completion signal from consumer instead of size checks.
     * MPSC queue size() is not atomic with polling, so we use this flag to signal
     * when the consumer has finished processing all events.
     */
    private final AtomicBoolean consumerFinished = new AtomicBoolean(false);

    /**
     * FIX P1-4: CountDownLatch to wait for consumer's current batch processing to complete.
     * This prevents race condition where stop() returns while consumer is still processing a batch.
     */
    private final CountDownLatch consumerBatchLatch = new CountDownLatch(1);

    /**
     * FIX P2 #17: Use a unique ID field instead of relying on thread name for identification.
     * Thread names can be duplicated across Virtual Threads.
     */
    private final String consumerId = "secure-log-consumer-" + System.nanoTime();

    // Backpressure metrics - use AtomicLong to prevent race conditions
    private final AtomicLong droppedEvents = new AtomicLong(0);

    public VirtualAsyncAppender(SecureLogConfig config, LogProcessor processor) {
        this.config = config;
        this.processor = processor;
        this.buffer = new ArrayBlockingQueue<>(config.getBufferSize());
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

            /**
             * FIX P1-4: Wait for consumer's current batch to complete using CountDownLatch.
             * This ensures we don't proceed while consumer is still processing events.
             */
            try {
                boolean batchCompleted = consumerBatchLatch.await(10, TimeUnit.SECONDS);
                if (!batchCompleted) {
                    addWarn("Timeout waiting for consumer batch to complete");
                }
            } catch (InterruptedException e) {
                addWarn("Interrupted while waiting for consumer batch completion");
                Thread.currentThread().interrupt();
            }

            // Wait for consumer to signal completion
            int waitCount = 0;
            while (!consumerFinished.get() && waitCount < 100) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                waitCount++;
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
            // FIX P2 #17: Use unique consumerId for thread name
            Thread.currentThread().setName(consumerId);

            try {
                while (isRunning.get() || !buffer.isEmpty()) {
                    try {
                        processNextBatch();
                    } catch (Exception e) {
                        addError("[" + consumerId + "] Error in consumer loop", e);
                    }
                }
            } finally {
                // FIX P1 #6: Signal that consumer has finished processing
                consumerFinished.set(true);
                // FIX P1-4: Signal that consumer batch processing is complete
                consumerBatchLatch.countDown();
            }
        });
    }

    /**
     * Process events in batch for efficiency.
     * Uses blocking poll with timeout to avoid busy-waiting.
     */
    private void processNextBatch() {
        try {
            // Use blocking poll with timeout - simpler than busy-spin
            ILoggingEvent event = buffer.poll(100, TimeUnit.MILLISECONDS);
            if (event == null) {
                return; // No events available
            }

            // Process the first event
            LogEntry logEntry = LogEntry.fromEvent(event);
            processor.process(logEntry);

            // Drain additional events (up to batch size) without blocking
            int batchSize = 1;
            final int maxBatchSize = 100;
            while (batchSize < maxBatchSize && (event = buffer.poll()) != null) {
                try {
                    logEntry = LogEntry.fromEvent(event);
                    processor.process(logEntry);
                    batchSize++;
                } catch (Exception e) {
                    addError("Error processing log event", e);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            addError("Error processing log event", e);
        }
    }

    /**
     * Handle backpressure when buffer is full.
     * Simply saves to fallback storage to prevent data loss.
     */
    private void handleBackpressure(ILoggingEvent event) {
        long dropped = droppedEvents.incrementAndGet();

        // Log warning periodically
        if (dropped % 1000 == 0) {
            addWarn("Buffer full. Dropped " + dropped + " events so far.");
        }

        // Save to fallback storage to prevent data loss
        processor.processFallback(LogEntry.fromEvent(event));
    }

    public long getDroppedEvents() {
        return droppedEvents.get();
    }

    public int getQueueSize() {
        return buffer.size();
    }

    public int getQueueCapacity() {
        // Return configured buffer size since BlockingQueue doesn't have capacity()
        return config.getBufferSize();
    }
}
