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
 * 비동기 로그 Appender. ArrayBlockingQueue 버퍼 + 고정 Thread Pool 기반.
 *
 * 설정 가능한 Consumer 스레드 수로 처리량 조절 가능.
 */
public class VirtualAsyncAppender extends UnsynchronizedAppenderBase<ILoggingEvent> {

    private final ExecutorService executor;
    private final BlockingQueue<ILoggingEvent> buffer;
    private final int consumerThreads;

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final SecureLogConfig config;
    private final LogProcessor processor;

    private Thread consumerThread;

    private final AtomicBoolean consumerFinished = new AtomicBoolean(false);
    private final CountDownLatch consumerBatchLatch;
    private final String consumerId = "secure-log-consumer-" + System.nanoTime();
    private final AtomicLong droppedEvents = new AtomicLong(0);

    public VirtualAsyncAppender(SecureLogConfig config, LogProcessor processor) {
        this.config = config;
        this.processor = processor;
        this.buffer = new ArrayBlockingQueue<>(config.getBufferSize());
        this.consumerThreads = Math.max(1, config.getConsumerThreads());
        this.executor = Executors.newFixedThreadPool(consumerThreads);
        this.consumerBatchLatch = new CountDownLatch(consumerThreads);
    }

    @Override
    public void start() {
        if (isRunning.compareAndSet(false, true)) {
            super.start();
            for (int i = 0; i < consumerThreads; i++) {
                startConsumerLoop(i);
            }
            addInfo("VirtualAsyncAppender started with buffer size: " + config.getBufferSize() +
                    ", consumer threads: " + consumerThreads);
        }
    }

    @Override
    public void stop() {
        if (isRunning.compareAndSet(true, false)) {
            addInfo("VirtualAsyncAppender stopping...");

            try {
                boolean batchCompleted = consumerBatchLatch.await(10, TimeUnit.SECONDS);
                if (!batchCompleted) {
                    addWarn("Timeout waiting for consumer batch to complete");
                }
            } catch (InterruptedException e) {
                addWarn("Interrupted while waiting for consumer batch completion");
                Thread.currentThread().interrupt();
            }

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

        event.prepareForDeferredProcessing();

        if (!buffer.offer(event)) {
            handleBackpressure(event);
        }
    }

    private void startConsumerLoop(int threadIndex) {
        String threadName = consumerId + "-" + threadIndex;
        executor.submit(() -> {
            if (threadIndex == 0) {
                consumerThread = Thread.currentThread();
            }
            Thread.currentThread().setName(threadName);

            try {
                while (isRunning.get() || !buffer.isEmpty()) {
                    try {
                        processNextBatch();
                    } catch (Exception e) {
                        addError("[" + threadName + "] Error in consumer loop", e);
                    }
                }
            } finally {
                if (consumerBatchLatch.getCount() == 1) {
                    consumerFinished.set(true);
                }
                consumerBatchLatch.countDown();
            }
        });
    }

    /** 배치 이벤트 처리 */
    private void processNextBatch() {
        try {
            ILoggingEvent event = buffer.poll(100, TimeUnit.MILLISECONDS);
            if (event == null) {
                return;
            }

            LogEntry logEntry = LogEntry.fromEvent(event);
            processor.process(logEntry);

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

    /** Backpressure 처리 (Fallback 저장) */
    private void handleBackpressure(ILoggingEvent event) {
        long dropped = droppedEvents.incrementAndGet();

        if (dropped % 1000 == 0) {
            addWarn("Buffer full. Dropped " + dropped + " events so far.");
        }

        processor.processFallback(LogEntry.fromEvent(event));
    }

    public long getDroppedEvents() {
        return droppedEvents.get();
    }

    public int getQueueSize() {
        return buffer.size();
    }

    public int getQueueCapacity() {
        return config.getBufferSize();
    }
}
