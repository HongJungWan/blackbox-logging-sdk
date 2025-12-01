# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SecureHR Logging SDK (v8.0.0)** is a zero-dependency, high-performance logging SDK for HR domain applications requiring strict security and compliance. Built on Java 21 Virtual Threads and off-heap memory architecture.

**Artifact ID**: `secure-hr-logging-starter`
**Requirements**: Java 21+, Spring Boot 3.5+
**Architecture**: Multi-module Gradle project with dependency shading

## Common Commands

```bash
# Build all modules
./gradlew build

# Build with dependency shading (Shadow JAR)
./gradlew shadowJar

# Run tests
./gradlew test

# Run single test class
./gradlew test --tests "ClassName"

# Run single test method
./gradlew test --tests "ClassName.methodName"

# Build without tests
./gradlew build -x test

# Module-specific builds
./gradlew :secure-log-core:build
./gradlew :secure-log-starter:build
./gradlew :secure-log-test:build

# Run integration tests (requires Docker for Testcontainers)
./gradlew integrationTest

# Run unit tests only (excluding Testcontainers integration tests)
./gradlew :secure-log-core:test --tests "io.github.hongjungwan.blackbox.core.context.*" \
  --tests "io.github.hongjungwan.blackbox.core.resilience.*" \
  --tests "io.github.hongjungwan.blackbox.core.interceptor.*" \
  --tests "io.github.hongjungwan.blackbox.core.masking.*"
```

## Project Structure

```
.
├── secure-log-core/           # [Library] Pure Java, shaded dependencies
├── secure-log-starter/        # [Starter] Spring Boot AutoConfiguration
└── secure-log-test/           # [Test] TestKit with LogAssert utilities
```

**Base Package**: `io.github.hongjungwan.blackbox`

## Critical Architecture Constraints

### 1. Virtual Thread Compatibility
- **NEVER use `synchronized` keyword** - causes carrier thread pinning
- **Always use `ReentrantLock` or `StampedLock`** for synchronization
- Use `Executors.newVirtualThreadPerTaskExecutor()` for async operations
- Use `LockSupport.parkNanos()` instead of `Thread.sleep()`

### 2. Zero-Allocation Design
- **No `String.replaceAll()` or regex object creation** in hot paths
- Use JCTools `MpscArrayQueue` for lock-free queues
- Use char array manipulation for masking (see `PiiMasker.java`)
- Target: GC allocation rate < 1MB/sec under load

### 3. Dependency Shading
All internal dependencies relocated to `io.github.hongjungwan.blackbox.internal.*`:
- Jackson, Zstd, JCTools, Caffeine, BouncyCastle, Kafka, AWS SDK

Configured in `secure-log-core/build.gradle` using Gradle Shadow plugin.

## Core Architecture

### Processing Pipeline
```
LogEvent → VirtualAsyncAppender → LogProcessor Pipeline:
  1. Deduplication (SemanticDeduplicator)
  2. PII Masking (PiiMasker)
  3. Integrity Chain (MerkleChain)
  4. Encryption (EnvelopeEncryption)
  5. Serialization (LogSerializer - Zstd)
  6. Transport (ResilientLogTransport - Kafka/Fallback)
```

### Key Subsystems

**Context Propagation** (FEAT-09) - `context/` package
- `LoggingContext` - Immutable, ThreadLocal-scoped trace context
- `ContextPropagator` - W3C Trace Context/Baggage header support
- Auto-propagation across threads via `LoggingContext.wrap(Runnable)`

**Interceptor Chain** (FEAT-10) - `interceptor/` package
- `LogInterceptor` - Hook interface for pipeline stages
- `InterceptorChain` - Priority-ordered execution chain
- `BuiltInInterceptors` - Sampling, level filter, field redaction

**Resilience** (FEAT-11) - `resilience/` package
- `CircuitBreaker` - State machine (CLOSED→OPEN→HALF_OPEN), exponential backoff
- `RetryPolicy` - Configurable retries with jitter
- `RateLimiter` - Token bucket algorithm (20K logs/sec default)

**Metrics** (FEAT-12) - `metrics/` package
- `SdkMetrics` - Throughput, latency histograms, error rates
- `MetricsExporter` - Prometheus/JSON format export

### Security Model
- **Envelope Encryption**: DEK (AES-256-GCM) + KEK (from KMS)
- **Integrity**: Merkle Tree SHA-256 hash chaining
- **Crypto-Shredding**: DEK destruction makes logs unrecoverable
- **PII Masking**: Zero-allocation char array manipulation

### Enhanced Components
- `EnhancedLogProcessor` - Pipeline with interceptors + metrics
- `ResilientLogTransport` - Circuit breaker + retry + rate limiting

## Implementation Guidelines

### Adding New Masking Patterns
1. Add pattern to `PiiMasker.initializeStrategies()`
2. Create `MaskingStrategy` implementation using char array manipulation
3. Register field name mappings (e.g., "card", "cardNumber" → same strategy)

### Adding New Interceptors
```java
processor.addPreProcessInterceptor("name", LogInterceptor.Priority.HIGH,
    (entry, chain) -> {
        // Modify entry or return null to drop
        return chain.proceed(entry);
    });
```

### Circuit Breaker States
- `CLOSED` - Normal operation, counting failures
- `OPEN` - Failing fast to fallback, waiting for recovery timeout
- `HALF_OPEN` - Testing recovery with limited calls

## Configuration Properties

```yaml
secure-hr:
  logging:
    enabled: true
    mode: ASYNC  # SYNC, ASYNC, FALLBACK
    buffer-size: 8192
    circuit-breaker-failure-threshold: 3
    rate-limit-logs-per-second: 20000
    pii-masking:
      enabled: true
      patterns: ["rrn", "credit_card", "password", "ssn"]
    security:
      encryption-enabled: true
      kms-key-id: "arn:aws:kms:..."
```

## Performance Targets

- **Throughput**: 20,000 logs/sec per instance (4 vCPU)
- **Latency**: Log call return < 5μs (non-blocking)
- **Memory**: GC allocation < 1MB/sec under load

## Testing Notes

- Integration tests require Docker (Testcontainers for Kafka, LocalStack)
- Run unit tests with `--tests "!*IntegrationTest"` to skip Docker-dependent tests
- Use `LogAssert` from `secure-log-test` module for fluent assertions
