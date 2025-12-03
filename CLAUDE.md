# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SecureHR Logging SDK (v8.0.0)** is a zero-dependency, high-performance logging SDK for HR domain applications requiring strict security and compliance. Built on Java 21 Virtual Threads and Lock-free Queue (JCTools) architecture.

**Artifact ID**: `secure-hr-logging-starter`
**Requirements**: Java 21+, Spring Boot 3.5+
**Architecture**: Multi-module Gradle project with dependency shading

## Common Commands

```bash
# Build all modules
./gradlew build

# Clean build (useful for troubleshooting)
./gradlew clean build

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

# Run unit tests only (no Docker required)
./gradlew :secure-log-core:test
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
  1. Deduplication (SemanticDeduplicator) - async summary emission via Virtual Thread executor
  2. PII Masking (PiiMasker) - message + payload 필드 모두 마스킹, value pattern auto-detection
  3. Integrity Chain (MerkleChain) - persisted on shutdown, restored on startup
  4. Encryption (EnvelopeEncryption) - DEK rotation every 1 hour
  5. Serialization (LogSerializer - Zstd) - 100MB limit, size validation after decompress
  6. Transport (ResilientLogTransport - Kafka/Fallback) - file locking for replay safety
```

### Graceful Shutdown
```
SecureLogLifecycle.stop():
  1. VirtualAsyncAppender.stop() - 10s buffer drain timeout with progress check
  2. Timeout exceeded → remaining events saved to fallback via processFallback()
  3. LogProcessor.flush() - closes deduplicator executor
  4. MerkleChain.saveState() - persist hash chain state
```

### Backpressure Handling
When buffer is full, `VirtualAsyncAppender.handleBackpressure()` saves events to fallback storage to prevent data loss.

### Error Recovery Security
`LogProcessor.process()` ensures PII-masked entry is always sent to fallback on exceptions - original unmasked data never leaks to fallback storage.

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
- `CircuitBreaker` - State machine (CLOSED→OPEN→HALF_OPEN), exponential backoff with ±20% jitter
- `RetryPolicy` - Configurable retries with jitter
- `RateLimiter` - Token bucket algorithm (20K logs/sec), overflow-safe token calculation

**Metrics** (FEAT-12) - `metrics/` package
- `SdkMetrics` - Throughput, latency histograms, error rates
- `MetricsExporter` - Prometheus/JSON format export

### Security Model
- **Envelope Encryption**: DEK (AES-256-GCM) + KEK (from KMS), 1-hour DEK rotation with TOCTOU-safe lock
- **Integrity**: SHA-256 Hash Chain with canonical JSON serialization (Jackson `ORDER_MAP_ENTRIES_BY_KEYS`)
- **Crypto-Shredding**: DEK destruction via Destroyable interface (JVM limitations documented)
- **PII Masking**: Zero-allocation char array manipulation + auto-detection patterns (message + payload 필드 모두 마스킹)
- **Fallback KEK**: Atomic file creation with POSIX permissions, invalid files auto-deleted
- **IV Validation**: Encrypted DEK minimum length (60 bytes) validation before decryption

**Note**: MerkleChain provides per-instance integrity only. In distributed deployments, consider a centralized integrity service.

### Null Safety Patterns
SDK applies defensive null checks at critical points:
- `PiiMasker`: null key check + ConcurrentModificationException prevention (ArrayList copy)
- `EnvelopeEncryption`: payload/encrypted field validation, null entry/message check in encrypt()
- `MerkleChain`: integrity field null check, ThreadLocal MessageDigest caching
- `LogProcessor`: null deduplicator defensive check, **예외 시 maskedEntry fallback 보장**
- `LogEntry`: ClassCastException handling for Map casting
- `LogSerializer`: negative size validation first, compression level 1-22 range check

### Cache Synchronization
- `KmsClient`: `CachedKekHolder` inner class for atomic KEK + timestamp reads
- `VirtualAsyncAppender`: `consumerFinished` AtomicBoolean for reliable shutdown signaling

### Enhanced Components
- `EnhancedLogProcessor` - Pipeline with interceptors + metrics
- `ResilientLogTransport` - Circuit breaker + retry + rate limiting + Zstd magic number validation
- `LoggingContext` - Trace ID with timestamp component for collision prevention

### SPI (Extension Points) - `spi/` package
Provider interfaces for customization without modifying core:
- `EncryptionProvider` - Custom encryption implementations
- `IntegrityProvider` - Custom integrity verification
- `TransportProvider` - Custom log transport destinations
- `MaskingStrategy` - Custom PII masking patterns
- `LoggerProvider` - Custom logger implementations

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

**Note**: `tryAcquirePermission()` acquires lock for atomic state transitions.

### Kafka Error Categories
KafkaProducer classifies errors for proper handling:
- `AUTHENTICATION` / `AUTHORIZATION` - Non-retryable, requires config fix
- `NETWORK` / `TIMEOUT` - Retryable with backoff
- `RECORD_TOO_LARGE` - Non-retryable, log warning
- `SERIALIZATION` - Non-retryable, likely bug

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

## Testing

### Test Structure
```
secure-log-core/src/
├── test/java/...                    # Unit tests (Docker 불필요)
└── integrationTest/java/            # Integration tests (Docker 필요)
    └── io/.../integration/
        ├── EndToEndTest.java
        ├── KafkaIntegrationTest.java
        └── KmsIntegrationTest.java
```

### Commands
```bash
# Unit tests only (no Docker required)
./gradlew :secure-log-core:test

# Integration tests (requires Docker)
./gradlew :secure-log-core:integrationTest

# All tests
./gradlew :secure-log-core:allTests
```

### Docker Test Infrastructure
```bash
# Start test infrastructure
./scripts/start-test-infra.sh --wait

# Stop test infrastructure
./scripts/stop-test-infra.sh

# Check Docker status
./scripts/check-docker.sh
```

Docker services for integration tests:
- Kafka: `localhost:9092`
- LocalStack (KMS): `localhost:4566`

Use `LogAssert` from `secure-log-test` module for fluent assertions.

### Performance Benchmarks
JMH benchmarks available in `secure-log-core/src/test/java/.../benchmark/`:
```bash
# Run benchmarks (requires building first)
./gradlew :secure-log-core:test --tests "*Benchmark*"
```
- `LogProcessorBenchmark` - End-to-end processing throughput
- `PiiMaskerBenchmark` - Masking performance
- `SerializationBenchmark` - JSON/Zstd serialization

## Package Structure

```
io.github.hongjungwan.blackbox
├── api/                    # Public API (SecureLogger, LogEntry, LoggingContext)
│   ├── config/             # Configuration classes
│   ├── context/            # Context propagation
│   ├── domain/             # Domain models
│   └── interceptor/        # Interceptor interfaces
├── core/
│   ├── internal/           # Core implementations (LogProcessor, VirtualAsyncAppender, etc.)
│   ├── resilience/         # CircuitBreaker, RetryPolicy, RateLimiter
│   └── security/           # EnvelopeEncryption, KmsClient, PiiMasker
└── spi/                    # Extension points (providers for encryption, masking, transport)
```
