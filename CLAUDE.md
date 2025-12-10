# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SecureHR Logging SDK (v8.0.0-RELEASE)** - HR 도메인용 보안 로깅 SDK. PII 자동 마스킹, AES-256-GCM 암호화, Hash Chain 무결성 검증 지원.

**Artifact ID**: `secure-hr-logging-starter`
**Requirements**: Java 21+, Spring Boot 3.5.8+
**Architecture**: Multi-module Gradle project (core / starter / test)

## Common Commands

```bash
# Build all modules
./gradlew build

# Clean build (useful for troubleshooting)
./gradlew clean build

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

# Check Gradle version / Update wrapper
./gradlew --version
./gradlew wrapper --gradle-version=8.10
```

## Project Structure

```
.
├── secure-log-core/           # [Library] Pure Java core library
├── secure-log-starter/        # [Starter] Spring Boot AutoConfiguration
└── secure-log-test/           # [Test] TestKit with LogAssert utilities
```

**Base Package**: `io.github.hongjungwan.blackbox`

## Architecture Constraints

### 1. Thread Safety
- Use `ReentrantLock` for synchronization where needed
- Standard Java `BlockingQueue` for async processing
- `AtomicBoolean`, `AtomicLong` for thread-safe counters

### 2. Simplicity
- Standard String operations for masking (no char array manipulation)
- Fixed-interval retry (no exponential backoff)
- Simple CLOSED/OPEN circuit breaker (no HALF_OPEN state)

### 3. Dependencies
Dependencies defined in `secure-log-core/build.gradle`:
- Jackson (`jackson-databind` 2.18.2) - JSON serialization
- Zstd (`zstd-jni` 1.5.6-3) - Compression
- BouncyCastle (`bcprov-jdk18on` 1.79) - Cryptography
- Kafka (`kafka-clients` 3.7.0) - Log transport
- AWS SDK (`kms`, `sts` - 2.25.0) - KMS integration

## Core Architecture

### Processing Pipeline
```
LogEvent -> VirtualAsyncAppender -> LogProcessor Pipeline:
  1. PII Masking (PiiMasker) - message + payload masking, value pattern auto-detection
  2. Integrity Chain (MerkleChain) - persisted on shutdown, restored on startup
  3. Encryption (EnvelopeEncryption) - DEK rotation every 1 hour
  4. Serialization (LogSerializer - Zstd) - 100MB limit, size validation after decompress
  5. Transport (ResilientLogTransport - Kafka/Fallback) - file locking for replay safety
```

### Graceful Shutdown
```
SecureLogLifecycle.stop():
  1. VirtualAsyncAppender.stop() - 10s buffer drain timeout with progress check
  2. Timeout exceeded -> remaining events saved to fallback via processFallback()
  3. MerkleChain.saveState() - persist hash chain state
```

### Backpressure Handling
When buffer is full, `VirtualAsyncAppender.handleBackpressure()` saves events to fallback storage to prevent data loss.

### Error Recovery Security
- `LogProcessor.process()` ensures PII-masked entry is always sent to fallback on exceptions
- Original unmasked data never leaks to fallback storage

### Key Subsystems

**Context Propagation** (FEAT-09) - `context/` package
- `LoggingContext` - Immutable, ThreadLocal-scoped trace context
- `ContextPropagator` - W3C Trace Context/Baggage header support
- Auto-propagation across threads via `LoggingContext.wrap(Runnable)`

**Interceptor Chain** (FEAT-10) - `interceptor/` package
- `LogInterceptor` - Hook interface for pipeline stages
- `BuiltInInterceptors` - Sampling, level filter, field redaction

**Resilience** (FEAT-11) - `resilience/` package
- `CircuitBreaker` - Simple consecutive failure-based breaker (CLOSED/OPEN), N failures triggers fast-fail
- `RetryPolicy` - Fixed interval retry (simplified, no exponential backoff)

**Metrics** (FEAT-12) - `metrics/` package
- `SdkMetrics` - Throughput, latency histograms, error rates
- `MetricsExporter` - Prometheus/JSON format export

### Security Model
- **Envelope Encryption**: DEK (AES-256-GCM) + KEK (from KMS), 1-hour DEK rotation with TOCTOU-safe lock
- **Integrity**: SHA-256 Hash Chain with canonical JSON serialization (Jackson `ORDER_MAP_ENTRIES_BY_KEYS`)
- **Crypto-Shredding**: DEK destruction via Destroyable interface (JVM limitations documented)
- **PII Masking**: Field name-based auto-detection + annotation-based masking (message + payload)
- **Fallback KEK**: Atomic file creation with POSIX permissions, invalid files auto-deleted
- **IV Validation**: Encrypted DEK minimum length (60 bytes) validation before decryption

**Note**: MerkleChain provides per-instance integrity only. In distributed deployments, consider a centralized integrity service.

### Annotation-Based PII Masking
DTO fields can use `@Mask` annotation for declarative PII masking:

```java
public class EmployeeDto {
    @Mask(MaskType.RRN)
    private String residentNumber;    // 123456-1234567 -> 123456-*******

    @Mask(MaskType.PHONE)
    private String phoneNumber;       // 010-1234-5678 -> 010-****-5678

    @Mask(MaskType.EMAIL)
    private String email;             // user@example.com -> u***@example.com

    @Mask(MaskType.CREDIT_CARD)
    private String cardNumber;        // 1234-5678-9012-3456 -> ****-****-****-3456

    @Mask(MaskType.PASSWORD)
    private String password;          // secret -> ********
}

// Usage
PiiMasker masker = new PiiMasker(config);
Map<String, Object> masked = masker.maskObject(dto);        // Returns Map
EmployeeDto maskedDto = masker.maskObjectToInstance(dto);   // Returns typed instance
String maskedValue = masker.maskValue("123456-1234567", MaskType.RRN);  // Direct value masking
```

**Supported MaskTypes**: RRN, PHONE, EMAIL, CREDIT_CARD, PASSWORD, SSN, NAME, ADDRESS, ACCOUNT_NUMBER

**Emergency Mode**: Use `@Mask(value = MaskType.RRN, emergency = true)` to encrypt original data with RSA public key instead of masking (for later recovery with private key).

**Files**:
- `api/annotation/Mask.java` - Field/method annotation
- `api/annotation/MaskType.java` - Masking type enum
- `core/security/AnnotationMaskingProcessor.java` - Reflection-based processor with metadata caching
- `core/security/EmergencyEncryptor.java` - RSA-OAEP public key encryption for emergency mode

### AOP-Based Audit Context (Who/Whom/Why)
Automatically capture audit context using `@AuditContext` annotation:

```java
@AuditContext(
    why = "급여 정보 조회",
    whomParam = "employeeId",
    action = AuditAction.READ,
    resourceType = "Salary"
)
public EmployeeSalaryDto getSalary(String employeeId) {
    // Automatically captured:
    // - who: Current authenticated user (from SecurityContext)
    // - whom: employeeId parameter value
    // - why: "급여 정보 조회"
    // - action: READ
    return repository.findSalary(employeeId);
}

// SpEL expression support
@AuditContext(why = "#{#employeeId}의 급여를 #{#reason}으로 조회")
public EmployeeSalaryDto getSalary(String employeeId, String reason) { ... }
```

**AuditAction types**: CREATE, READ, UPDATE, DELETE, EXPORT, APPROVE, REJECT, LOGIN, LOGOUT, PERMISSION_CHANGE, OTHER

**Who extraction priority**:
1. Spring Security SecurityContextHolder
2. LoggingContext userId baggage
3. "ANONYMOUS" (fallback)

**Whom auto-detection**: Automatically finds parameters named `employeeId`, `userId`, `targetId`, `id`, `memberId`, `staffId`

**Files**:
- `api/annotation/AuditContext.java` - Method annotation
- `api/annotation/AuditAction.java` - Action type enum
- `api/domain/AuditInfo.java` - Immutable audit info domain
- `starter/aop/AuditContextAspect.java` - AOP aspect implementation
- `starter/aop/AuditUserExtractor.java` - User extraction interface
- `starter/aop/SecurityContextUserExtractor.java` - Spring Security integration

### Null Safety Patterns
SDK applies defensive null checks at critical points:
- `PiiMasker`: null key check + ConcurrentModificationException prevention (ArrayList copy)
- `EnvelopeEncryption`: payload/encrypted field validation, null entry/message check in encrypt()
- `MerkleChain`: integrity field null check
- `LogProcessor`: **guaranteed masked entry fallback on exception**
- `LogEntry`: ClassCastException handling for Map casting
- `LogSerializer`: negative size validation first, compression level 1-22 range check

### Thread Safety Patterns
- **AtomicInteger for counters**: Use `AtomicInteger.incrementAndGet()` instead of `volatile int++`
- **CountDownLatch for shutdown**: Explicit batch completion waiting (see `VirtualAsyncAppender.consumerBatchLatch`)
- **Async completion waiting**: Always call `.join()` on `CompletableFuture` when retry is needed

### Cache Synchronization
- `KmsClient`: `CachedKekHolder` inner class for atomic KEK + timestamp reads
- `VirtualAsyncAppender`: `consumerFinished` AtomicBoolean + `CountDownLatch` for reliable shutdown signaling

### Key Components
- `ResilientLogTransport` - Circuit breaker + retry + Zstd magic number validation
- `LoggingContext` - Trace ID with timestamp component for collision prevention

### SPI (Extension Points) - `spi/` package
Provider interfaces for customization without modifying core:
- `EncryptionProvider` - Custom encryption implementations
- `TransportProvider` - Custom log transport destinations
- `MaskingStrategy` - Custom PII masking patterns (String-based)

## Implementation Guidelines

### Adding New Masking Patterns
1. Add pattern to `PiiMasker.initializeStrategies()`
2. Create `MaskingStrategy` implementation using String operations
3. Register field name mappings (e.g., "card", "cardNumber" -> same strategy)

### Adding New Interceptors
```java
processor.addPreProcessInterceptor("name", LogInterceptor.Priority.HIGH,
    (entry, chain) -> {
        // Modify entry or return null to drop
        return chain.proceed(entry);
    });
```

### Circuit Breaker (Simplified)
- `CLOSED` - Normal state, counting consecutive failures
- `OPEN` - Blocked state, auto-reset after timeout

**Behavior**: After N consecutive failures, transitions to OPEN. Auto-resets to CLOSED after configured timeout.

### Kafka Error Categories
KafkaProducer classifies errors for proper handling:
- `AUTHENTICATION` / `AUTHORIZATION` - Non-retryable, requires config fix
- `NETWORK` / `TIMEOUT` - Retryable with fixed delay
- `RECORD_TOO_LARGE` - Non-retryable, log warning
- `SERIALIZATION` - Non-retryable, likely bug

## Configuration Properties

```yaml
secure-hr:
  logging:
    enabled: true
    mode: ASYNC  # SYNC, ASYNC, FALLBACK
    buffer-size: 8192
    consumer-threads: 2  # Async consumer thread count
    pii-masking:
      enabled: true
      patterns: ["rrn", "credit_card", "password", "ssn"]
    security:
      encryption-enabled: true
      integrity-enabled: true
      kms-key-id: "arn:aws:kms:..."
      emergency-public-key: "Base64-encoded-RSA-public-key"  # For emergency mode
    audit:
      enabled: true  # Enable @AuditContext AOP
      log-enabled: true  # Log audit events
```

## Performance Targets

- **Throughput**: 20,000 logs/sec per instance (4 vCPU)
- **Latency**: Log call return < 5μs (non-blocking)
- **Encryption**: Full pipeline (masking + hash + encryption) < 4ms

## Testing

### Test Structure
```
secure-log-core/src/
├── test/java/...                    # Unit tests (Docker not required)
└── integrationTest/java/            # Integration tests (Docker required)
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

### Security Performance Tests
Encryption performance tests in `secure-log-core/src/test/java/.../performance/`:
```bash
# Run encryption performance tests
./gradlew :secure-log-core:test --tests "EncryptionPerformanceTest"
```
**Target**: All encryption operations should complete within 4ms

Test coverage:
- `EncryptionPerformanceTest` - AES-256-GCM encryption, SHA-256 hash chain, PII masking, full pipeline

Measured metrics:
- Single call latency (standard/large payload)
- Average latency over 1000 iterations
- P50, P99 percentile latencies
- Full pipeline (masking + hash + encryption) combined latency

## Package Structure

```
io.github.hongjungwan.blackbox
├── api/                    # Public API (SecureLogger, LogEntry, LoggingContext)
│   ├── annotation/         # @Mask, MaskType, @AuditContext, AuditAction
│   ├── config/             # Configuration classes
│   ├── context/            # Context propagation
│   ├── domain/             # Domain models (LogEntry, AuditInfo)
│   └── interceptor/        # Interceptor interfaces
├── core/
│   ├── internal/           # Core implementations (LogProcessor, VirtualAsyncAppender, etc.)
│   ├── resilience/         # CircuitBreaker, RetryPolicy
│   └── security/           # EnvelopeEncryption, KmsClient, PiiMasker, EmergencyEncryptor
├── spi/                    # Extension points (EncryptionProvider, MaskingStrategy, TransportProvider)
└── starter/                # Spring Boot Starter (secure-log-starter module)
    └── aop/                # AuditContextAspect, AuditUserExtractor
```
