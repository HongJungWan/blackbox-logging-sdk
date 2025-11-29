# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SecureHR Logging SDK (v8.0.0)** is a zero-dependency, high-performance logging SDK for HR domain applications requiring strict security and compliance. Built on Java 21 Virtual Threads and off-heap memory architecture.

**Artifact ID**: `secure-hr-logging-starter`
**Requirements**: Java 21+, Spring Boot 3.5+
**Architecture**: Multi-module Gradle project with dependency shading

## Common Commands

### Build and Test
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

# Clean build
./gradlew clean

# Build without tests
./gradlew build -x test
```

### Module-Specific Commands
```bash
# Build only core module
./gradlew :secure-log-core:build

# Build only starter module
./gradlew :secure-log-starter:build

# Run load tests (when implemented)
./gradlew :secure-log-test:test --tests "*LoadTest"
```

## Project Structure (Multi-Module)

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

### 2. Zero-Allocation Design
- **No `String.replaceAll()` or regex object creation** in hot paths
- Use `VarHandle` or JCTools for lock-free data structures
- Leverage off-heap `DirectByteBuffer` or `MpscArrayQueue` for RingBuffer
- Target: GC allocation rate < 1MB/sec under load

### 3. Dependency Shading (No Classpath Conflicts)
All internal dependencies MUST be relocated to `io.github.hongjungwan.blackbox.internal.*`:
- Jackson → `io.github.hongjungwan.blackbox.internal.jackson`
- Zstd → `io.github.hongjungwan.blackbox.internal.zstd`
- JCTools → `io.github.hongjungwan.blackbox.internal.jctools`
- Caffeine → `io.github.hongjungwan.blackbox.internal.caffeine`
- BouncyCastle → `io.github.hongjungwan.blackbox.internal.bouncycastle`

Configured in `secure-log-core/build.gradle` using Gradle Shadow plugin 8.1.1

## Core Features Implementation Guide

### FEAT-01: Zero-Allocation Masking
- Extend Jackson `ContextualSerializer`
- Use `JsonGenerator.writeString(char[], int, int)` for direct char array manipulation
- Support Java `record` types via `RecordComponent` API

### FEAT-02: Semantic Deduplication
- Key: `messageTemplate + Throwable` hash
- Sliding window: 1 second with `AtomicInteger` counter
- Storage: Caffeine Cache (shaded) with W-TinyLFU algorithm

### FEAT-03: Virtual Thread Async Appender
- Extend `ch.qos.logback.core.UnsynchronizedAppenderBase`
- Use `ReentrantLock` for queue insertion (NOT synchronized)
- Consumer loop runs on Virtual Thread for I/O operations

### FEAT-04: Envelope Encryption
- **KEK (Master)**: Stored in KMS with rotation support
- **DEK (Data)**: Per-block, in-memory, generated via SecureRandom
- Process: Encrypt logs with DEK, encrypt DEK with KEK, store in header

### FEAT-05: Circuit Breaker Fallback
- Trigger: KMS timeout (2s) or Kafka failure (3 retries)
- Action: Encrypt with embedded RSA public key → save to `logs/fallback/`
- Recovery: Auto-replay + secure delete (overwrite + NIO delete)

### FEAT-06: Spring Boot AutoConfiguration
- Use `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
- Profile-aware: `prod` profile → auto-enable ASYNC + Binary mode
- Configuration prefix: `secure-hr.logging.*`

### FEAT-07: TestKit (LogAssert)
- Module: `secure-log-test`
- AssertJ-style API: `assertThatLog().hasField("rrn").isMasked()`

## Security & Compliance

### Encryption Model
- **Envelope Encryption**: DEK (data) + KEK (master key in KMS)
- **Integrity**: Merkle Tree-based block chaining (hash chaining in headers)
- **Crypto-Shredding**: DEK destruction makes logs permanently unrecoverable

### Log Entry Structure
Transmitted as **Zstd-compressed binary**, canonical JSON representation:
```json
{
  "ts": 1716345000123,
  "lvl": "INFO",
  "trace_id": "0af7651916cd43dd8448eb211c80319c",
  "span_id": "b7ad6b7169203331",
  "ctx": { "user_id": "emp_1001", "region": "KR" },
  "msg": "Salary processed",
  "payload": {
    "amount": "******",
    "bank": "ENC(A1b...)"
  },
  "integ": "sha256:a8f..."
}
```

## Performance Targets

- **Throughput**: 20,000 logs/sec per instance (4 vCPU)
- **Latency**: Log call return < 5μs (non-blocking)
- **Memory**: GC allocation < 1MB/sec under load
- **Buffer**: Default 8192 entries (configurable)

## Doctor Service (Self-Diagnostics)

On SDK initialization (`SmartLifecycle.start`), run:
1. KMS connectivity check
2. Disk write permission (`logs/fallback/`)
3. Off-heap memory allocation test

On failure: Log warning to System.err + auto-switch to Fallback Mode

## Configuration Example

```yaml
secure-hr:
  logging:
    enabled: true
    mode: ASYNC # SYNC, ASYNC, FALLBACK
    buffer-size: 8192
    pii-masking:
      enabled: true
      patterns: ["rrn", "credit_card", "password"]
    security:
      encryption-enabled: true
      kms-endpoint: "https://kms.internal/v1/keys"
```

## Implementation Details

### Processing Pipeline
The log processing flow in `LogProcessor.java`:
1. **Deduplication** → `SemanticDeduplicator` (FEAT-02)
2. **PII Masking** → `PiiMasker` (FEAT-01)
3. **Integrity Chain** → `MerkleChain` (adds SHA-256 hash)
4. **Encryption** → `EnvelopeEncryption` (FEAT-04)
5. **Serialization** → `LogSerializer` (Zstd compression)
6. **Transport** → `LogTransport` (Kafka or fallback) (FEAT-05)

### Key Implementation Files
- `VirtualAsyncAppender.java` - Main entry point, uses JCTools `MpscArrayQueue`
- `PiiMasker.java` - Zero-allocation masking strategies
- `SemanticDeduplicator.java` - Caffeine cache with `LogSignature` hashing
- `EnvelopeEncryption.java` - AES-256-GCM with DEK rotation (1 hour interval)
- `KmsClient.java` - HTTP client for KEK retrieval, 5-minute cache, 2-second timeout
- `LogTransport.java` - Circuit breaker (opens after 3 failures), fallback to disk
- `MerkleChain.java` - SHA-256 hash chaining with previous block hash
- `SecureLogDoctor.java` - Startup diagnostics (KMS, disk, off-heap memory)
- `SecureLogAutoConfiguration.java` - Spring Boot bean wiring with SmartLifecycle

### Masking Strategies (FEAT-01)
- **RRN**: `123456-1234567` → `123456-*******` (masks last 7 digits)
- **Credit Card**: `1234-5678-9012-3456` → `****-****-****-3456` (shows last 4)
- **Password**: Complete masking to `********`
- **SSN**: `123-45-6789` → `***-**-6789` (masks first 7 chars)

All use char array manipulation without creating new String objects.

### Encryption Details (FEAT-04)
- **Algorithm**: AES-256-GCM with 128-bit authentication tag
- **IV Length**: 12 bytes (GCM standard)
- **DEK**: Generated per-block using `SecureRandom`, rotated hourly
- **KEK**: Retrieved from KMS, cached for 5 minutes
- **Format**: IV (12 bytes) + Ciphertext + GCM tag
- **Provider**: BouncyCastle (shaded)

### Circuit Breaker (FEAT-05)
- **Threshold**: 3 consecutive failures
- **States**: CLOSED (normal) → OPEN (fallback mode)
- **Fallback Location**: `logs/fallback/log-{timestamp}.zst`
- **Replay**: Manual via `LogTransport.replayFallbackLogs()`
- **Secure Delete**: Overwrite with zeros + NIO delete

### Deduplication Algorithm (FEAT-02)
```java
// Message template extraction
"User 123 logged in" → "User {} logged in"

// Signature = hash(messageTemplate + throwableSignature)
// Cache: Caffeine with W-TinyLFU, max 10K entries, 1s expiration
// Counter: AtomicInteger per signature
```

## Known Limitations / TODO

1. **Kafka Integration**: Currently uses placeholder `KafkaProducer.java`. Add `org.apache.kafka:kafka-clients` for production.
2. **KMS Integration**: `KmsClient` has fallback key generator. Needs real KMS provider (AWS KMS, Vault, etc.).
3. **Logback Configuration**: Users must configure `logback-spring.xml` to use `VirtualAsyncAppender`.
4. **Load Testing**: Performance targets (20K logs/sec) not yet validated.
5. **Automatic Replay**: Fallback replay is manual; consider adding scheduled task.
6. **Metrics**: No JMX/Actuator metrics exposed yet.

## Testing & Compatibility

- **Java Versions**: Java 21 LTS (required), Java 23 compatibility testing
- **Spring Boot**: Test on 3.3, 3.4, 3.5
- **Load Tests**: JMeter/Gatling scenarios for 20K logs/sec validation
- **Test Utilities**: Use `LogAssert` from `secure-log-test` module for fluent assertions
