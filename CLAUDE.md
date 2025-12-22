# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**KBS (blacK-Box logging SDK) v3.0.0-RELEASE** - HR 도메인용 보안 로깅 SDK. PII 자동 마스킹, AES-256-GCM 암호화, Hash Chain 무결성 검증 지원.

- **Group:Artifact**: `io.github.hongjungwan:blackbox-logging-sdk`
- **Requirements**: Java 21+, Spring Boot 3.5.8+
- **Architecture**: Multi-module Gradle project (Gradle wrapper included)
- **Output Mode**: Console (System.out) - NDJSON 형식

## Common Commands

```bash
# Build
./gradlew build                              # 전체 빌드
./gradlew clean build                        # 클린 빌드
./gradlew build -x test                      # 테스트 제외

# Test
./gradlew test                               # 전체 테스트
./gradlew test --tests "ClassName"           # 단일 클래스
./gradlew test --tests "ClassName.methodName" # 단일 메서드

# Module-specific
./gradlew :secure-log-core:build
./gradlew :secure-log-core:test
./gradlew :secure-log-core:integrationTest   # 통합 테스트 (Docker 필요)
./gradlew :secure-log-core:allTests          # 단위 + 통합 테스트

# Infrastructure (Docker required for integration tests)
./scripts/start-test-infra.sh --wait         # 테스트 인프라 시작
./scripts/stop-test-infra.sh                 # 인프라 중지
./scripts/check-docker.sh                    # Docker 상태 확인
```

## Project Structure

```
.
├── secure-log-core/     # 핵심 라이브러리 (Jackson, Logback, BouncyCastle 의존)
├── secure-log-starter/  # Spring Boot AutoConfiguration + AOP (core 의존)
├── secure-log-test/     # TestKit - LogAssert, TestLogCapture 유틸리티 (core 의존)
└── scripts/             # Docker 테스트 인프라 스크립트
```

**Module Dependency**: `starter` → `core`, `test` → `core`

**Base Package**: `io.github.hongjungwan.blackbox`

### Key Package Structure
- `api/` - Public API: SecureLogger, @Mask, @AuditContext, LogEntry, LoggingContext
- `core/internal/` - Pipeline 구현 (외부 노출 금지): LogProcessor, VirtualAsyncAppender, ConsoleLogTransport, MerkleChain
- `core/security/` - 보안 구현: PiiMasker, EnvelopeEncryption, LocalKeyManager
- `core/resilience/` - CircuitBreaker, RetryPolicy
- `spi/` - Extension Points: TransportProvider, EncryptionProvider, MaskingStrategy

## Core Architecture

### Processing Pipeline
```
SecureLogger.info() → SLF4J/Logback → VirtualAsyncAppender → LogProcessor:
  1. PII Masking (PiiMasker)
  2. Integrity Chain (MerkleChain) - SHA-256 Hash Chain
  3. Encryption (EnvelopeEncryption) - AES-256-GCM, 1시간 DEK 로테이션
  4. Console Output (ConsoleLogTransport) - NDJSON to System.out
```

### Logback Integration
VirtualAsyncAppender는 Logback Appender로, 사용자 애플리케이션의 `logback-spring.xml`에 등록 필요:
```xml
<appender name="SECURE" class="io.github.hongjungwan.blackbox.core.internal.VirtualAsyncAppender">
    <!-- LogProcessor를 통해 자동 설정 -->
</appender>
```

### Output Format
```json
{"timestamp":1734448200000,"level":"INFO","traceId":"abc123","message":"...","integrity":"sha256:...","encryptedDek":"..."}
```

### Key Components

| 컴포넌트 | 위치 | 역할 |
|---------|------|------|
| `VirtualAsyncAppender` | core/internal | Fixed Thread Pool 기반 비동기 처리 (Logback Appender) |
| `LogProcessor` | core/internal | 파이프라인 오케스트레이션 |
| `ConsoleLogTransport` | core/internal | Thread-safe JSON stdout 출력 |
| `PiiMasker` | core/security | 필드명 기반 + 어노테이션 마스킹 |
| `EnvelopeEncryption` | core/security | DEK/KEK 봉투 암호화 |
| `MerkleChain` | core/internal | 로그 무결성 체인 |
| `LoggingContext` | api/context | W3C Trace Context 전파 |
| `LocalKeyManager` | core/security | KEK 관리 (로컬 모드) |

### SPI Extension Points (`spi/` package)
- `TransportProvider` - 커스텀 로그 전송 목적지
- `EncryptionProvider` - 커스텀 암호화 구현
- `MaskingStrategy` - 커스텀 PII 마스킹 패턴

## Annotation-Based Features

### @Mask - PII 마스킹
```java
public class EmployeeDto {
    @Mask(MaskType.RRN)
    private String residentNumber;    // 123456-1234567 → 123456-*******

    @Mask(MaskType.PHONE)
    private String phoneNumber;       // 010-1234-5678 → 010-****-5678

    @Mask(value = MaskType.RRN, emergency = true)  // Break-glass: RSA 암호화 저장
    private String emergencyRrn;
}

// Usage
PiiMasker masker = new PiiMasker(config);
Map<String, Object> masked = masker.maskObject(dto);
EmployeeDto maskedDto = masker.maskObjectToInstance(dto);
```

**MaskTypes**: RRN, PHONE, EMAIL, CREDIT_CARD, PASSWORD, SSN, NAME, ADDRESS, ACCOUNT_NUMBER

### @AuditContext - 감사 문맥
```java
@AuditContext(
    why = "급여 정보 조회",
    whomParam = "employeeId",
    action = AuditAction.READ
)
public EmployeeSalaryDto getSalary(String employeeId) {
    // who: SecurityContext에서 자동 추출
    // whom: employeeId 파라미터 값
    return repository.findSalary(employeeId);
}
```

**AuditAction**: CREATE, READ, UPDATE, DELETE, EXPORT, APPROVE, REJECT, LOGIN, LOGOUT, PERMISSION_CHANGE, OTHER

## Configuration

```yaml
secure-hr:
  logging:
    enabled: true
    mode: ASYNC                    # SYNC, ASYNC, FALLBACK
    buffer-size: 8192
    consumer-threads: 2
    pii-masking:
      enabled: true
      patterns: ["rrn", "credit_card", "password", "ssn"]
    security:
      encryption-enabled: true
      integrity-enabled: true
      emergency-public-key: "Base64-RSA-public-key"
    audit:
      enabled: true
    fallback-directory: "logs/fallback"
```

## Architecture Constraints

### Thread Safety
- `ReentrantLock` for JSON output synchronization (ConsoleLogTransport)
- `AtomicLong`, `AtomicBoolean` for counters
- `CountDownLatch` for shutdown coordination

### Error Recovery
- `LogProcessor.process()`: 예외 시 마스킹된 엔트리만 fallback 저장
- 원본 미마스킹 데이터 누출 방지

### Graceful Shutdown
```
SecureLogLifecycle.stop():
  1. VirtualAsyncAppender.stop() - 10초 버퍼 드레인 (consumerBatchLatch.await)
  2. Timeout → processFallback()으로 잔여 이벤트 저장
  3. MerkleChain.saveState() - 체인 상태 영속화
```

### Thread Model
- `VirtualAsyncAppender`: `Executors.newFixedThreadPool(consumerThreads)` - 설정 가능한 Consumer 스레드
- `ConsoleLogTransport`: `ReentrantLock` - JSON 출력 동기화
- `ArrayBlockingQueue`: Non-blocking offer, 100ms poll timeout

## Performance Targets

- **Throughput**: 20,000 logs/sec per instance (4 vCPU)
- **Latency**: Log call return < 5μs (non-blocking)
- **Pipeline**: Full pipeline (masking + hash + encryption) < 4ms

## Testing

180+ 테스트 케이스 포함:
- Unit tests: `secure-log-core/src/test/java/`
- Integration tests: `secure-log-core/src/integrationTest/java/` (Docker 필요)
- JMH Benchmarks: `LogProcessorBenchmark`, `PiiMaskerBenchmark`, `SerializationBenchmark`
- Performance tests: `EncryptionPerformanceTest`

```bash
# 단위 테스트
./gradlew :secure-log-core:test

# 통합 테스트 (Docker 필요, Testcontainers 사용)
./gradlew :secure-log-core:integrationTest

# 특정 테스트
./gradlew :secure-log-core:test --tests "EncryptionPerformanceTest"
./gradlew :secure-log-core:test --tests "*Benchmark*"
```

**Note**: 통합 테스트는 `-XX:+EnableDynamicAgentLoading` JVM 옵션이 자동 적용됨

## Dependencies

### secure-log-core
- Jackson (`jackson-databind` 2.18.2) - JSON 직렬화
- Zstd (`zstd-jni` 1.5.6-3) - Fallback 압축
- BouncyCastle (`bcprov-jdk18on` 1.79) - 암호화
- Logback (`logback-classic` 1.5.15) + SLF4J (`slf4j-api` 2.0.16)
- Lombok (`1.18.36`) - compileOnly
- JMH (`1.37`) - testImplementation (벤치마크용)
- Testcontainers (`1.19.7`) - integrationTest용

### secure-log-starter
- Spring Boot Starter (`3.5.8`) - AutoConfiguration
- Spring Boot AOP - @AuditContext 지원
- Spring Security - compileOnly (사용자 추출용, 선택적)
