<div align="center">
  <h1>🚛 KBS (blacK-Box logging SDK)</h1>

  <img src="https://github.com/user-attachments/assets/4af1bc28-4377-466a-94a0-1c51ffcf5676" width="600">

</div>

<p align=center>
  <a href="https://github.com/HongJungWan/blackbox-logging-sdk/wiki">📕 위키</a>
</p>

## ✍🏻 프로젝트 개요

> "바퀴를 다시 발명하지 말라구요? 하지만 맞는 바퀴가 없다면 만들어야죠."

로그, 그냥 남기면 되는 줄 알았습니다. 하지만 '보안'이 붙는 순간 이야기가 달라지더군요. 

주민번호 마스킹, DB 암호화, 감사(Audit) 기록, 위변조 방지... 이 모든 걸 갖춘 오픈소스, 찾아보셨나요?

놀랍게도 세상에 없었습니다.

물론 Logback이나 SLF4J를 커스텀해서 구현할 수도 있습니다. 하지만 7가지나 되는 보안 요구사항을 기존 라이브러리에 억지로 끼워 맞추다 보면 로깅 코드를 짜는 데 생각보다 많은 시간을 쏟게 됩니다.

이 프로젝트의 목적은 단순합니다. "보안 로그 때문에 야근하지 말자"는 것입니다. 

복잡한 보안 로깅 기능을 AOP와 어노테이션으로 우아하게 말아 넣었습니다.

까다로운 보안 요구사항은 KBS가 알아서 처리해서 안전하게 블랙박스에 담아두겠습니다.

<br><br>

## ⚙️ 핵심 기능

### 1. PII 자동 마스킹

> 비즈니스 로직에만 집중하세요. 
> 전화번호, 이메일, 주민등록번호 같은 민감 정보(PII)가 감지되면 SDK가 자동으로 `******` 마스킹 처리하여 저장합니다.

<img src="https://github.com/user-attachments/assets/a4116d53-4855-458b-bccc-1d448b74d682" width="450">

<br>

### 2. @Mask 어노테이션 마스킹

> DTO 필드에 어노테이션만 붙이면 리플렉션 프로세서가 자동으로 마스킹을 수행합니다. 
> 9가지 MaskType(RRN, PHONE, EMAIL, CREDIT_CARD, PASSWORD, SSN, NAME, ADDRESS, ACCOUNT_NUMBER)을 지원합니다.

```java
  public class EmployeeDto {
      @Mask(MaskType.RRN)
      private String residentNumber;    // 123456-1234567 → 123456-*******

      @Mask(MaskType.PHONE)
      private String phoneNumber;       // 010-1234-5678 → 010-****-5678

      @Mask(MaskType.EMAIL)
      private String email;             // user@example.com → u***@example.com
  }
```

<br>

### 3. 비상용 복호화 로깅 (Break-glass)

> "마스킹된 데이터, 사고 분석 시 원본이 필요하면?" 이런 고민을 해결합니다. 
> `@Mask(emergency = true)` 설정 시 마스킹 대신 RSA-OAEP로 암호화된 원본을 저장합니다. 
> 평문 노출 없이 추후 인가된 관리자만 복호화할 수 있습니다.

```java
  @Mask(value = MaskType.RRN, emergency = true)
  private String residentNumber;        // 결과: {"display":"123456-*******", "encrypted":"Base64..."}
```

<br>

### 4. AOP 기반 감사 문맥

> 누가(Who), 누구의(Whom) 정보를 왜(Why) 봤는지 자동으로 기록합니다.
> 비즈니스 로직에 침투하지 않고도 감사 정보를 추출합니다.

```java
  @AuditContext(
      why = "급여 정보 조회",
      whomParam = "employeeId",
      action = AuditAction.READ
  )
  public EmployeeSalaryDto getSalary(String employeeId) {
      // who: Spring Security에서 자동 추출
      // whom: employeeId 파라미터 값
      // why: "급여 정보 조회"
      return repository.findSalary(employeeId);
  }
```

<br>

### 5. 위변조 방지

> 로그의 신뢰성을 위해 블록체인의 Hash Chain 기술을 적용했습니다. 
> 이전 로그와 현재 로그가 체인처럼 연결되어 있어, 중간에 데이터가 1바이트라도 변조되면 즉시 탐지 가능합니다.

<img src="https://github.com/user-attachments/assets/a8baa6f2-661b-4a94-b893-b899ca7ab6c0" width="450">

<br>

### 6. 암호화

> 저장되는 순간 AES-256-GCM 암호화 방식이 적용됩니다. 
> 암호화 키 없이는 그 누구도 내용을 확인할 수 없습니다.

<img src="https://github.com/user-attachments/assets/f9a33ea7-59ab-4146-8c26-8202039fc7da" width="450">

<br>

### 7. Crypto-Shredding

> 수많은 로그 속에서 특정 개인정보를 찾아 지우는 것은 비효율적입니다. 
> 우리는 해당 데이터의 '암호화 키'를 파기하는 방식으로, 데이터를 영구적으로 복구 불가능하게 만듭니다.

<img src="https://github.com/user-attachments/assets/c9c70602-8db7-4478-a91a-a80a34d9f51a" width="450">

<br><br>

## 🤿 이런 차이점이 있어요

| 기능                        | ⭐️ KBS SDK ⭐ | Logback+SLF4J |
  |:--------------------------|:------------:| :---: | 
| **PII 자동 마스킹**            |   ✅ **내장**   | ❌ | 
| **@Mask 어노테이션**           |      ✅       | ❌ | 
| **비상용 복호화**               |      ✅       | ❌ |
| **감사 문맥 (@AuditContext)** |      ✅       | ❌ | 
| **위변조 방지 (Hash Chain)**   |      ✅       | ❌ | 
| **암호화**                   |      ✅       | ❌ | 
| **Crypto-Shredding**      |      ✅       | ❌ |

<br><br>

## 🤿 기술 스택

<table>
    <thead>
        <tr>
            <th>분류</th>
            <th>기술 스택</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
                <p>BackEnd</p>
            </td>
            <td>
                <img src="https://img.shields.io/badge/Java-ED8B00?logo=openjdk&logoColor=white" alt="Java"/>
                <img src="https://img.shields.io/badge/Spring%20Boot-6DB33F?logo=springboot&logoColor=white" alt="Spring Boot"/>
            </td>
        </tr>
        <tr>
            <td>
                <p>Infra</p>
            </td>
            <td>
                <img src="https://img.shields.io/badge/AWS-%23232F3E.svg?style=flat&logo=amazonwebservices&logoColor=white" alt="AWS"/>
            </td>
        </tr>
    </tbody>
</table>

<br><br>

## 🏛️ 서비스 아키텍처

<img src="https://github.com/user-attachments/assets/9a3a4a1c-d2e8-4075-a044-b8b99a850d36" width="500">

<br><br>

## 🛠️ KBS SDK 사용 가이드

### 1. 라이브러리 추가

> `build.gradle` 파일에 의존성을 추가합니다.

```groovy
dependencies {
    implementation 'io.github.hongjungwan:blackbox-logging-sdk:3.0.0-RELEASE'
}
```

<br>

### 2. 설정하기

> application.yml에서 로깅 정책을 설정합니다. 비동기 처리(ASYNC)를 통해 애플리케이션 성능 영향을 최소화하며, 보안 옵션을 손쉽게 활성화할 수 있습니다.

```yaml
secure-hr:
  logging:
    enabled: true
    mode: ASYNC          # 로깅 성능 최적화 (ASYNC / SYNC)
    pii-masking:
      enabled: true
      patterns: [rrn, credit_card, password, ssn] # 자동 마스킹할 필드명 패턴
    security:
      encryption-enabled: true # 로그 데이터 암호화 활성화
      integrity-enabled: true  # 로그 위변조 방지를 위한 무결성 검증 활성화
    fallback-directory: "logs/fallback" # 로깅 실패 시 저장할 로컬 경로
```

<br>

### 3. 사용법

#### 3.1. SecureLogger
일반 Logger와 동일하게 사용하되, 설정된 민감 정보 패턴(예: rrn)이 감지되면 자동으로 마스킹 처리됩니다.

```java
@Service
public class EmployeeService {

    private final SecureLogger secureLogger;

    public void process(String employeeId) {
        // 민감 정보(rrn)는 자동으로 마스킹되어 기록됩니다.
        secureLogger.info("급여 조회", Map.of(
            "employeeId", employeeId,
            "rrn", "901234-1234567"    // Log Output: 901234-*******
        ));
    }
}
```

<br>

#### 3.2. @Mask Annotation
DTO 필드에 @Mask 어노테이션을 적용하여 명시적으로 마스킹 정책을 적용할 수 있습니다.

```java
public class EmployeeDto {
    @Mask(MaskType.RRN)        // 주민등록번호 마스킹
    private String residentNumber;

    @Mask(MaskType.PHONE)      // 전화번호 마스킹
    private String phoneNumber;
}
```

<br>

#### 3.3. @AuditContext Annotation (Audit Logging)
누가(Who), 왜(Why), 어떤 행위(Action)를 했는지 명확한 감사 로그를 남깁니다. Controller 메서드에 적용 시 반복적인 감사 로깅 코드를 줄일 수 있습니다.

```java
@AuditContext(
    why = "급여 정보 조회",       // 조회 목적
    whomParam = "employeeId",   // 조회 대상 (파라미터명 매핑)
    action = AuditAction.READ   // 수행 행위
)
@GetMapping("/{employeeId}/salary")
public SalaryDto getSalary(@PathVariable String employeeId) {
    // 비즈니스 로직 실행 시, Audit Context 정보가 자동으로 로깅됩니다.
    return service.getSalary(employeeId);
}
```

<br>

### 4. 로그 출력 예시

> 읽기 쉬운 JSON 포맷으로 출력되며, 보안 메타데이터가 포함됩니다.

```json
{
  "timestamp": 1734448200000,
  "level": "INFO",
  "traceId": "abc123",
  "message": "급여 조회",
  "payload": {
    "employeeId": "EMP001",
    "rrn": "901234-*******"
  },
  "integrity": "sha256:a1b2c3d4...", 
  "encryptedDek": "eyJhbGciOi..."
}
```

* **payload**: 마스킹 처리된 안전한 데이터
* **integrity**: 로그 위변조 검증을 위한 해시 값
* **encryptedDek**: 데이터 복호화를 위한 암호화된 키

<br>