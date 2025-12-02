<div align="center">
  <h1>🚛 KBS (Blackbox Logging SDK)</h1>

  <img src="https://github.com/user-attachments/assets/4af1bc28-4377-466a-94a0-1c51ffcf5676" width="600">

</div>

<p align=center>
  <a href="https://github.com/HongJungWan/blackbox-logging-sdk/wiki">📕 위키</a>
</p>

## ✍🏻 프로젝트 개요

"로그, 남기는 건 필수지만 기다리는 건 싫으니까요."

보안이 강력한 로그 시스템은 느려지기 쉽습니다. 암호화와 무결성 검증 비용이 곧 레이턴시가 되기 때문입니다.
우리는 **Java 21의 Virtual Thread**와 **Lock-free Queue**를 도입해 이 문제를 해결했습니다.

물론, 속도만 챙긴 것은 아닙니다. 제가 개발을 하며 겪은 보안 고민들도 함께 담았습니다.

- 💡 어? 방금 로그에 주민번호 찍힌 거 아냐?
- 💡 이 로그, 진짜 원본 맞아요?
- 💡 퇴사한 직원 데이터, 언제 다 지우지?

KBS SDK를 사용하면 시스템 부하가 높아져도 로그는 메인 로직을 방해하지 않고, 안전하게 포장되어 배달됩니다.

<br><br>

## ⚙️ 핵심 기능

### 1. PII 자동 마스킹

> 비즈니스 로직에만 집중하세요. 전화번호, 이메일, 주민등록번호 같은 민감 정보(PII)가 감지되면 SDK가 자동으로 `******` 마스킹 처리하여 저장합니다.

<img src="https://github.com/user-attachments/assets/3dd44c8f-8a36-4000-b0a5-e250810f2ed0" width="450">

### 2. 위변조 방지

> 로그의 신뢰성을 위해 블록체인의 Hash Chain 기술을 적용했습니다. 
> 이전 로그와 현재 로그가 체인처럼 연결되어 있어, 중간에 데이터가 1바이트라도 변조되면 즉시 탐지 가능합니다.

<img src="https://github.com/user-attachments/assets/5adfc1d7-32ac-456d-a6bf-44cd89867d5d" width="450">

### 3. 암호화

> 저장되는 순간 현존 최고 수준의 암호화 방식인 AES-256-GCM이 적용됩니다. 
> 암호화 키 없이는 그 누구도 내용을 확인할 수 없습니다.

<img src="https://github.com/user-attachments/assets/2c2ae06c-c7d1-4745-9f55-51cfc9e72e74" width="450">

### 4. Crypto-Shredding

> 수많은 로그 속에서 특정 개인정보를 찾아 지우는 것은 비효율적입니다. 
> 우리는 해당 데이터의 '암호화 키'를 파기하는 방식으로, 데이터를 영구적으로 복구 불가능하게 만듭니다.

<img src="https://github.com/user-attachments/assets/caa74a07-ec89-4777-a00e-ca7aa99a1436" width="450">

<br><br>

## 🤿 이런 차이점이 있어요

| 기능 | ⭐️ KBS SDK ⭐ | Logback+SLF4J | Sentry | Datadog |
| :--- |:------------:| :---: | :---: | :---: |
| **PII 자동 마스킹** |   ✅ **내장**   | ❌ | ❌ | 추가 설정 |
| **위변조 방지 (Hash Chain)** |      ✅       | ❌ | ❌ | ❌ |
| **암호화 (AES-256-GCM)** |      ✅       | ❌ | ❌ | ❌ |
| **Crypto-Shredding (GDPR)** |      ✅       | ❌ | ❌ | ❌ |
| **데이터 위치** |    자체 인프라    | 자체 | Sentry 서버 | Datadog 서버 |

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
                <img src="https://img.shields.io/badge/Apache%20Kafka-000000?style=flat&logo=apachekafka&logoColor=white" alt="Kafka"/>
                <img src="https://img.shields.io/badge/AWS-%23232F3E.svg?style=flat&logo=amazonwebservices&logoColor=white" alt="AWS"/>
            </td>
        </tr>
    </tbody>
</table>

<br><br>

## 🏛️ 서비스 아키텍처

<img src="https://github.com/user-attachments/assets/82893c14-ba04-4abf-b75d-bb698faa3354" width="500">
