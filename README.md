<div align="center">
  <h1>Blackbox Logging SDK</h1>

![blackbox-logging-sdk]()
</div>

<p align=center>
  <a href="">📕 위키</a>
  &nbsp; | &nbsp; 
  <a href="">🔍 기획서</a>
  &nbsp; | &nbsp;
  <a href="">🛠️ How To Install?</a>
  &nbsp;
</p>

## ✍🏻 프로젝트 개요

"기존 SLF4J와 Logback만으로는 HR 도메인의 엄격한 보안과 성능 요구를 동시에 충족하기 어려웠습니다."

민감 정보의 실시간 암호화와 무결성 검증은 필연적으로 성능 병목을 야기하기 때문입니다. Blackbox Logging SDK는 이 난제를 해결하기 위해 Java 21 Virtual Threads와 Off-heap RingBuffer 아키텍처를 도입했습니다.

시스템이 멈추는 순간까지 데이터를 보호하는 Envelope Encryption과 위변조를 막는 Merkle Tree 기술을 통해, 성능 타협 없는 완벽한 '블랙박스' 감사(Audit) 시스템을 제공합니다.

![]()

## ⚙️ 핵심 기능

### 시스템 로그를 저장할 수 있어요

> 제공되는 Java SDK를 활용해 로그를 전송해보세요!
> Java `Slf4j`를 통해 제공됩니다.

<img width="1200" alt="image" src="">

### 저장한 로그를 조회할 수 있어요

> SDK를 통해서 전송된 로그들을 조회해보세요!

<img width="1200" alt="image" src="">

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
                <img src="https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL"/>
            </td>
        </tr>
        <tr>
            <td>
                <p>SDK</p>
            </td>
            <td>
              <img src="https://img.shields.io/badge/Java-%23ED8B00.svg?logo=openjdk&logoColor=white">
            </td>
        </tr>
    </tbody>
</table>

## 🏛️ 서비스 아키텍처

![Sercice Architecture]()
