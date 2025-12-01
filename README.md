<div align="center">
  <h1>Blackbox Logging SDK</h1>

  <img src="https://github.com/user-attachments/assets/4af1bc28-4377-466a-94a0-1c51ffcf5676" width="600">

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

"로그, 남기는 건 필수지만 기다리는 건 싫으니까요."

감사 시스템에서 '엄격한 보안'과 '빠른 성능'은 양립하기 힘든 문제입니다. 암호화 비용이 곧 레이턴시가 되기 때문입니다.

우리는 이 트레이드오프를 아키텍처로 극복했습니다.
- Java 21 Virtual Thread로 동시성을 극대화하고,
- Lock-free Queue로 스레드 경합(Contention)을 없앴습니다.

시스템이 아무리 바빠도 로그는 조용히, 그리고 안전하게 기록됩니다.

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
