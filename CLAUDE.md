# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Blackbox Logging SDK is a Java 21-based SDK designed for secure logging with HR domain requirements. The project focuses on real-time encryption of sensitive information, integrity verification using Merkle Tree technology, and high-performance logging through Java 21 Virtual Threads and Off-heap RingBuffer architecture.

Key architectural features:
- Envelope Encryption for data protection
- Merkle Tree for tamper detection
- Integration with SLF4J for logging interface
- Performance-optimized for audit systems

## Common Commands

### Build and Run
```bash
# Build the project
./gradlew build

# Run tests
./gradlew test

# Run a single test class
./gradlew test --tests "ClassName"

# Run a single test method
./gradlew test --tests "ClassName.methodName"

# Clean build artifacts
./gradlew clean

# Build without running tests
./gradlew build -x test
```

### Running the Application
```bash
# Run the Spring Boot application
./gradlew bootRun
```

## Technology Stack

- **Java**: 21 (with Virtual Threads support)
- **Framework**: Spring Boot 3.5.8
- **Build Tool**: Gradle
- **Logging**: SLF4J integration
- **Dependencies**: Lombok, Spring Web

## Project Structure

- **Base Package**: `io.github.hongjungwan.blackbox`
- **Main Application**: `BlackboxLoggingSdkApplication.java` - Standard Spring Boot entry point
- **Resources**: Configuration in `application.properties`

## Architecture Notes

This is an SDK project intended to be consumed by other Java applications. The architecture should support:

1. **Virtual Threads**: Leverage Java 21's virtual threads for high-performance concurrent logging
2. **Off-heap Memory**: RingBuffer implementation should utilize off-heap memory for performance
3. **Encryption**: Envelope encryption layer for sensitive data protection
4. **Integrity**: Merkle Tree implementation for log integrity verification
5. **SLF4J Integration**: Provide logging interface compatible with SLF4J ecosystem

The project is in early stages with only the Spring Boot skeleton currently implemented.
