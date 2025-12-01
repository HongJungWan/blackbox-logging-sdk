#!/bin/bash
# Check Docker status and test infrastructure readiness
# Usage: ./scripts/check-docker.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Checking Docker and test infrastructure..."
echo ""

# Check Docker
echo -n "Docker: "
if docker info > /dev/null 2>&1; then
    echo -e "${GREEN}Running${NC}"
else
    echo -e "${RED}Not running${NC}"
    echo ""
    echo "Please start Docker Desktop and try again."
    exit 1
fi

# Check Docker Compose
echo -n "Docker Compose: "
if docker-compose version > /dev/null 2>&1; then
    echo -e "${GREEN}Available${NC}"
else
    echo -e "${RED}Not found${NC}"
    exit 1
fi

echo ""
echo "Service Status:"

# Check Zookeeper
echo -n "  Zookeeper: "
if docker-compose ps zookeeper 2>/dev/null | grep -q "Up"; then
    echo -e "${GREEN}Running${NC}"
else
    echo -e "${YELLOW}Not running${NC}"
fi

# Check Kafka
echo -n "  Kafka:     "
if docker-compose ps kafka 2>/dev/null | grep -q "Up"; then
    # Also check if Kafka is actually accepting connections
    if docker-compose exec -T kafka kafka-topics --bootstrap-server localhost:9092 --list > /dev/null 2>&1; then
        echo -e "${GREEN}Running & Healthy${NC}"
    else
        echo -e "${YELLOW}Running (not ready)${NC}"
    fi
else
    echo -e "${YELLOW}Not running${NC}"
fi

# Check LocalStack
echo -n "  LocalStack: "
if docker-compose ps localstack 2>/dev/null | grep -q "Up"; then
    if curl -sf http://localhost:4566/_localstack/health > /dev/null 2>&1; then
        echo -e "${GREEN}Running & Healthy${NC}"
    else
        echo -e "${YELLOW}Running (not ready)${NC}"
    fi
else
    echo -e "${YELLOW}Not running${NC}"
fi

echo ""
echo "To start infrastructure: ./scripts/start-test-infra.sh --wait"
echo "To run integration tests: ./gradlew integrationTest"
