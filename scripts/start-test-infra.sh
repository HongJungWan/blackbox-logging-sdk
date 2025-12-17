#!/bin/bash
# Start test infrastructure for SecureHR Logging SDK integration tests
# Usage: ./scripts/start-test-infra.sh [--wait]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
WAIT_FOR_READY=false

for arg in "$@"; do
    case $arg in
        --wait)
            WAIT_FOR_READY=true
            shift
            ;;
        *)
            ;;
    esac
done

echo -e "${GREEN}Starting SecureHR test infrastructure...${NC}"

cd "$PROJECT_DIR"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Start services
docker-compose up -d

# Wait for services to be ready
if [ "$WAIT_FOR_READY" = true ]; then
    echo -e "${YELLOW}Waiting for services to be healthy...${NC}"

    # Wait for LocalStack
    echo -n "Waiting for LocalStack..."
    timeout=60
    while ! curl -sf http://localhost:4566/_localstack/health > /dev/null 2>&1; do
        sleep 2
        timeout=$((timeout - 2))
        if [ $timeout -le 0 ]; then
            echo -e "${RED} Timeout waiting for LocalStack${NC}"
            exit 1
        fi
        echo -n "."
    done
    echo -e "${GREEN} Ready${NC}"
fi

echo ""
echo -e "${GREEN}Test infrastructure is running!${NC}"
echo ""
echo "Services:"
echo "  - LocalStack: localhost:4566 (KMS)"
echo ""
echo "Commands:"
echo "  Stop:    docker-compose down"
echo "  Logs:    docker-compose logs -f"
echo "  Status:  docker-compose ps"
