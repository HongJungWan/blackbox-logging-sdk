#!/bin/bash
# Stop test infrastructure for SecureHR Logging SDK
# Usage: ./scripts/stop-test-infra.sh [--clean]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
CLEAN=false

for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN=true
            shift
            ;;
        *)
            ;;
    esac
done

cd "$PROJECT_DIR"

echo -e "${YELLOW}Stopping SecureHR test infrastructure...${NC}"

if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Removing volumes and orphan containers...${NC}"
    docker-compose --profile debug down -v --remove-orphans
else
    docker-compose --profile debug down
fi

echo -e "${GREEN}Test infrastructure stopped.${NC}"
