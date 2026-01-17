#!/bin/bash
# clean_and_scan.sh - Clean up orphan containers and run a scan
# Usage: ./clean_and_scan.sh [--repo <repo>] [additional args...]
#
# This script gracefully removes orphan Docker containers that conflict
# with the auditgh stack, then runs a scan.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Cleaning up Docker environment ==="

# Stop any running containers from this project
echo "[1/4] Stopping any running containers..."
docker-compose down --remove-orphans 2>/dev/null || true

# Remove the specific conflicting container if it exists
echo "[2/4] Removing orphan auditgh_db container if present..."
docker rm -f auditgh_db 2>/dev/null || true

# Prune any dangling containers (optional, safe cleanup)
echo "[3/4] Pruning stopped containers..."
docker container prune -f 2>/dev/null || true

echo "[4/4] Docker environment cleaned."
echo ""

# Run the scan with provided arguments
echo "=== Starting scan ==="
if [ $# -eq 0 ]; then
    echo "No arguments provided. Running: docker-compose run --rm auditgh --repo android-consumer-app"
    docker-compose run --rm auditgh --repo android-consumer-app
else
    echo "Running: docker-compose run --rm auditgh $@"
    docker-compose run --rm auditgh "$@"
fi
