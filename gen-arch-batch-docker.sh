#!/bin/bash
#
# Docker-based batch processor for multiple repositories
#
# Usage: ./gen-arch-batch-docker.sh <pattern> [tenant_slug] [options]
#        ./gen-arch-batch-docker.sh "-oic" --skip-if-exists --delay=60
#        ./gen-arch-batch-docker.sh "EBS-R-" "tenant-slug" --delay=45
#
# This version runs entirely in Docker, avoiding macOS bash compatibility issues.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if pattern argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <pattern> [tenant_slug] [options]"
    echo ""
    echo "Examples:"
    echo "  $0 \"-oic\" --skip-if-exists --delay=60"
    echo "  $0 \"EBS-R-\" --delay=45"
    echo "  $0 \"-oic\" \"tenant\" --skip-if-exists --delay=30"
    echo ""
    echo "Options:"
    echo "  --skip-if-exists    Skip repositories that already have architecture files"
    echo "  --delay=SECONDS     Wait SECONDS between processing repos (default: 0)"
    echo "  --max-retries=N     Maximum retry attempts (default: 2)"
    echo ""
    echo "This Docker-based version avoids macOS bash compatibility issues."
    exit 1
fi

# Check if Docker is running
if ! command -v docker-compose &> /dev/null; then
    echo "ERROR: docker-compose not found"
    echo "Please install Docker and docker-compose"
    exit 1
fi

if ! docker-compose ps api &> /dev/null 2>&1; then
    echo "ERROR: Docker containers not running"
    echo "Please start Docker: docker-compose up -d"
    exit 1
fi

echo "Running batch processor in Docker..."
echo ""

# Run the Python batch processor inside Docker
# Pass all arguments directly to the Python script
docker-compose exec -T api python batch_process.py "$@"
