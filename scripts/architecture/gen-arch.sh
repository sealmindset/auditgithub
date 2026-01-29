#!/bin/bash
#
# Wrapper script to generate architecture diagrams and reports
#
# Usage: ./gen-arch.sh "Repository Name"
#        ./gen-arch.sh "repository-uuid"
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if repository argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <repository_name_or_id> [tenant_slug]"
    echo ""
    echo "Examples:"
    echo "  $0 \"My Repository Name\""
    echo "  $0 \"EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR\""
    echo "  $0 \"d4e5f6g7-8901-2345-6789-012345678901\""
    echo "  $0 \"My Repo\" \"tenant-slug\""
    exit 1
fi

# Check if we're in a Docker environment or can use local Python
if command -v docker-compose &> /dev/null && docker-compose ps api &> /dev/null 2>&1; then
    echo "Running via Docker..."
    docker-compose exec -T api python generate_architecture_cli.py "$@"
else
    # Try local Python with venv if available
    if [ -d "$SCRIPT_DIR/venv" ]; then
        echo "Using local virtual environment..."
        source "$SCRIPT_DIR/venv/bin/activate"
        python "$SCRIPT_DIR/generate_architecture_cli.py" "$@"
    elif [ -d "$SCRIPT_DIR/.venv" ]; then
        echo "Using local virtual environment..."
        source "$SCRIPT_DIR/.venv/bin/activate"
        python "$SCRIPT_DIR/generate_architecture_cli.py" "$@"
    else
        echo "ERROR: Cannot find Docker or Python virtual environment"
        echo ""
        echo "Please either:"
        echo "  1. Start Docker: docker-compose up -d"
        echo "  2. Or create a virtual environment: python -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
fi
