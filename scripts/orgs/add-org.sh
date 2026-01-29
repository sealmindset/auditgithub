#!/bin/bash
#
# Add Sleep Number organization and import its repositories
#
# Usage: ./add-org.sh [--import-repos]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if we're in a Docker environment or can use local Python
if command -v docker-compose &> /dev/null && docker-compose ps api &> /dev/null 2>&1; then
    echo "Running via Docker..."
    docker-compose exec api python add_sleepnumber_org.py "$@"
else
    # Try local Python with venv if available
    if [ -d "$SCRIPT_DIR/venv" ]; then
        echo "Using local virtual environment..."
        source "$SCRIPT_DIR/venv/bin/activate"
        python "$SCRIPT_DIR/add_sleepnumber_org.py" "$@"
    elif [ -d "$SCRIPT_DIR/.venv" ]; then
        echo "Using local virtual environment..."
        source "$SCRIPT_DIR/.venv/bin/activate"
        python "$SCRIPT_DIR/add_sleepnumber_org.py" "$@"
    else
        echo "ERROR: Cannot find Docker or Python virtual environment"
        echo ""
        echo "Please either:"
        echo "  1. Start Docker: docker-compose up -d"
        echo "  2. Or create a virtual environment: python -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
fi
