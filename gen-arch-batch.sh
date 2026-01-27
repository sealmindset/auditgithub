#!/bin/bash
#
# Batch process multiple repositories matching a pattern
#
# Usage: ./gen-arch-batch.sh <pattern> [tenant_slug] [--skip-if-exists] [--delay=SECONDS]
#        ./gen-arch-batch.sh "-oic"
#        ./gen-arch-batch.sh "EBS-R-" "tenant-slug"
#        ./gen-arch-batch.sh "-oic" --skip-if-exists --delay=60
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
SKIP_IF_EXISTS=false
DELAY=0  # No delay by default

# Check if pattern argument is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <pattern> [tenant_slug] [--skip-if-exists] [--delay=SECONDS]"
    echo ""
    echo "Examples:"
    echo "  $0 \"-oic\"                          # Process all repos with '-oic' in name"
    echo "  $0 \"EBS-R-\"                        # Process all repos starting with 'EBS-R-'"
    echo "  $0 \"-oic\" \"tenant\"                 # Process with specific tenant"
    echo "  $0 \"-oic\" --skip-if-exists        # Skip repos with existing architecture"
    echo "  $0 \"-oic\" --delay=60              # Add 60s delay between repos (rate limiting)"
    echo "  $0 \"-oic\" --skip-if-exists --delay=30  # Combine options"
    echo ""
    echo "Options:"
    echo "  --skip-if-exists    Skip repositories that already have architecture files"
    echo "  --delay=SECONDS     Wait SECONDS between processing repos (default: 0)"
    echo ""
    echo "Pattern matching is case-insensitive and matches anywhere in the repository name."
    exit 1
fi

PATTERN="$1"
TENANT_SLUG="default"

# Parse arguments
shift  # Remove pattern argument
for arg in "$@"; do
    case "$arg" in
        --skip-if-exists)
            SKIP_IF_EXISTS=true
            ;;
        --delay=*)
            DELAY="${arg#*=}"
            ;;
        *)
            # Assume it's the tenant slug if it doesn't start with --
            if [[ ! "$arg" =~ ^-- ]]; then
                TENANT_SLUG="$arg"
            fi
            ;;
    esac
done

echo "========================================"
echo "Batch Architecture Generation"
echo "========================================"
echo "Pattern: $PATTERN"
echo "Tenant: $TENANT_SLUG"
if [ "$SKIP_IF_EXISTS" = true ]; then
    echo "Mode: Skip if exists"
fi
if [ "$DELAY" -gt 0 ]; then
    echo "Delay: ${DELAY}s between repos"
fi
echo "========================================"
echo ""

# Create temporary Python script for querying
QUERY_SCRIPT_FILE=$(mktemp)
cat > "$QUERY_SCRIPT_FILE" <<'EOF'
import sys
import os

# Add src to path - when running in Docker, use /app, otherwise use current dir
if os.path.exists('/app/src'):
    sys.path.insert(0, '/app')
else:
    sys.path.insert(0, os.getcwd())

from src.api.database import SessionLocal, MULTI_TENANT_ENABLED
from src.api.database_router import database_router
from src.api import models

pattern = sys.argv[1]
tenant_slug = sys.argv[2] if len(sys.argv) > 2 else "default"

# Initialize database connection
if MULTI_TENANT_ENABLED:
    db = database_router.get_session(tenant_slug)
else:
    db = SessionLocal()

try:
    # Query repositories matching pattern (case-insensitive)
    repos = db.query(models.Repository).filter(
        models.Repository.name.ilike(f"%{pattern}%")
    ).order_by(models.Repository.name).all()

    # Print repository names (one per line)
    for repo in repos:
        print(repo.name)
finally:
    db.close()
EOF

# Get list of matching repositories
if command -v docker-compose &> /dev/null && docker-compose ps api &> /dev/null 2>&1; then
    echo "Querying database via Docker..."
    # Copy script to container and run it
    docker-compose exec -T api bash -c "cat > /tmp/query_repos.py" < "$QUERY_SCRIPT_FILE"
    REPOS=$(docker-compose exec -T api python /tmp/query_repos.py "$PATTERN" "$TENANT_SLUG")
    docker-compose exec -T api rm -f /tmp/query_repos.py
else
    echo "Querying database locally..."
    if [ -d "$SCRIPT_DIR/venv" ]; then
        source "$SCRIPT_DIR/venv/bin/activate"
    elif [ -d "$SCRIPT_DIR/.venv" ]; then
        source "$SCRIPT_DIR/.venv/bin/activate"
    fi
    cd "$SCRIPT_DIR"
    REPOS=$(python "$QUERY_SCRIPT_FILE" "$PATTERN" "$TENANT_SLUG")
fi

# Cleanup
rm -f "$QUERY_SCRIPT_FILE"

# Read repos into array (this prevents stdin consumption issues in the loop)
# Use portable approach compatible with bash 3.2 (macOS default)
REPO_ARRAY=()
while IFS= read -r line; do
    [ -n "$line" ] && REPO_ARRAY+=("$line")
done < <(echo "$REPOS")
REPO_COUNT=${#REPO_ARRAY[@]}

if [ "$REPO_COUNT" -eq 0 ]; then
    echo "No repositories found matching pattern: $PATTERN"
    exit 1
fi

echo "Found $REPO_COUNT repositories matching pattern '$PATTERN':"
echo ""
for repo in "${REPO_ARRAY[@]}"; do
    echo "$repo"
done
echo ""
echo "========================================"
echo ""

# Ask for confirmation
read -p "Process all $REPO_COUNT repositories? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "Starting batch processing..."
echo ""

# Self-healing configuration
MAX_RETRIES=2
TIMEOUT_SECONDS=600  # 10 minutes max per repository
RATE_LIMIT_BACKOFF=300  # 5 minutes wait if rate limited

# Process each repository
SUCCESS_COUNT=0
SKIP_COUNT=0
FAIL_COUNT=0
FAILED_REPOS=()
SKIPPED_REPOS=()
RETRY_QUEUE=()

# Function to execute with timeout and self-healing
process_repo_with_healing() {
    local repo_name="$1"
    local retry_count="${2:-0}"

    # Build command with optional flags
    CMD_ARGS=("$repo_name")
    if [ "$TENANT_SLUG" != "default" ]; then
        CMD_ARGS+=("$TENANT_SLUG")
    fi
    if [ "$SKIP_IF_EXISTS" = true ]; then
        CMD_ARGS+=("--skip-if-exists")
    fi

    # Execute with timeout and stdin protection
    # Use timeout command if available, otherwise use built-in alarm
    if command -v timeout &> /dev/null; then
        OUTPUT=$(timeout "$TIMEOUT_SECONDS" "$SCRIPT_DIR/gen-arch.sh" "${CMD_ARGS[@]}" < /dev/null 2>&1)
        EXIT_CODE=$?
    else
        # Fallback: use background process with manual timeout
        OUTPUT=$( (
            trap 'kill 0' TERM
            "$SCRIPT_DIR/gen-arch.sh" "${CMD_ARGS[@]}" < /dev/null 2>&1 &
            CHILD_PID=$!
            (sleep "$TIMEOUT_SECONDS" && kill -TERM $CHILD_PID 2>/dev/null) &
            TIMEOUT_PID=$!
            wait $CHILD_PID
            EXIT_CODE=$?
            kill -TERM $TIMEOUT_PID 2>/dev/null
            exit $EXIT_CODE
        ) )
        EXIT_CODE=$?
    fi

    # Display output
    echo "$OUTPUT"

    # Self-healing: Detect common error patterns
    local should_retry=false
    local retry_reason=""

    if [ $EXIT_CODE -eq 124 ] || [ $EXIT_CODE -eq 137 ]; then
        # Timeout occurred
        retry_reason="timeout (exceeded ${TIMEOUT_SECONDS}s)"
        should_retry=true
    elif echo "$OUTPUT" | grep -qi "rate limit"; then
        # Rate limit hit
        retry_reason="rate limit exceeded"
        should_retry=true
        if [ $retry_count -eq 0 ]; then
            echo "⚠ Rate limit detected! Waiting ${RATE_LIMIT_BACKOFF}s before retry..."
            sleep "$RATE_LIMIT_BACKOFF"
        fi
    elif echo "$OUTPUT" | grep -qi "repository not found\|does not exist\|no such repository"; then
        # Repository doesn't exist - don't retry
        retry_reason="repository not found (permanent failure)"
        should_retry=false
    elif echo "$OUTPUT" | grep -qi "authentication failed\|permission denied\|401\|403"; then
        # Auth issues - don't retry
        retry_reason="authentication/permission error (permanent failure)"
        should_retry=false
    elif echo "$OUTPUT" | grep -qi "network\|connection\|timeout\|timed out"; then
        # Network issues - retry
        retry_reason="network/connection error"
        should_retry=true
    elif [ $EXIT_CODE -ne 0 ]; then
        # Generic failure - retry once
        retry_reason="unknown error (exit code: $EXIT_CODE)"
        should_retry=true
    fi

    # Return success status
    if [ $EXIT_CODE -eq 0 ]; then
        if echo "$OUTPUT" | grep -q "SKIPPED!"; then
            return 2  # Skipped
        else
            return 0  # Success
        fi
    elif [ "$should_retry" = true ] && [ $retry_count -lt $MAX_RETRIES ]; then
        return 3  # Retry
    else
        return 1  # Failed permanently
    fi
}

# Iterate over array instead of heredoc to avoid stdin consumption
for repo_name in "${REPO_ARRAY[@]}"; do
    # Skip empty lines
    if [ -z "$repo_name" ]; then
        continue
    fi

    CURRENT=$((SUCCESS_COUNT + SKIP_COUNT + FAIL_COUNT + 1))

    echo "========================================"
    echo "Processing: $repo_name"
    echo "Progress: $CURRENT/$REPO_COUNT"
    echo "========================================"

    # Try processing with retries
    retry_count=0
    success=false

    while [ $retry_count -le $MAX_RETRIES ]; do
        if [ $retry_count -gt 0 ]; then
            echo "⟳ Retry attempt $retry_count/$MAX_RETRIES for: $repo_name"
            # Exponential backoff: 30s, 60s
            backoff=$((30 * retry_count))
            echo "Waiting ${backoff}s before retry..."
            sleep "$backoff"
        fi

        process_repo_with_healing "$repo_name" "$retry_count"
        result=$?

        if [ $result -eq 0 ]; then
            # Success
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            echo "✓ SUCCESS: $repo_name"
            ACTUAL_DELAY=$DELAY
            success=true
            break
        elif [ $result -eq 2 ]; then
            # Skipped
            SKIP_COUNT=$((SKIP_COUNT + 1))
            SKIPPED_REPOS+=("$repo_name")
            echo "⊘ SKIPPED: $repo_name (architecture already exists)"
            ACTUAL_DELAY=10
            success=true
            break
        elif [ $result -eq 3 ]; then
            # Should retry
            retry_count=$((retry_count + 1))
            continue
        else
            # Permanent failure
            break
        fi
    done

    if [ "$success" = false ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_REPOS+=("$repo_name")
        echo "✗ FAILED: $repo_name (after $retry_count retries)"
        ACTUAL_DELAY=$DELAY
    fi

    echo ""

    # Add delay between repositories (except after last one)
    # Use shorter delay for skipped repos
    if [ "$CURRENT" -lt "$REPO_COUNT" ] && [ "$ACTUAL_DELAY" -gt 0 ]; then
        echo "Waiting ${ACTUAL_DELAY}s before next repository..."
        sleep "$ACTUAL_DELAY"
        echo ""
    fi
done

# Print summary
echo "========================================"
echo "Batch Processing Complete"
echo "========================================"
echo "Total: $REPO_COUNT repositories"
echo "Success: $SUCCESS_COUNT (generated architecture)"
echo "Skipped: $SKIP_COUNT (already had architecture)"
echo "Failed: $FAIL_COUNT"
echo ""

if [ $SKIP_COUNT -gt 0 ]; then
    echo "Skipped repositories (already had architecture):"
    for repo in "${SKIPPED_REPOS[@]}"; do
        echo "  - $repo"
    done
    echo ""
fi

if [ $FAIL_COUNT -gt 0 ]; then
    echo "Failed repositories:"
    for repo in "${FAILED_REPOS[@]}"; do
        echo "  - $repo"
    done
    echo ""
    exit 1
else
    echo "All repositories processed successfully!"
    exit 0
fi
