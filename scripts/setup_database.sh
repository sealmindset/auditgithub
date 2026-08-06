#!/bin/bash
# =============================================================================
# AuditGH Database Setup Script
# =============================================================================
# This script sets up the complete database schema from scratch.
# Safe to run on existing databases - uses IF NOT EXISTS throughout.
#
# Usage:
#   ./scripts/setup_database.sh
#
# Or from docker-compose:
#   docker-compose run --rm --entrypoint bash auditgh -c './scripts/setup_database.sh'
# =============================================================================

set -e

echo "=============================================="
echo "AuditGH Database Setup"
echo "=============================================="

# Database connection - uses same defaults as .env.example
DB_HOST="${POSTGRES_HOST:-db}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_USER="${POSTGRES_USER:-postgres}"
DB_NAME="${POSTGRES_DB:-auditgh_kb}"
DB_PASSWORD="${POSTGRES_PASSWORD:-postgres}"

export PGPASSWORD="$DB_PASSWORD"

# Function to run SQL
run_sql() {
    local file=$1
    echo "Applying: $file"
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$file" 2>&1 || true
}

# Function to run SQL command
run_cmd() {
    local cmd=$1
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$cmd" 2>&1 || true
}

echo ""
echo "1. Checking database connection..."
run_cmd "SELECT 1 as connected;" | grep -q "connected" && echo "   ✓ Connected to $DB_NAME" || { echo "   ✗ Failed to connect"; exit 1; }

echo ""
echo "2. Applying base schema..."
run_sql "setup/schema.sql"

echo ""
echo "3. Applying migrations in order..."

# Every numbered migration under migrations/ is applied in numeric order.
# Previously 001-006 were hardcoded here, so 007+ (including 017_cicd_tracking
# and 020_deployment_topology) never ran on a fresh database.
#
# Mock-user seeds are dev-only and stay opt-in via SEED_MOCK_USERS=true.
for migration in $(ls migrations/[0-9][0-9][0-9]_*.sql 2>/dev/null | sort -V); do
    case "$migration" in
        *seed_mock*)
            if [ "${SEED_MOCK_USERS:-false}" != "true" ]; then
                echo "Skipping (dev-only seed, set SEED_MOCK_USERS=true to apply): $migration"
                continue
            fi
            ;;
    esac
    run_sql "$migration"
done

echo ""
echo "4. Verifying tables..."
TABLE_COUNT=$(run_cmd "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | grep -E '^\s*[0-9]+' | tr -d ' ')
echo "   Tables created: $TABLE_COUNT"

echo ""
echo "5. Verifying organizations table columns..."
ORG_COLS=$(run_cmd "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'organizations';" | grep -E '^\s*[0-9]+' | tr -d ' ')
echo "   Organizations columns: $ORG_COLS"

echo ""
echo "=============================================="
echo "Database setup complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Start all services: docker-compose up -d"
echo "  2. List organizations: docker-compose run --rm --entrypoint bash auditgh -c 'python3 scan_repos.py --list-orgs'"
echo ""
