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

# Migration 001: Sync schema (remediations, api_endpoints, openapi_specs)
if [ -f "migrations/001_sync_schema.sql" ]; then
    run_sql "migrations/001_sync_schema.sql"
fi

# Migration 002: Organizations (multi-tenant support)
if [ -f "migrations/002_organizations.sql" ]; then
    run_sql "migrations/002_organizations.sql"
fi

# Migration 003: Credential URL test results
if [ -f "migrations/003_credential_url_test_results.sql" ]; then
    run_sql "migrations/003_credential_url_test_results.sql"
fi

# Migration 004: Fix multi-tenant repositories
if [ -f "migrations/004_fix_multi_tenant_repositories.sql" ]; then
    run_sql "migrations/004_fix_multi_tenant_repositories.sql"
fi

# Migration 005: Mobile and Go scanners
if [ -f "migrations/005_mobile_go_scanners.sql" ]; then
    run_sql "migrations/005_mobile_go_scanners.sql"
fi

# Migration 006: Ensure all tables (catch-all)
if [ -f "migrations/006_ensure_all_tables.sql" ]; then
    run_sql "migrations/006_ensure_all_tables.sql"
fi

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
