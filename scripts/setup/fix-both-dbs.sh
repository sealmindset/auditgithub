#!/bin/bash
#
# Fix organizations table schema in BOTH databases
# - security_portal (used by API for architecture generation)
# - auditgh_kb (used by scanner for security scans)
#
# Usage: ./fix-both-dbs.sh
#

set -e

echo "========================================="
echo "Fixing Organizations Table Schema"
echo "========================================="
echo ""

if ! command -v docker-compose &> /dev/null || ! docker-compose ps db &> /dev/null 2>&1; then
    echo "ERROR: Docker containers not running"
    echo "Please start Docker: docker-compose up -d"
    exit 1
fi

# SQL to add missing columns
SQL_SCRIPT='
-- Add missing columns to organizations table
DO $$
BEGIN
    -- schema_version
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'schema_version'"'"') THEN
        ALTER TABLE organizations ADD COLUMN schema_version VARCHAR(128);
        RAISE NOTICE '"'"'Added column: schema_version'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: schema_version'"'"';
    END IF;

    -- schema_version_name
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'schema_version_name'"'"') THEN
        ALTER TABLE organizations ADD COLUMN schema_version_name VARCHAR(100);
        RAISE NOTICE '"'"'Added column: schema_version_name'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: schema_version_name'"'"';
    END IF;

    -- last_schema_sync
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'last_schema_sync'"'"') THEN
        ALTER TABLE organizations ADD COLUMN last_schema_sync TIMESTAMPTZ;
        RAISE NOTICE '"'"'Added column: last_schema_sync'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: last_schema_sync'"'"';
    END IF;

    -- schema_sync_status
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'schema_sync_status'"'"') THEN
        ALTER TABLE organizations ADD COLUMN schema_sync_status VARCHAR(50) DEFAULT '"'"'unknown'"'"';
        RAISE NOTICE '"'"'Added column: schema_sync_status'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: schema_sync_status'"'"';
    END IF;

    -- schema_sync_error
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'schema_sync_error'"'"') THEN
        ALTER TABLE organizations ADD COLUMN schema_sync_error TEXT;
        RAISE NOTICE '"'"'Added column: schema_sync_error'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: schema_sync_error'"'"';
    END IF;

    -- database_schema
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'database_schema'"'"') THEN
        ALTER TABLE organizations ADD COLUMN database_schema VARCHAR(255) DEFAULT '"'"'public'"'"';
        RAISE NOTICE '"'"'Added column: database_schema'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: database_schema'"'"';
    END IF;

    -- last_scan_at
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'last_scan_at'"'"') THEN
        ALTER TABLE organizations ADD COLUMN last_scan_at TIMESTAMPTZ;
        RAISE NOTICE '"'"'Added column: last_scan_at'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: last_scan_at'"'"';
    END IF;

    -- scan_status
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'scan_status'"'"') THEN
        ALTER TABLE organizations ADD COLUMN scan_status VARCHAR(50) DEFAULT '"'"'idle'"'"';
        RAISE NOTICE '"'"'Added column: scan_status'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: scan_status'"'"';
    END IF;

    -- scan_progress
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'scan_progress'"'"') THEN
        ALTER TABLE organizations ADD COLUMN scan_progress INTEGER DEFAULT 0;
        RAISE NOTICE '"'"'Added column: scan_progress'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: scan_progress'"'"';
    END IF;

    -- current_scan_id
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'current_scan_id'"'"') THEN
        ALTER TABLE organizations ADD COLUMN current_scan_id UUID;
        RAISE NOTICE '"'"'Added column: current_scan_id'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: current_scan_id'"'"';
    END IF;

    -- total_scans
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'total_scans'"'"') THEN
        ALTER TABLE organizations ADD COLUMN total_scans INTEGER DEFAULT 0;
        RAISE NOTICE '"'"'Added column: total_scans'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: total_scans'"'"';
    END IF;

    -- total_repos
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'total_repos'"'"') THEN
        ALTER TABLE organizations ADD COLUMN total_repos INTEGER DEFAULT 0;
        RAISE NOTICE '"'"'Added column: total_repos'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: total_repos'"'"';
    END IF;

    -- total_findings
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'total_findings'"'"') THEN
        ALTER TABLE organizations ADD COLUMN total_findings INTEGER DEFAULT 0;
        RAISE NOTICE '"'"'Added column: total_findings'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: total_findings'"'"';
    END IF;

    -- description
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'description'"'"') THEN
        ALTER TABLE organizations ADD COLUMN description TEXT;
        RAISE NOTICE '"'"'Added column: description'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: description'"'"';
    END IF;

    -- settings
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'settings'"'"') THEN
        ALTER TABLE organizations ADD COLUMN settings JSONB DEFAULT '"'"'{}'"'"';
        RAISE NOTICE '"'"'Added column: settings'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: settings'"'"';
    END IF;

    -- created_by
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='"'"'organizations'"'"' AND column_name='"'"'created_by'"'"') THEN
        ALTER TABLE organizations ADD COLUMN created_by UUID;
        RAISE NOTICE '"'"'Added column: created_by'"'"';
    ELSE
        RAISE NOTICE '"'"'Column already exists: created_by'"'"';
    END IF;
END $$;
'

# Fix security_portal database (used by API)
echo "Fixing security_portal database (used by API)..."
echo "$SQL_SCRIPT" | docker-compose exec -T db psql -U postgres -d security_portal

echo ""
echo "Fixing auditgh_kb database (used by scanner)..."
echo "$SQL_SCRIPT" | docker-compose exec -T db psql -U postgres -d auditgh_kb

echo ""
echo "✓ Both databases updated successfully!"
echo ""
echo "Now you can:"
echo "  1. Add sleepnumber org: ./add-org.sh --import-repos"
echo "  2. Run scanner: docker-compose run --rm scanner --target sleepnumber --dry-run"
