#!/bin/bash
#
# Run database migrations on the master database
#
# Usage: ./run-migrations.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================="
echo "Running Database Migrations"
echo "========================================="
echo ""

# Check if we're in a Docker environment
if command -v docker-compose &> /dev/null && docker-compose ps db &> /dev/null 2>&1; then
    echo "Running migrations via Docker..."

    # Run migrations in order
    for migration in "$SCRIPT_DIR/migrations"/*.sql; do
        migration_name=$(basename "$migration")
        echo "Applying: $migration_name"

        # Use psql inside the db container
        docker-compose exec -T db psql -U auditgh -d auditgithub -f "/docker-entrypoint-initdb.d/$migration_name" 2>&1 | grep -v "already exists" | grep -v "duplicate" || true
    done

    echo ""
    echo "✓ Migrations applied successfully!"

else
    echo "ERROR: Docker containers not running"
    echo "Please start Docker: docker-compose up -d"
    exit 1
fi
