#!/bin/bash
# discover_repos.sh - Discover repositories from GitHub and add to database
# without running full security scans
#
# Usage:
#   ./discover_repos.sh <org_name>

ORG="${1:-SleepNumberInc}"

echo "================================================================================"
echo "Repository Discovery (No Security Scans)"
echo "================================================================================"
echo "Organization: $ORG"
echo ""
echo "This will query GitHub and add repositories to the database"
echo "WITHOUT running security scans. Use this to populate the database quickly."
echo "================================================================================"
echo ""

read -p "Discover all repositories for $ORG? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Discovery cancelled."
  exit 0
fi

echo ""
echo "Discovering repositories from GitHub..."

# Run scanner in discovery mode (minimal scan, just creates database entries)
docker-compose run --rm scanner --target "$ORG" --skip-scan

echo ""
echo "================================================================================"
echo "Discovery complete! Check database for new repositories:"
echo ""
echo "  docker exec auditgh_db psql -U postgres -d security_portal -c \\"
echo "    \"SELECT COUNT(*) FROM repositories r \\"
echo "     JOIN organizations o ON r.organization_id = o.id \\"
echo "     WHERE o.github_org = '$ORG';\""
echo "================================================================================"
