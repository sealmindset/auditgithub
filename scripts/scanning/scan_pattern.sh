#!/bin/bash
# scan_pattern.sh - Scan repositories matching a SQL LIKE pattern
#
# Usage:
#   ./scan_pattern.sh <org_name> <pattern>
#
# Examples:
#   ./scan_pattern.sh SleepNumberInc "%-oic-%"     # Contains "oic"
#   ./scan_pattern.sh SleepNumberInc "cloud-%"      # Starts with "cloud-"
#   ./scan_pattern.sh SleepNumberInc "%-api"        # Ends with "-api"

ORG="${1:-SleepNumberInc}"
PATTERN="${2:-%}"

echo "================================================================================"
echo "Pattern-Based Repository Scanner"
echo "================================================================================"
echo "Organization: $ORG"
echo "Pattern:      $PATTERN"
echo "================================================================================"
echo ""

# Find matching repositories
echo "Finding repositories matching pattern..."
repos=$(docker exec auditgh_db psql -U postgres -d security_portal -t -c \
  "SELECT r.name FROM repositories r
   JOIN organizations o ON r.organization_id = o.id
   WHERE o.github_org = '$ORG'
   AND r.name LIKE '$PATTERN'
   ORDER BY r.name;")

# Count repositories
count=$(echo "$repos" | grep -v '^$' | wc -l | xargs)

if [ "$count" -eq 0 ]; then
  echo "No repositories found matching pattern: $PATTERN"
  echo ""
  echo "Examples of available repositories:"
  docker exec auditgh_db psql -U postgres -d security_portal -t -c \
    "SELECT r.name FROM repositories r
     JOIN organizations o ON r.organization_id = o.id
     WHERE o.github_org = '$ORG'
     ORDER BY r.name LIMIT 10;"
  exit 0
fi

echo "Found $count repositories"
echo ""

# List repositories that will be scanned
echo "Repositories to scan:"
echo "$repos" | head -20
if [ "$count" -gt 20 ]; then
  echo "... and $((count - 20)) more"
fi
echo ""

# Ask for confirmation
read -p "Scan all $count repositories? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Scan cancelled."
  exit 0
fi

echo ""
echo "================================================================================"
echo "Starting scan of $count repositories"
echo "================================================================================"
echo ""

# Scan each repository
i=0
echo "$repos" | while read -r repo; do
  repo=$(echo "$repo" | xargs)  # Trim whitespace
  [ -z "$repo" ] && continue

  i=$((i + 1))
  echo "================================================================================"
  echo "[$i/$count] Scanning: $repo"
  echo "================================================================================"
  docker-compose run --rm scanner --target "$ORG" --repo "$repo"
  echo ""
done

echo "================================================================================"
echo "Pattern scan complete! Scanned $count repositories."
echo "================================================================================"
