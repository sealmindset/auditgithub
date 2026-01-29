#!/bin/bash
# rescan_pattern.sh - Force rescan repositories matching a pattern
#
# This script:
# 1. Finds repos matching pattern in DATABASE
# 2. Runs scanner with --overridescan (forces fresh clone)
# 3. Auto-ingests results into database
#
# Usage:
#   ./rescan_pattern.sh <org_name> <pattern>
#   ./rescan_pattern.sh SleepNumberInc "%-OIC-%"

ORG="${1:-SleepNumberInc}"
PATTERN="${2:-%}"

echo "================================================================================"
echo "Pattern-Based Repository Rescan (with --overridescan)"
echo "================================================================================"
echo "Organization: $ORG"
echo "Pattern:      $PATTERN (case-insensitive)"
echo "================================================================================"
echo ""

# Find matching repositories from database (case-insensitive)
echo "Finding repositories matching pattern in database..."
repos=$(docker exec auditgh_db psql -U postgres -d security_portal -t -c \
  "SELECT r.name FROM repositories r
   JOIN organizations o ON r.organization_id = o.id
   WHERE o.github_org = '$ORG'
   AND r.name ILIKE '$PATTERN'
   ORDER BY r.name;")

# Count repositories
count=$(echo "$repos" | grep -v '^$' | wc -l | xargs)

if [ "$count" -eq 0 ]; then
  echo "No repositories found matching pattern: $PATTERN"
  echo ""
  echo "First 10 available repositories in database:"
  docker exec auditgh_db psql -U postgres -d security_portal -t -c \
    "SELECT r.name FROM repositories r
     JOIN organizations o ON r.organization_id = o.id
     WHERE o.github_org = '$ORG'
     ORDER BY r.name LIMIT 10;"
  echo ""
  echo "Tip: Use ILIKE pattern syntax:"
  echo "  %-OIC-%    = contains 'OIC' (case-insensitive)"
  echo "  %EBS%      = contains 'EBS'"
  echo "  cloud-%    = starts with 'cloud-'"
  echo "  %-api      = ends with '-api'"
  exit 0
fi

echo "Found $count repositories matching pattern"
echo ""

# List repositories that will be scanned
echo "Repositories to rescan:"
echo "$repos" | head -20
if [ "$count" -gt 20 ]; then
  echo "... and $((count - 20)) more"
fi
echo ""

# Ask for confirmation
read -p "Rescan all $count repositories with --overridescan? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Rescan cancelled."
  exit 0
fi

echo ""
echo "================================================================================"
echo "Starting rescan of $count repositories (with --overridescan)"
echo "================================================================================"
echo ""

# Scan each repository with --overridescan
i=0
total=$count
echo "$repos" | while read -r repo; do
  repo=$(echo "$repo" | xargs)  # Trim whitespace
  [ -z "$repo" ] && continue

  i=$((i + 1))
  echo "================================================================================"
  echo "[$i/$total] Rescanning: $repo (forcing fresh clone)"
  echo "================================================================================"
  
  # Run scanner with --overridescan flag
  docker-compose run --rm scanner --target "$ORG" --repo "$repo" --overridescan
  
  echo ""
done

echo "================================================================================"
echo "Pattern rescan complete! Rescanned $count repositories."
echo "Data automatically ingested into database."
echo "================================================================================"
