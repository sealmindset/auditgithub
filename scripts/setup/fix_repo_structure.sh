#!/bin/bash
# fix_repo_structure.sh - Move misplaced repositories under SleepNumberInc/

cd vulnerability_reports || exit 1

echo "================================================================================"
echo "Repository Structure Fix"
echo "================================================================================"
echo "Moving misplaced repositories under SleepNumberInc/"
echo ""

# Create SleepNumberInc directory if it doesn't exist
mkdir -p SleepNumberInc

moved=0
skipped=0

for dir in */; do
    dirname="${dir%/}"

    # Skip special directories and the target organization directory
    if [ "$dirname" = "SleepNumberInc" ] || [[ "$dirname" == _* ]] || [[ "$dirname" == .* ]]; then
        continue
    fi

    # Check if already exists in SleepNumberInc
    if [ -d "SleepNumberInc/$dirname" ]; then
        echo "  Skipping $dirname (already exists in SleepNumberInc/)"
        skipped=$((skipped + 1))
    else
        echo "  Moving $dirname -> SleepNumberInc/$dirname"
        mv "$dirname" "SleepNumberInc/"
        moved=$((moved + 1))
    fi
done

echo ""
echo "================================================================================"
echo "Summary"
echo "================================================================================"
echo "  Moved: $moved repositories"
echo "  Skipped: $skipped repositories (already in SleepNumberInc/)"
echo ""
echo "Next step: Re-run ingestion to load the reports"
echo "  docker exec auditgh_api python /app/ingest_reports.py"
echo "================================================================================"
