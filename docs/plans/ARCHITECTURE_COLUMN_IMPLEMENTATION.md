# Architecture Column Implementation

**Date:** 2026-01-20
**Status:** ✅ Completed

---

## Overview

Added a new "Architecture" column to the Repositories table that displays "Yes" or "No" to indicate whether a repository has successfully generated architecture documentation (both diagram and report).

---

## Changes Made

### 1. Backend API Changes

**File:** `src/api/routers/projects.py`

Added logic to check if both `architecture_report` and `architecture_diagram` fields are present in the database:

```python
# Check if architecture report and diagram are both present
has_architecture = bool(p.architecture_report and p.architecture_diagram)

results.append({
    # ... other fields ...
    "has_architecture": has_architecture,
    # ... rest of fields ...
})
```

**Logic:**
- Returns `true` if BOTH `architecture_report` AND `architecture_diagram` are not null/empty
- Returns `false` if either field is missing or empty

**API Endpoint:** `GET /projects/`

**Sample Response:**
```json
{
  "id": "uuid-here",
  "name": "android-consumer-app",
  "has_architecture": true,
  "language": "Kotlin",
  "last_scanned_at": "2026-01-20T10:00:00Z",
  ...
}
```

### 2. Frontend UI Changes

**File:** `src/web-ui/app/repositories/page.tsx`

#### Added Icon Import
```typescript
import { Loader2, Clock, ScanSearch, Eye, EyeOff, Globe, Archive, FileText } from "lucide-react"
```

#### Added New Column Definition
```typescript
{
    accessorKey: "has_architecture",
    header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Architecture" />
    ),
    cell: ({ row }) => {
        const hasArchitecture = row.getValue("has_architecture") as boolean
        if (hasArchitecture) {
            return (
                <Badge className="bg-green-500 hover:bg-green-600">
                    <FileText className="h-3 w-3 mr-1" />
                    Yes
                </Badge>
            )
        } else {
            return (
                <Badge variant="secondary">
                    <FileText className="h-3 w-3 mr-1" />
                    No
                </Badge>
            )
        }
    },
    filterFn: (row, id, value) => {
        const hasArchitecture = row.getValue(id) as boolean
        return value.includes(hasArchitecture ? "yes" : "no")
    },
    sortingFn: (rowA, rowB) => {
        const a = rowA.getValue("has_architecture") as boolean
        const b = rowB.getValue("has_architecture") as boolean
        return (a === b) ? 0 : a ? -1 : 1
    }
}
```

**Features:**
- **Display:** Shows "Yes" (green badge) or "No" (gray badge) with FileText icon
- **Sortable:** Can sort by architecture status (Yes appears first)
- **Filterable:** Can filter repositories by architecture status

---

## Column Appearance

### Yes (Architecture Available)
```
┌──────────────┐
│ 📄 Yes       │  (Green badge)
└──────────────┘
```
Indicates that both the Architecture Diagram and Report are successfully generated and available at:
- `/projects/{id}` → Architecture tab → Diagram
- `/projects/{id}` → Architecture tab → Report

### No (Architecture Not Available)
```
┌──────────────┐
│ 📄 No        │  (Gray badge)
└──────────────┘
```
Indicates that either:
- The architecture report is missing/empty, OR
- The architecture diagram is missing/empty, OR
- Both are missing

---

## Database Schema

The column reads from existing database fields:

```sql
-- repositories table
architecture_report       TEXT  -- Architecture analysis report (markdown)
architecture_diagram      TEXT  -- Mermaid diagram code
architecture_preprocessed TEXT  -- Pre-processed architecture data
```

**Condition for "Yes":**
```sql
architecture_report IS NOT NULL
  AND architecture_report != ''
  AND architecture_diagram IS NOT NULL
  AND architecture_diagram != ''
```

---

## Testing

### API Test
```bash
# Check API returns has_architecture field
curl -s http://localhost:8000/projects/ | jq '.[0] | {name, has_architecture}'

# Find repositories with architecture
curl -s http://localhost:8000/projects/ | jq '.[] | select(.has_architecture == true) | {name, has_architecture}'

# Count repositories with architecture
curl -s http://localhost:8000/projects/ | jq '[.[] | select(.has_architecture == true)] | length'
```

**Expected Output:**
```json
{
  "name": "android-consumer-app",
  "has_architecture": true
}
{
  "name": "asrd-bam-tools",
  "has_architecture": true
}
```

### UI Test

1. Navigate to: http://localhost:3000/repositories
2. Verify new "Architecture" column appears
3. Verify badges display correctly:
   - Green "Yes" badge for repos with architecture
   - Gray "No" badge for repos without architecture
4. Test sorting by clicking column header
5. Test filtering (if available in data table)

---

## Sample Data

Based on database query, repositories with architecture:

```bash
docker exec auditgh_db psql -U postgres -d security_portal -c "
SELECT
    name,
    LENGTH(architecture_report) as report_len,
    LENGTH(architecture_diagram) as diagram_len
FROM repositories
WHERE architecture_report IS NOT NULL
  AND architecture_diagram IS NOT NULL
ORDER BY name
LIMIT 10;
"
```

**Results:**
- `android-consumer-app` - Yes (has both)
- `asrd-bam-tools` - Yes (has both)
- `grant-github-secrets` - Yes (has both)
- `snint-repidadj-apim` - Yes (has both)
- Many EBS-E-* repositories - Yes (has both)

---

## Column Position

The Architecture column appears in this order:

1. Name
2. Visibility
3. Last Commit
4. Last Scan
5. Open Findings
6. Severity
7. **Architecture** ← New column
8. (Future columns)

---

## Implementation Notes

### Why Check Both Fields?

The architecture generation process creates:
1. **Diagram:** Visual representation (Mermaid syntax)
2. **Report:** Textual analysis and insights

Both are required for a complete architecture documentation. If only one is present, the system considers it incomplete (shows "No").

### Performance

The check is performed at the API level during project list query:
- No additional database queries
- Simple boolean check on existing fields
- Minimal performance impact

### Future Enhancements

Possible improvements:
1. Add tooltip showing last architecture generation date
2. Link directly to architecture tab when clicking "Yes" badge
3. Add architecture generation button for "No" entries
4. Show architecture generation status (in progress, failed, etc.)

---

## Troubleshooting

### Column not appearing

1. **Check API restart:**
   ```bash
   docker-compose restart api
   ```

2. **Verify API response:**
   ```bash
   curl -s http://localhost:8000/projects/ | jq '.[0] | keys'
   # Should include "has_architecture"
   ```

3. **Check web UI refresh:**
   - Hard refresh browser (Cmd+Shift+R or Ctrl+Shift+R)
   - Check browser console for errors

### All showing "No"

1. **Check database data:**
   ```bash
   docker exec auditgh_db psql -U postgres -d security_portal -c "
   SELECT COUNT(*) FROM repositories
   WHERE architecture_report IS NOT NULL
     AND architecture_diagram IS NOT NULL;
   "
   ```

2. **Verify architecture generation:**
   - Check if architecture scanning is enabled
   - Review scan logs for architecture generation errors

### Badge colors wrong

The badge colors are defined in the component:
- **Yes:** `bg-green-500 hover:bg-green-600` (Green)
- **No:** `variant="secondary"` (Gray)

These can be customized in the component if needed.

---

## Files Modified

1. `/src/api/routers/projects.py` - Added `has_architecture` field to API response
2. `/src/web-ui/app/repositories/page.tsx` - Added Architecture column to table

---

## Summary

✅ **API Updated:** Returns `has_architecture` boolean field
✅ **UI Updated:** Displays Architecture column with Yes/No badges
✅ **Tested:** API returns correct values
✅ **Sortable:** Column can be sorted
✅ **Filterable:** Column can be filtered

The Architecture column is now live and visible on the Repositories page at http://localhost:3000/repositories.
