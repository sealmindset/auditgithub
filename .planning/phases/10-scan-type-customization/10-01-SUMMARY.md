---
phase: 10-scan-type-customization
plan: 01
subsystem: ui, api
tags: [scanners, security-tools, fastapi, react, radix-tabs]

# Dependency graph
requires:
  - phase: 08-override-management
    provides: ScheduleOverrideDialog with tabbed UI, lazy-load pattern
provides:
  - GET /schedules/scanners endpoint with categorized scanner list
  - Scanner selection tab in ScheduleOverrideDialog
  - Per-repo scanner configuration via scan_arguments
affects: [schedule-execution, scan-repos]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Scanner list API with Pydantic model
    - Collapsible category selection UI
    - Lazy-load data on tab activation

key-files:
  created: []
  modified:
    - src/api/routers/schedules.py
    - src/web-ui/components/ScheduleOverrideDialog.tsx
    - src/web-ui/components/SchedulerCalendar.tsx
    - src/web-ui/app/scheduler/page.tsx

key-decisions:
  - "Scanner categories based on scan_repos.py groupings (8 categories)"
  - "Empty scan_arguments.scanners means use all scanners (default)"
  - "Lazy-load scanner list on tab activation (consistent with history tab)"
  - "Separate Save Scanner Config from lock flow (scanner changes don't require lock)"

patterns-established:
  - "Collapsible category sections with Select All/Clear buttons"
  - "Use all toggle at top of selection UI"
  - "Custom badge indicator in Details tab"

issues-created: []

# Metrics
duration: 4min
completed: 2026-01-17
---

# Phase 10 Plan 01: Scan Type Customization Summary

**Per-repository scanner selection with categorized UI and API integration for customizing which security tools run during scheduled scans**

## Performance

- **Duration:** 4 min
- **Started:** 2026-01-17T17:53:00Z
- **Completed:** 2026-01-17T17:57:00Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- Added GET /schedules/scanners API endpoint returning all 26 scanners with metadata
- Created Scanners tab in ScheduleOverrideDialog with categorized checkbox UI
- Wired scanner selection to schedule updates via scan_arguments JSONB field
- Added custom scanner indicator in Details tab

## Task Commits

Each task was committed atomically:

1. **Task 1: Add GET /schedules/scanners endpoint** - `7512b59` (feat)
2. **Task 2: Add Scanners tab to override dialog** - `4963b73` (feat)
3. **Task 3: Wire scanner selection to schedule API** - `9d3d486` (feat)

## Files Created/Modified

- `src/api/routers/schedules.py` - Added ScannerInfo model, AVAILABLE_SCANNERS constant (26 scanners), GET /scanners endpoint
- `src/web-ui/components/ScheduleOverrideDialog.tsx` - Added 4th tab with scanner selection UI, lazy-load, category groupings
- `src/web-ui/components/SchedulerCalendar.tsx` - Added scan_arguments to Schedule interface, onUpdateScanners prop
- `src/web-ui/app/scheduler/page.tsx` - Added handleUpdateScanners callback with optimistic UI

## Decisions Made

- **Scanner categories**: Grouped into 8 categories matching scan infrastructure (secrets, sast, deps, iac, api, mobile, go, other)
- **Default behavior**: Empty scan_arguments.scanners = use all scanners (no storage needed for default)
- **Lazy loading**: Fetch scanner list only when Scanners tab activated (consistent with history tab pattern)
- **Separate save**: Scanner config saved independently from lock/unlock flow (can change scanners without locking)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added missing useMemo import**
- **Found during:** Build verification after Task 3
- **Issue:** ScheduleOverrideDialog used useMemo but didn't import it
- **Fix:** Added useMemo to React imports
- **Files modified:** src/web-ui/components/ScheduleOverrideDialog.tsx
- **Verification:** TypeScript check passes
- **Committed in:** 9d3d486 (amended into Task 3 commit)

---

**Total deviations:** 1 auto-fixed (blocking)
**Impact on plan:** Minor fix, no scope creep

## Issues Encountered

None - plan executed smoothly.

## Next Phase Readiness

- Scanner selection UI complete and functional
- Phase 10 complete - all deliverables implemented
- Milestone complete - all 10 phases finished

---
*Phase: 10-scan-type-customization*
*Completed: 2026-01-17*
