# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-17)

**Core value:** Smart AI scheduling that automatically adapts scan frequency to repository activity patterns — high-activity repos get scanned more often, dormant repos less often, all without manual configuration.
**Current focus:** Phase 10 — Scan Type Customization

## Current Position

Phase: 10 of 10 (Scan Type Customization)
Plan: 0 of TBD in current phase
Status: Ready for planning
Last activity: 2026-01-17 — Completed Phase 9

Progress: █████████░ 90%

## Performance Metrics

**Velocity:**
- Total plans completed: 9
- Average duration: 3.6 min
- Total execution time: 32 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1. Database Schema | 1 | 2 min | 2 min |
| 2. Schedule API | 1 | 3 min | 3 min |
| 3. Commit Analysis | 1 | 3 min | 3 min |
| 4. AI Scheduling Engine | 1 | 3 min | 3 min |
| 5. Schedule Execution | 1 | 3 min | 3 min |
| 6. Calendar UI Foundation | 1 | 5 min | 5 min |
| 7. Calendar Interactions | 1 | 5 min | 5 min |
| 8. Override Management | 1 | 5 min | 5 min |
| 9. Multi-Org Support | 1 | 3 min | 3 min |

**Recent Trend:**
- Last 5 plans: 3 min, 5 min, 5 min, 5 min, 3 min
- Trend: —

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Calendar view over table interface
- Manual lock (no AI override) for user overrides
- Day + time window granularity for scheduling
- Full context AI analysis (commits, findings, files, contributors, risk)
- New repos default to daily scans until patterns emerge
- One schedule per repository via unique constraint (Phase 1)
- Time windows as strings for user-friendliness (Phase 1)
- Enum validation for frequency/time_window matching DB constraints (Phase 2)
- All mutations create ScheduleOverride audit records (Phase 2)
- 90-day lookback window for commit analysis (Phase 3)
- Frequency thresholds: 7+/week=daily, 2-7=weekly, 0.5-2=bi-weekly, <0.5=monthly (Phase 3)
- Dormant repos cache for 7 days vs 24h for active repos (Phase 3)
- Heuristic escalation: critical/high findings or risk >= 0.7 → weekly minimum (Phase 4)
- Batch processing size of 5 repos with 1s delay for rate limiting (Phase 4)
- Confidence levels: AI=variable, Heuristics=0.6, New repo=0.7 (Phase 4)
- Time window hours: morning=8, afternoon=14, evening=20, night=2 (Phase 5)
- Bi-weekly via weekly cron + 10-day skip logic (Phase 5)
- 2-hour per-repo scan timeout (Phase 5)
- Hourly schedule sync from database (Phase 5)
- react-big-calendar over FullCalendar: MIT license, lighter weight (Phase 6)
- date-fns for calendar localization: tree-shakeable, ESM (Phase 6)
- 2-hour event duration for visual scan window representation (Phase 6)
- Frequency unchanged on drag, only date/time changes (Phase 7)
- Mandatory time window selection after every drop (Phase 7)
- Optimistic UI updates with rollback on error (Phase 7)
- Tabbed interface for details/lock/history in override dialog (Phase 8)
- Lazy-load history on tab select to avoid unnecessary API calls (Phase 8)
- Single-button unlock (no separate confirmation dialog) (Phase 8)
- Leverage existing OrganizationSelector page-reload pattern (Phase 9)
- Session-based org context via tenant middleware (Phase 9)
- Client-side stats from fetched schedules via useMemo (Phase 9)

### Deferred Issues

None yet.

### Pending Todos

None yet.

### Blockers/Concerns

None yet.

## Session Continuity

Last session: 2026-01-17
Stopped at: Completed Phase 9 (ready for Phase 10 planning)
Resume file: None
