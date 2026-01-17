# Roadmap: Rescan Scheduler

## Overview

Build an AI-powered intelligent scanning scheduler that automatically determines optimal rescan timing based on commit patterns, finding history, file types, contributor activity, and risk scores. The journey progresses from database foundation through AI engine to a beautiful calendar-based UI with drag-and-drop rescheduling and manual override capabilities.

## Milestones

- [v1.0 Rescan Scheduler](milestones/v1.0-ROADMAP.md) (Phases 1-10) — SHIPPED 2026-01-17
- **v2.0 Dashboard Redesign** — Phases 11-18 (in progress)

## Domain Expertise

None

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

<details>
<summary>v1.0 Rescan Scheduler (Phases 1-10) — SHIPPED 2026-01-17</summary>

- [x] **Phase 1: Database Schema** - Schedule persistence models and migrations
- [x] **Phase 2: Schedule API** - Backend CRUD endpoints for schedules
- [x] **Phase 3: Commit Analysis Service** - GitHub commit pattern extraction
- [x] **Phase 4: AI Scheduling Engine** - Core AI logic for schedule recommendations
- [x] **Phase 5: Schedule Execution** - Integration with scan_repos.py and APScheduler
- [x] **Phase 6: Calendar UI Foundation** - Calendar library setup and basic view
- [x] **Phase 7: Calendar Interactions** - Drag-and-drop rescheduling
- [x] **Phase 8: Override Management** - Manual schedule locks and custom args
- [x] **Phase 9: Multi-Org Support** - Organization switching in scheduler
- [x] **Phase 10: Scan Type Customization** - Per-repo tool selection

</details>

### v2.0 Dashboard Redesign (In Progress)

**Milestone Goal:** Transform the AuditGH interface with a modern dashboard featuring data visualization, improved navigation, and better information architecture.

- [ ] **Phase 11: Dashboard Foundation** - New dashboard page layout with widget system
- [ ] **Phase 12: Security Overview Widget** - Security posture summary with severity charts
- [ ] **Phase 13: Scan Activity Widget** - Recent scan activity timeline with status
- [ ] **Phase 14: Repository Health Widget** - Repo health cards with risk indicators
- [ ] **Phase 15: Finding Trends Widget** - Finding trend charts over time
- [ ] **Phase 16: Quick Actions Panel** - Common actions panel (trigger scan, view reports)
- [ ] **Phase 17: Dashboard Customization** - Widget arrangement and user preferences
- [ ] **Phase 18: Navigation Redesign** - Improved sidebar navigation and breadcrumbs

## Phase Details

### Phase 11: Dashboard Foundation
**Goal**: Create new dashboard page layout with widget grid system
**Depends on**: v1.0 complete
**Research**: Unlikely (existing React/Radix patterns)
**Plans**: TBD

Plans:
- [ ] 11-01: TBD (run /gsd:plan-phase 11 to break down)

### Phase 12: Security Overview Widget
**Goal**: Build security posture summary showing severity distribution, open findings count, and trend indicators
**Depends on**: Phase 11
**Research**: Unlikely (existing data models)
**Plans**: TBD

Plans:
- [ ] 12-01: TBD

### Phase 13: Scan Activity Widget
**Goal**: Create recent scan activity timeline showing scan status, duration, and results
**Depends on**: Phase 11
**Research**: Unlikely (existing scan data)
**Plans**: TBD

Plans:
- [ ] 13-01: TBD

### Phase 14: Repository Health Widget
**Goal**: Build repository health cards showing risk scores, last scan, and finding counts per repo
**Depends on**: Phase 11
**Research**: Unlikely (existing repo/schedule data)
**Plans**: TBD

Plans:
- [ ] 14-01: TBD

### Phase 15: Finding Trends Widget
**Goal**: Create finding trend charts showing finding counts over time by severity
**Depends on**: Phase 11
**Research**: Likely (charting library selection)
**Research topics**: React charting libraries (recharts, visx, chart.js), time-series visualization patterns
**Plans**: TBD

Plans:
- [ ] 15-01: TBD

### Phase 16: Quick Actions Panel
**Goal**: Add quick actions panel for common tasks (trigger scan, view reports, jump to scheduler)
**Depends on**: Phase 11
**Research**: Unlikely (existing UI patterns)
**Plans**: TBD

Plans:
- [ ] 16-01: TBD

### Phase 17: Dashboard Customization
**Goal**: Allow users to arrange widgets, save layouts, and set preferences
**Depends on**: Phase 11-16
**Research**: Unlikely (localStorage/state patterns)
**Plans**: TBD

Plans:
- [ ] 17-01: TBD

### Phase 18: Navigation Redesign
**Goal**: Improve sidebar navigation with better hierarchy, breadcrumbs, and quick search
**Depends on**: Phase 11
**Research**: Unlikely (existing Radix patterns)
**Plans**: TBD

Plans:
- [ ] 18-01: TBD

## Progress

| Phase | Milestone | Plans | Status | Completed |
|-------|-----------|-------|--------|-----------|
| 1-10 | v1.0 | 10/10 | Complete | 2026-01-17 |
| 11. Dashboard Foundation | v2.0 | 0/? | Not started | - |
| 12. Security Overview Widget | v2.0 | 0/? | Not started | - |
| 13. Scan Activity Widget | v2.0 | 0/? | Not started | - |
| 14. Repository Health Widget | v2.0 | 0/? | Not started | - |
| 15. Finding Trends Widget | v2.0 | 0/? | Not started | - |
| 16. Quick Actions Panel | v2.0 | 0/? | Not started | - |
| 17. Dashboard Customization | v2.0 | 0/? | Not started | - |
| 18. Navigation Redesign | v2.0 | 0/? | Not started | - |
