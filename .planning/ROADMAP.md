# Roadmap: Rescan Scheduler

## Overview

Build an AI-powered intelligent scanning scheduler that automatically determines optimal rescan timing based on commit patterns, finding history, file types, contributor activity, and risk scores. The journey progresses from database foundation through AI engine to a beautiful calendar-based UI with drag-and-drop rescheduling and manual override capabilities.

## Domain Expertise

None

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Database Schema** - Schedule persistence models and migrations ✓
- [x] **Phase 2: Schedule API** - Backend CRUD endpoints for schedules ✓
- [x] **Phase 3: Commit Analysis Service** - GitHub commit pattern extraction ✓
- [x] **Phase 4: AI Scheduling Engine** - Core AI logic for schedule recommendations ✓
- [x] **Phase 5: Schedule Execution** - Integration with scan_repos.py and APScheduler ✓
- [x] **Phase 6: Calendar UI Foundation** - Calendar library setup and basic view ✓
- [ ] **Phase 7: Calendar Interactions** - Drag-and-drop rescheduling
- [ ] **Phase 8: Override Management** - Manual schedule locks and custom args
- [ ] **Phase 9: Multi-Org Support** - Organization switching in scheduler
- [ ] **Phase 10: Scan Type Customization** - Per-repo tool selection

## Phase Details

### Phase 1: Database Schema ✓
**Goal**: Create SQLAlchemy models for scan schedules with org/repo relationships
**Depends on**: Nothing (first phase)
**Research**: Unlikely (existing SQLAlchemy patterns in codebase)
**Plans**: 1/1 complete
**Completed**: 2026-01-17

Key deliverables:
- ScanSchedule model with schedule_type, frequency, time_window, next_run
- ScheduleOverride model for manual locks
- Alembic migration
- Foreign keys to organizations and repositories tables

### Phase 2: Schedule API ✓
**Goal**: Backend REST endpoints for schedule CRUD operations
**Depends on**: Phase 1
**Research**: Unlikely (existing FastAPI router patterns)
**Plans**: 1/1 complete
**Completed**: 2026-01-17

Key deliverables:
- GET /schedules - list all schedules for org
- GET /schedules/{repo_id} - get schedule for specific repo
- PUT /schedules/{repo_id} - update schedule
- POST /schedules/{repo_id}/lock - lock schedule from AI
- DELETE /schedules/{repo_id}/lock - unlock schedule for AI
- GET /schedules/{repo_id}/history - override audit history

### Phase 3: Commit Analysis Service ✓
**Goal**: Extract commit patterns from GitHub for scheduling decisions
**Depends on**: Phase 1
**Research**: Likely (GitHub API for commit history, file types)
**Plans**: 1/1 complete
**Completed**: 2026-01-17

Key deliverables:
- CommitAnalyzer class that fetches commit history
- Pattern extraction: frequency, typical timing, file types modified
- Contributor activity analysis
- Caching to avoid repeated API calls

### Phase 4: AI Scheduling Engine ✓
**Goal**: AI-powered schedule recommendation based on full context analysis
**Depends on**: Phase 3
**Research**: Likely (AI provider integration, scheduling algorithm design)
**Research topics**: Prompt engineering for schedule analysis, existing AI agent patterns
**Plans**: 1/1 complete
**Completed**: 2026-01-17

Key deliverables:
- ScheduleRecommender class using AI providers
- Input aggregation: commits, findings, risk scores, file types
- Schedule frequency determination (daily/weekly/bi-weekly/monthly)
- Time window recommendation based on commit patterns
- Batch processing for initial schedule generation

### Phase 5: Schedule Execution ✓
**Goal**: Integrate schedules with APScheduler and scan_repos.py
**Depends on**: Phase 2, Phase 4
**Research**: Unlikely (existing APScheduler in src/api/scheduler.py)
**Plans**: 1/1 complete
**Completed**: 2026-01-17

Key deliverables:
- APScheduler job registration for each schedule
- scan_repos.py invocation with correct arguments
- Schedule status updates (last_run, next_run)
- New repo detection and immediate scan trigger

### Phase 6: Calendar UI Foundation ✓
**Goal**: Calendar component with basic schedule visualization
**Depends on**: Phase 2
**Research**: Complete - selected react-big-calendar (MIT license, lightweight, native React)
**Plans**: 1/1 complete
**Completed**: 2026-01-17

Key deliverables:
- Calendar library integration
- Monthly/weekly view switching
- Schedule events rendered on calendar
- Time window visualization (morning/afternoon/evening/night)
- Styling to match existing UI patterns

### Phase 7: Calendar Interactions
**Goal**: Drag-and-drop rescheduling on calendar
**Depends on**: Phase 6
**Research**: Unlikely (calendar library drag-drop features)
**Plans**: 1/1 created

Key deliverables:
- Event drag-and-drop support
- Date change API integration
- Time window selection on drop
- Optimistic UI updates
- Error handling and rollback

### Phase 8: Override Management
**Goal**: Manual schedule locks and custom scan arguments
**Depends on**: Phase 7
**Research**: Unlikely (CRUD operations with existing patterns)
**Plans**: TBD

Key deliverables:
- Override modal/dialog UI
- Lock indicator on calendar events
- Custom argument editor (--target, --repo, --overridescan defaults)
- Override removal with confirmation
- Visual distinction between AI and manual schedules

### Phase 9: Multi-Org Support
**Goal**: Organization switching in scheduler UI
**Depends on**: Phase 8
**Research**: Unlikely (existing org context patterns)
**Plans**: TBD

Key deliverables:
- Org selector integration with scheduler page
- Schedule data filtering by org
- Context persistence across navigation
- Org-specific schedule statistics

### Phase 10: Scan Type Customization
**Goal**: Per-repo tool selection for scans
**Depends on**: Phase 8
**Research**: Unlikely (configuration UI patterns)
**Plans**: TBD

Key deliverables:
- Tool selection UI in override modal
- Available tools enumeration from scan infrastructure
- Tool configuration persistence
- Default vs custom tool set indicator

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Database Schema | 1/1 | Complete ✓ | 2026-01-17 |
| 2. Schedule API | 1/1 | Complete ✓ | 2026-01-17 |
| 3. Commit Analysis | 1/1 | Complete ✓ | 2026-01-17 |
| 4. AI Scheduling Engine | 1/1 | Complete ✓ | 2026-01-17 |
| 5. Schedule Execution | 1/1 | Complete ✓ | 2026-01-17 |
| 6. Calendar UI Foundation | 1/1 | Complete ✓ | 2026-01-17 |
| 7. Calendar Interactions | 0/1 | Plan ready | - |
| 8. Override Management | 0/TBD | Not started | - |
| 9. Multi-Org Support | 0/TBD | Not started | - |
| 10. Scan Type Customization | 0/TBD | Not started | - |
