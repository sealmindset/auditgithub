# Roadmap: Rescan Scheduler

## Overview

Build an AI-powered intelligent scanning scheduler that automatically determines optimal rescan timing based on commit patterns, finding history, file types, contributor activity, and risk scores. The journey progresses from database foundation through AI engine to a beautiful calendar-based UI with drag-and-drop rescheduling and manual override capabilities.

## Completed Milestones

- [v1.0 Rescan Scheduler](milestones/v1.0-ROADMAP.md) (Phases 1-10) — SHIPPED 2026-01-17

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

## Progress

| Milestone | Phases | Plans | Status | Completed |
|-----------|--------|-------|--------|-----------|
| v1.0 Rescan Scheduler | 1-10 | 10/10 | Complete | 2026-01-17 |
