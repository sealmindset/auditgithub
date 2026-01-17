# Rescan Scheduler

## What This Is

An AI-powered intelligent scanning scheduler for AuditGH that automatically determines optimal rescan timing based on full context analysis: commit patterns, finding history, file types changed, contributor activity, and risk scores. Features a beautiful calendar-based UI for visualizing and managing scan schedules across all repositories in an organization.

## Core Value

Smart AI scheduling that automatically adapts scan frequency to repository activity patterns — high-activity repos get scanned more often, dormant repos less often, all without manual configuration.

## Requirements

### Validated

- ✓ Repository scanning infrastructure — existing (`scan_repos.py`, `execution/` scripts)
- ✓ Organization/repo management — existing (`src/api/routers/organizations.py`, `repositories.py`)
- ✓ GitHub API integration for commit data — existing (`src/github/api.py`)
- ✓ Finding storage and history — existing (`src/api/models.py`)
- ✓ AI provider infrastructure — existing (`src/ai_agent/providers/`)
- ✓ React UI with Radix/Tailwind — existing (`src/web-ui/`)

### Active

- [ ] AI scheduling engine that analyzes commit patterns, finding history, file types, contributor activity, and risk scores
- [ ] Automatic schedule generation for all repos based on AI analysis
- [ ] Calendar view UI showing scheduled scans with day + time window granularity
- [ ] Drag-and-drop rescheduling on calendar
- [ ] Manual override capability with permanent lock (AI won't modify)
- [ ] Per-repo argument customization (`--target <org> --repo <repo> --overridescan` as defaults)
- [ ] New repo handling: immediate scan, then daily until patterns emerge
- [ ] Schedule persistence in database
- [ ] Backend API endpoints for schedule CRUD operations
- [ ] Multi-org support in scheduling (switch between orgs)
- [ ] Scan type customization per repo (which tools to run)

### Out of Scope

- Notifications/alerts when scans complete or fail — future enhancement, not v1
- Cross-org unified calendar view — v1 is per-org only
- Real-time scan progress in calendar — just shows scheduled vs completed

## Context

**Existing Infrastructure:**
- APScheduler already in `src/api/scheduler.py` for background jobs
- Scan execution via `scan_repos.py` with `--org`, `--repo` flags
- GitHub commit data accessible via `src/github/api.py`
- Finding history in PostgreSQL via SQLAlchemy models
- React 19 + Next.js 16 + Radix UI + Tailwind CSS 4 for frontend

**AI Analysis Inputs:**
- Commit frequency and timing patterns (when do commits typically happen?)
- Historical finding counts and severity trends
- File types being modified (security-sensitive files weight higher)
- Contributor activity patterns
- Current risk scores from existing scans

**Schedule Logic:**
- High activity repos (daily commits) → daily scans, timed after typical commit window
- Medium activity (weekly commits) → 2-3x/week scans
- Low activity (monthly or less) → weekly scans
- Dormant repos (no commits in 30+ days) → bi-weekly or monthly scans

**UI/UX:**
- Calendar view as primary interface
- Day + time window granularity (morning/afternoon/evening/night)
- Manual overrides are locked — AI won't touch them
- AI sets schedules automatically, no reasoning display needed

## Constraints

- **UI Framework**: Must use existing Radix UI + Tailwind CSS component patterns from `src/web-ui/components/ui/`
- **Calendar Library**: Select appropriate React calendar library that integrates well with Radix/Tailwind
- **Database**: Must store schedules in PostgreSQL with proper org/repo relationships
- **Execution**: Leverage existing `scan_repos.py` for actual scan execution

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Calendar view over table | User preference for visual scheduling interface | — Pending |
| Manual lock (no AI override) | User wants full control when they set overrides | — Pending |
| Day + time window granularity | Balance between precision and simplicity | — Pending |
| Full context AI analysis | More inputs = smarter scheduling decisions | — Pending |
| New repos default to daily | Conservative approach until patterns emerge | — Pending |
| No reasoning display | Keep UI clean, user trusts AI decisions | — Pending |

---
*Last updated: 2026-01-17 after initialization*
