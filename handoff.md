# Handoff -- AuditGH (AuditBoard filing: issue grouping + cross-scanner rule equivalence)

_Written 2026-09-17 12:12 by /clear-it. Read this file in full before continuing work._

**Note on scope.** The previous handoff (now the top entry in `.handoff-history.md`) covered the
**Report Generator Wizard, P1 + P2**. That workstream was not touched this session; its open items
are carried in section 6 and its still-binding dead ends in section 5 marked `(carried forward)`.
This session was a different workstream on the same branch.

---

## 1. Goal

Make one AuditBoard issue mean one defect. Rob's principle, verbatim from the session that set it:
*"same findings, across multiple projects in the same org ... should be grouped per project. Within
the project list out the unique location of the findings within the project ... So we have only one
issue according to the finding, and where the findings are found in the project."*

Rob's eight binding decisions: identity is `(scanner_name, rule_id)` plus an AI layer for
cross-scanner equivalence; escalate above 10 projects; Critical + High + Medium only; never bulk --
one press, one issue; AI verdicts at rule-pair level and cached; on AI failure or low confidence
keep scanners separate; a review queue where unreviewed pairs are inert; merged severity is the
highest of the members.

Acceptance: no issue claims coverage it cannot demonstrate; every failure path resolves to "not
merged", because AuditBoard issues cannot be deleted and descriptions cannot be edited after create.

## 2. Current State

- Branch `deployment-topology-p1-p2`. **Nothing in this workstream is committed.**
- **Built and tested.** 36 new tests in `tests/test_rule_equivalence.py` pass; `test_finding_groups.py`
  (39) and `test_issue_redaction.py` (20) pass. Full suite 528 pass / 82 collection errors, all
  pre-existing (55 SQLite `visit_JSONB`/`visit_ARRAY`, 27 `fixture 'db_session' not found`).
- **Live locally, as of this session.** The `api` container was running a process started
  2026-09-16 15:15:19 UTC, while the new router was written 17:58:58 the same day; `uvicorn` runs
  with **no `--reload`**, so the endpoints were on disk but not served. Restarted 2026-09-17
  16:48 UTC; healthy, clean startup, no traceback. `include_router` runs at import, so a clean
  startup means the router mounted.
- **Not verified through the live socket, and cannot be.** Every path needs a session cookie, and
  the auth middleware returns 401 before routing, so 401 carries no routing information. The
  outstanding check is Rob, signed in, opening `http://localhost:3001/rule-merges`.
- **Not deployed anywhere.** Local Docker Compose only (`auditgh_api`, `auditgh_web-ui`). The api
  host port changes on restart -- currently **54198**. web-ui on **3001**.
- `web-ui` runs `next dev` with the repo bind-mounted, so `/rule-merges` and the sidebar entry were
  live from the moment they were written and needed no restart.
- **Measured state:** 767,974 findings, 100% carrying `rule_id`, `cve_id` 0%. 2,638 distinct
  defects; 2,397 fileable at the severity floor; 241 of those span more than 10 projects.
  **478** candidate rule pairs at the floor / **834** all severities; **475 unchecked**. 3 proposals
  recorded, all `pending`, all `distinct`. **0 approved merges in force.** 5 issues filed
  (I#1716--I#1720).
- Three report documents written and consistent with one measurement run:
  `docs/GRC_Filing_Grouping_Status_Briefing.md`, `..._Technical.md`, and the generated
  `..._Appendix.md`. All three untracked.

## 3. Active Files

- `src/api/services/rule_equivalence.py` -- new, 746 lines. Blocking query, prompt, verdict parsing,
  `MIN_CONFIDENCE = 0.80`, persistence, review.
- `src/api/routers/rule_equivalences.py` -- new, 509 lines. Five paths, six operations. Reuses
  `findings:read` / `findings:write`.
- `src/api/services/finding_groups.py` -- identity, tiers, path normalization, union-find
  equivalence map, filing-match conditions.
- `src/api/services/issue_redaction.py` -- withholds secret-scanner `code_snippet` before any
  AuditBoard write.
- `src/api/routers/findings.py` -- `/findings/{id}/group`, `/auditboard-issue`,
  `/auditboard-filings`, delete dry-run. Also carries unrelated earlier work; +1087 lines total.
- `src/api/main.py` -- router import and `include_router(rule_equivalences.router)` at line 269.
- `src/web-ui/app/rule-merges/page.tsx` -- new, 556 lines, the review queue.
- `src/web-ui/components/app-sidebar.tsx` -- "Rule Merges" nav item under AI Management.
- `scripts/generate_grouping_appendix.py` -- new. Read-only; generates the names appendix and prints
  the figures so both documents quote one run.
- `migrations/022_rule_equivalences.sql`, `migrations/023_auditboard_group_key.sql` -- untracked.
- `tests/test_rule_equivalence.py` -- new, 36 tests.
- `.scratch/equivalence_*.py` -- four read-only probes, including the rollback-only proof that an
  approved merge changes grouping and a pending one does not.

## 4. Changes Made

**All uncommitted.**

- Grouping key moved from `(scanner_name, file_path)` to `(scanner_name, rule_id)`; tiers
  `specific` / `project` / `org`; `global` retired to readable-only `LEGACY_GLOBAL`.
- Cross-scanner equivalence service, review-queue router, and review UI, with every AI failure mode
  (timeout, provider exception, unparseable JSON, unknown verdict) collapsing to "no answer" --
  nothing recorded, pair stays a candidate.
- Secret redaction on both sides (`issue_redaction.py` server-side, `lib/finding-issue.ts` in the
  browser); server copy is the one that holds against a stale tab.
- Three report documents written together from one measurement run, plus a generated appendix.
- `api` container restarted so the running process serves the new routes.
- Report corrections applied this session: `Status_Technical.md` §3.2 rewritten to remove the
  invalid 401-based registration claim and to state the deployment limit (new §3.2.1); the briefing
  gained a "We are not claiming this is deployed" paragraph in its own vocabulary.

## 5. Failed Approaches -- DO NOT RETRY

**From this session:**

- **Treating `401` as proof a route is registered.** The auth middleware
  (`src/api/middleware/auth.py:50`) runs before routing and, with `AUTH_REQUIRED=true`, returns 401
  for every non-public path. Control: `/definitely-not-a-route-xyz` returned 401 too. Conclusion:
  status code carries **zero** routing information here. This claim had already been written into a
  report before it was tested.
- **`/api/openapi.json`.** It is in the middleware's public prefix list but the app never serves it
  there -- returns 404. The real path is `/openapi.json`, which is **not** public, so it 401s. There
  is therefore **no unauthenticated way to enumerate routes on the live process**. Stop looking.
- **`.pyc` access time as evidence the running process imported a module.** The bind mount does not
  maintain atime; it read stale. Inconclusive in both directions -- do not cite it either way.
- **Iterating `app.routes` to find router paths.** Reported "41 routes, no matches". This FastAPI
  version defers included routers behind `class _IncludedRouter(BaseRoute)`
  (`fastapi/routing.py:1586`), so router paths are invisible at the top level. Use
  `app.openapi()['paths']`.
- **Assuming a `docker compose restart` is unnecessary because `/app` is bind-mounted.** The mount
  makes files visible; it does not reload a running process. `uvicorn` has no `--reload`. Any API
  change is dead until the container restarts. (This also fired in the previous session -- it has
  now cost time twice.)
- **`settings.filing_severities`.** Does not exist. The accessor is `settings.filing_severities_list`
  (`src/api/config.py:93`).
- **Quoting a candidate-pair count without its denominator.** 478 and 834 are both correct: 478 is
  Critical/High/Medium and actionable-only, 834 is all severities, 464 is the floor plus a
  >= 2-shared-locations requirement. A bare "478" read as a contradiction of a bare "834".
- **"1,287 advisories" for the `package-lock.json` group.** Wrong. grype at exactly
  `/package-lock.json` is 386 distinct rules across 11,517 findings in 110 projects; the file-*name*
  view is 480 / 18,269 / 137. Two different questions, two different numbers, both now generated
  rather than typed.
- **Combined multi-field `PUT` to AuditBoard.** Refused with
  `ModelActionPermissionDenied (Permission: issue:action.editDraft)`. Write permissions there are
  **per field, not per record**: single-field PUTs succeed for `custom_text4` and the four user
  stamps. Issues cannot be deleted at all; descriptions cannot be edited after create;
  `identified_date` is settable only at create.
- **Filing to the obvious AuditBoard endpoint.** Issues, IT Risk Issues and IT Risk Exceptions are
  three different APIs with near-identical URLs. The first attempt landed in **IT Risk Exception**.
  The target is **IT Risk Issues**.
- **Reading the harness environment line "Is a git repository: false".** It is wrong;
  `git rev-parse --is-inside-work-tree` returns `true`.
- **Comparing a test-error count against a remembered baseline.** 82 errors looked like a regression
  against a recalled 41. All 82 are pre-existing and none touch this code. Re-measure the baseline
  on the same command before calling anything a regression.

**Carried forward -- still binding:**

- **(carried forward) `docker exec auditgh_postgres`** -- no such container. It is **`auditgh_db`**.
- **(carried forward) Running tests on the host.** Host Python has a pydantic / pydantic-core
  mismatch (`installed pydantic-core 2.46.4 ... requires 2.41.5`). Everything runs in `auditgh_api`.
- **(carried forward) Assuming Alembic governs the live schema.** `security_portal` has no
  `alembic_version` table; schema comes from `create_all()` at `src/api/main.py:243`, which adds
  missing tables but never missing columns. Verify with `information_schema.columns`.
- **(carried forward) `findings.id` vs `findings.finding_uuid`** are independent columns; 0 of
  769,825 rows have them equal. Read endpoints publish `finding_uuid`.
- **(carried forward) `findings.cwe_id` holds no real CWEs** -- only empty (710,126) and the literal
  `HorusecEngine` (59,699).
- **(carried forward) Believing a count published in an earlier message.** Take every figure from a
  query in the same message that publishes it. This has now fired in three consecutive sessions.
- **(carried forward) `docker compose restart web-ui` to pick up a change.** The `web-ui-next` named
  volume persists; wipe `.next` entirely.
- **(carried forward) Believing a zero-result grep.** Prove any zero with a single-file positive
  control.
- **(carried forward) Asking two AskUserQuestion questions at once.** One question, fewer options.
- **(carried forward) `npx playwright install chromium --with-deps` on macOS** -- Linux-only, hangs.
  Browser verification still not possible in this environment.

## 6. Next Steps

1. **Rob, signed in, opens `http://localhost:3001/rule-merges`.** Free, ~30 seconds, and it is the
   only remaining way to exercise `/rule-equivalences/stats` and `/candidates` against the live
   process. Closes the one acknowledged gap in the technical report.
2. **Decide the AI spend: 475 pairs, 475 short provider calls.** Estimated a few dollars, not
   measured. `POST /rule-equivalences/propose`, `limit` up to 100 per call, concurrency capped at 8.
   Nothing degrades if it is never run -- unchecked pairs stay separate.
3. **Rotate `<redacted - see AuditBoard I#1716>`.** Live Google API key, present in git
   history, in shipped APKs, and in plaintext in the body of AuditBoard issue **I#1716**, which
   cannot be edited. Needs Google Cloud console access.
4. **Rotate the GRC bearer token exposed by `NEXT_PUBLIC_AUDITBOARD_TOKEN`** at
   `frontend/app/(auth)/assessments/[id]/page.tsx:169-170` in the **sec-diligence** repo -- it ships
   to every browser. Rotation is the fix; deleting the line alone is not. Also still open there:
   `SEVERITY_MAP = {1:"low",2:"medium",3:"high",4:"critical"}` applied to `issue_rating_id` in
   `backend/app/services/auditboard.py` imports wrong severities.
5. **AuditBoard housekeeping**, all needing rights the API does not grant here: close **I#1717**
   (its findings were deleted; it now covers 0), add the supersede reason to **I#1715**, delete the
   **I#1714 `[TEST]`** record, and decide whether to hand-enter `identified_date` on
   I#1716--I#1719.
6. **Commit.** Nothing on this branch is committed across two workstreams. The AuditBoard/grouping
   changes and the P1/P2 taxonomy/KB changes are separate work in the same working tree -- read
   before including. Untracked agent-tool directories (`.agent/`, `.codex/`, `.cursor/`, `.kiro/`,
   `.scratch/`, and a dozen more) should be gitignored, not committed.
7. **Still open from the Report Generator Wizard workstream** (previous handoff, full detail in
   `.handoff-history.md`): the KB approval workflow -- all 2,639 entries are `draft`, no endpoint
   approves one, and this **blocks P4 outright**; architecture-report backfill over 703 repos;
   authoring the top KB entries in impact order; deciding where per-finding AI output lives; the
   Horusec ingest defect writing `HorusecEngine` into `cwe_id`.
8. **Still open from the npm supply-chain hunt:** decide the anti-remediation vector's shape.

**No further AuditBoard writes without explicit confirmation.** The earlier "Go" authorized the
I#1716--I#1719 backfill and the single create that became I#1720. It does not extend past that. No
AuditBoard writes were made in this session.
