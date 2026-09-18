# Handoff -- AuditGH (selection actions + real exception-rule generators; AuditBoard TPRM probe)

_Written 2026-09-17 15:43 by /clear-it. Read this file in full before continuing work._

**Note on scope.** Three prior workstreams sit on this same branch and were **not** touched this
session: the AuditBoard grouping / cross-scanner rule-equivalence work (previous handoff, now the
top entry in `.handoff-history.md`), the Report Generator Wizard P1+P2 work, and the npm
supply-chain hunt. Their open items are carried in section 6 and their still-binding dead ends in
section 5 marked `(carried forward)`.

This session did two things: finished the **multi-select actions** on the All Findings table
(checkbox column, Create Exception / Report to AuditBoard over a selection), and then -- after Rob
hit a bug and pasted a useless generated "rule" -- replaced the **exception-rule generator** with
real, scanner-specific ones. Separately, it answered a question about **AuditBoard Third Party Risk
API access** (answer: no route exists on the token we hold).

---

## 1. Goal

Two goals, both now met to the point where the next move is Rob's.

**Selection actions.** Tick rows in the All Findings table -- individual findings or groups -- and
act on the ticked set: create an exception, or file one AuditBoard issue covering exactly those
findings. A selection is *not* a rule: only the ticked rows are covered, so membership must be
written down and must never be widened back into a rule.

**Exception rules that actually work.** A generated rule is pasted into a repository and committed.
So it has to be true about that repository *after* the scan that produced the finding is gone. The
old generator emitted a block of `#` comments ending "Add to your scanner's ignore/allowlist
configuration" -- inert text that reads like a rule, commits like a rule, and suppresses nothing.

Acceptance: no rule is emitted on a key the scanner cannot suppress on, and no rule contains a path
that no longer exists. Where the stored identifier cannot be trusted, the rule says so in the
pasteable text rather than looking confident.

## 2. Current State

- Branch `deployment-topology-p1-p2`. **Nothing in this workstream is committed.** Last commit is
  `3bc69f6` (the previous /clear-it handoff).
- **Built, tested, and live locally.** Full suite **568 pass / 82 collection errors**. The 82 are
  pre-existing and unchanged all session (baseline was 544 -> 563 after five generators -> 568 after
  horusec). `tests/test_exception_rule_generators.py` is 24/24.
- `auditgh_api` restarted **2026-09-17 20:36:29 UTC**; `findings.py` mtime in the container is
  **20:35:35 UTC**. Start is after mtime, so the running process has the generators. Health
  `healthy`.
- **API host port is 64533 right now and changes on every restart.** `docker-compose.yml:76`
  declares `ports: - "8000"` with no host binding, so Docker assigns a new ephemeral port each
  start. Harmless in practice -- the UI reaches the API as `http://api:8000` over the Docker
  network -- but any `curl` from the host must re-read `docker port auditgh_api` first.
- **Exception-rule coverage, measured this session against the live DB:** **133,508 of 767,895
  findings (17.4%)** now get a real scanner-specific rule, up from 7,013 (0.9%). Breakdown:
  horusec 57,783, grype 31,693, trivy-fs 27,206, trufflehog 7,013 (pre-existing), terrascan 4,841,
  retirejs 4,780, nuclei 192.
- **634,387 findings (82.6%) still fall to the honest fallback**, which now states plainly that it
  is not a rule. It is two scanners: **whispers 568,554** and **mobsf 65,833** (android 64,597 +
  ios 1,236).
- **Not verified through a browser.** The selection dialogs were fixed by a container restart, but
  the only remaining check is Rob, signed in, opening `http://localhost:3001/findings` and running
  the dialog. Auth middleware returns 401 before routing, so `curl` cannot exercise it.
- **AuditBoard TPRM: no access on the credentials we hold.** No v1 vendor route exists (proved, not
  assumed -- see section 5). v2 rejects both tokens. The MCP server does not list TPRM among its
  domains. Findings written into the `auditboard-api` memory note.
- **No AuditBoard writes were made this session.** Every probe was a GET, and no credential was
  sent to any host outside the tenant.

## 3. Active Files

- `src/api/routers/findings.py` -- the main file. Seven generators, the ephemeral-path helper, and
  both dispatch sites (per-finding endpoint and selection endpoint). Also carries earlier
  workstreams' code; the diff against HEAD is +1178 lines total, not all of it this session.
- `src/api/services/finding_groups.py` -- `GroupTier.SELECTION`, `SelectionPopulation`,
  `filing_match_condition`, `findings_covered_condition`, `render_locations`.
- `src/api/models.py` -- the `auditboard_issue_findings` membership table.
- `migrations/024_auditboard_selection_filings.sql` -- untracked. Creates that table.
- `src/web-ui/components/data-table.tsx` -- checkbox column on rows and groups.
- `src/web-ui/components/findings-selection-toolbar.tsx` -- untracked. The action bar.
- `src/web-ui/components/SelectionExceptionDialog.tsx`,
  `src/web-ui/components/SelectionAuditBoardDialog.tsx` -- untracked. The two dialogs from Rob's
  screenshots.
- `src/web-ui/lib/selection-issue.ts` -- untracked. Browser-side body assembly.
- `src/web-ui/app/findings/page.tsx`, `src/web-ui/lib/auditboard.ts` -- wiring.
- `tests/test_exception_rule_generators.py` -- untracked, 24 tests.
- `tests/test_selection_filing.py` -- untracked.
- `~/.claude/projects/.../memory/reference_auditboard_api.md` -- updated twice with the v1/v2 split
  and the Optro/MCP findings.
- `.scratch/` -- ~12 read-only probes (`tprm_probe*.py`, `tprm_v2.py`, `mcp_probe.py`,
  `rule_gen_probe.py`, `horusec_probe.py`). Gitignore, do not commit.

## 4. Changes Made

**All uncommitted.**

- **Selection tier.** `GroupTier.SELECTION`, deliberately excluded from `FILEABLE_TIERS`; a
  membership table so "is this already filed?" has an answer; a coverage query that reads membership
  and never touches `rule_id`; issue bodies that name the project above each path, because a
  selection spans repositories by construction.
- **Seven exception-rule generators**, replacing a single generic one:
  - `generate_grype_rule` -- `.grype.yaml` `ignore:`. The one scanner whose stored data supports a
    genuinely precise rule.
  - `generate_retirejs_rule` -- `.retireignore.json`, keyed on component/version, which sidesteps
    the ephemeral-path problem entirely.
  - `generate_trivy_rule` -- `.trivyignore` when a real advisory id is present, otherwise falls back
    to `trivy.yaml` `skip-files:` **and names the reason**.
  - `generate_terrascan_rule` -- inline `#ts:skip=` or `[rules] skip-rules`, with a VERIFY header
    unless the stored value matches `^AC_[A-Z0-9]+_\d+$`.
  - `generate_nuclei_rule` -- slugified template name, always VERIFY-flagged, with the
    `nuclei -tl | grep` confirmation command.
  - `generate_horusec_rule` -- `horusec-config.json` fragment using `horusecCliFilesOrPathsToIgnore`.
  - `generate_generic_rule` -- rewritten to say "This is NOT a rule" instead of impersonating one.
- **`repo_relative_path()`** strips `/tmp/repo_scan_<random>/<repo>/` prefixes and returns
  `(None, True)` when nothing survives, so no dead path ever reaches a config file.
- **`auditgh_api` restarted** at 20:36:29 UTC so the running process serves all of it.
- **AuditBoard memory note rewritten** with the v1/v2 auth split, the Optro rename and MCP launch,
  the four access routes, and the `*.auditboardapp.com` wildcard warning.

## 5. Failed Approaches -- DO NOT RETRY

**From this session:**

- **Rob's pasted Horusec documentation is wrong.** It used `horusecCmsiFilesOrPathsToIgnore`,
  `horusecCmsiFalsePositiveHashes`, `horusecCmsiRiskAcceptHashes`, `horusecCmsiToolsToIgnore`,
  `horusecCmsiMinSeverityToFilter`, `horusecCmsiMinConfidenceToFilter`. **Every `horusecCmsi*` key
  is fictional.** Verified against ZupIT/horusec's own `horusec-config.json`: the prefix on every
  real key is **`horusecCli`**. Three of those fields have no real equivalent at all --
  `horusecCliToolsConfig` is an object not a list, `horusecCliSeveritiesToIgnore` is the severity
  key, and there is **no confidence key**. The `// horusec:ignore` inline-comment syntax in the same
  document could not be corroborated anywhere. This matters more than a normal typo because
  **Horusec ignores unrecognised keys silently** -- a misspelled config parses, commits, scans, and
  suppresses nothing, and the failure surfaces only when the finding reappears.
- **Putting `//` comment lines in the Horusec rule output.** `horusec-config.json` is strict JSON
  and JSON has no comment syntax; the block would have made the file unparseable for anyone who
  pasted it whole. Every *other* generator emits YAML or TOML where `#` is legal -- JSON is the
  exception. Caveats live in the `instruction` field now, pinned by
  `test_horusec_output_is_parseable_json`.
- **`docker exec python -c "import ..."` as proof the live server has a change.** It does not. That
  is a *fresh import* of the file on disk -- it verifies the code, not the running process. This is
  how the "routes are registered" claim was made while Rob was still getting `Not Found` in his
  browser. The only valid check is container `StartedAt` **after** the file's mtime.
- **Reading a `401` from `/api/v2/*` as evidence a route exists.** AuditBoard v2 runs auth before
  routing: `/api/v2/vendors` and `/api/v2/zzzz_nonexistent` return the identical
  `{"error":"TOKEN header is incorrectly formated"}`. **v2 401s carry zero routing information.**
  Same trap as AuditGitHub's own middleware -- it has now fired on two different APIs.
- **Reading DNS resolution as evidence a service exists.** `mcp.auditboardapp.com` resolves; so does
  `zzz-definitely-not-real.auditboardapp.com`, to the same AWS Global Accelerator addresses.
  `*.auditboardapp.com` is a **wildcard**.
- **Reading a 200 from `/tprm/...` as evidence the module is licensed.** Every unmatched path
  returns the same 8,366-byte Ember SPA shell.
- **`psql -d auditgh`.** No such database. It is **`security_portal`**
  (`docker-compose.yml:85`, `POSTGRES_DB=${POSTGRES_DB:-security_portal}`).
- **Unquoted `--include=*.py`** in zsh -- glob error, not a grep error. Quote it.

**What the probing *did* establish (do not re-derive):**

- The AB_TPRM_KEY Rob minted is a **zero-permission v1 token**: it returns `200` with an empty list
  on routes it cannot see, **not** `404`. That is what turns the `/api/v1/vendors` 404 into proof the
  **route is absent**, not merely unpermitted. v1 auth passes, so v1 404s *are* real routing
  information -- unlike v2.
- User **1361 needs workspace grants** regardless of which route TPRM ends up on.

**Two ingest defects found, not yet fixed** -- they cap how precise any generator can be:

- **573,526 findings (74.7%) store `/tmp/repo_scan_<random>/...` paths** (whispers, retirejs,
  nuclei). Handled by the stripper, but it should not be stored that way.
- **Trivy's `rule_id` holds advisory prose, not an advisory id** -- 7,602 blobs, only 13 real IDs
  out of 27,206. This is why `generate_trivy_rule` has a fallback at all.
- There is **no raw-scanner-output column on `findings`**, which is what puts Horusec's exact
  per-finding suppression (`horusecCliFalsePositiveHashes`, which needs the vulnerability hash from
  the report) permanently out of reach.

**Carried forward -- still binding:**

- **(carried forward) A bind mount does not reload a running process.** `uvicorn` runs with **no
  `--reload`**. Any API change is dead until `docker restart auditgh_api`. **This has now cost time
  in three consecutive sessions** -- it was the root cause of Rob's "The rules could not be
  generated / Not Found" this session.
- **(carried forward) Treating `401` as proof a route is registered** on AuditGitHub itself.
  `src/api/middleware/auth.py:50` runs before routing. Control: `/definitely-not-a-route-xyz` also
  401s.
- **(carried forward) `/api/openapi.json`** -- 404; the real path `/openapi.json` is not public, so
  it 401s. There is no unauthenticated way to enumerate routes on the live process.
- **(carried forward) Iterating `app.routes`** -- this FastAPI version hides included routers behind
  `_IncludedRouter`. Use `app.openapi()['paths']`.
- **(carried forward) `docker exec auditgh_postgres`** -- no such container. It is **`auditgh_db`**.
- **(carried forward) Running tests on the host** -- pydantic/pydantic-core mismatch. Everything
  runs in `auditgh_api`.
- **(carried forward) Assuming Alembic governs the live schema.** No `alembic_version` table;
  schema comes from `create_all()` at `src/api/main.py:243`, which adds missing *tables* but never
  missing *columns*. Verify with `information_schema.columns`.
- **(carried forward) `findings.id` vs `findings.finding_uuid`** are independent columns. Read
  endpoints publish `finding_uuid`.
- **(carried forward) `findings.cwe_id` holds no real CWEs** -- empty, or the literal
  `HorusecEngine`.
- **(carried forward) Comparing a test-error count against a *remembered* baseline.** Re-measure on
  the same command before calling anything a regression. The 82 errors are pre-existing.
- **(carried forward) Believing a count published in an earlier message.** Take every figure from a
  query in the same message that publishes it. This has now fired in four consecutive sessions.
- **(carried forward) `docker compose restart web-ui` to pick up a change** -- the `web-ui-next`
  named volume persists; wipe `.next` entirely.
- **(carried forward) Believing a zero-result grep** without a single-file positive control.
- **(carried forward) Combined multi-field `PUT` to AuditBoard** -- refused. Write permission there
  is **per field, not per record**. Issues cannot be deleted; descriptions cannot be edited after
  create; `identified_date` is settable only at create.
- **(carried forward) Filing to the obvious AuditBoard endpoint.** Issues, IT Risk Issues and IT
  Risk Exceptions are three different APIs with near-identical URLs. Target is **IT Risk Issues**.
- **(carried forward) The harness line "Is a git repository: false" is wrong.**
  `git rev-parse --is-inside-work-tree` returns `true`.
- **(carried forward) Asking two AskUserQuestion questions at once.** One question, fewer options.
- **(carried forward) `npx playwright install chromium --with-deps` on macOS** -- Linux-only, hangs.
  Browser verification is still not possible in this environment.

## 6. Next Steps

1. **Rob, signed in, opens `http://localhost:3001/findings`, ticks findings, and runs Create
   Exception.** Thirty seconds, and it is the only way to confirm the fix for the `Not Found` he
   screenshotted. The same trip should cover `http://localhost:3001/rule-merges`, still outstanding
   from the previous session.
2. **Decide whether to build the whispers generator.** 568,554 findings -- 74% of the estate --
   still on the fallback, and no one has ever been able to write a working whispers exception from
   this tool. Its config takes an `exclude: files:` regex list, so the generator is
   straightforward; the complication is that all 568,554 carry `/tmp/repo_scan_` paths. Rob's
   scoping answer was "the precise five first", which is delivered plus horusec on top; **volume is
   a separate decision he has not made.** mobsf (65,833) is the other gap.
3. **Raise the two ingest defects as their own work** -- ephemeral scan paths, and Trivy prose in
   `rule_id`. Both cap generator precision permanently while they stand.
4. **Take the four questions to the Optro CSM / account rep**, in priority order: (a) is TPRM data
   included in the PostgreSQL export -- the likeliest route; (b) what token type does v2 accept and
   how is one issued; (c) is our TPRM licensed at Professional tier; (d) does the MCP server expose
   TPRM, and as what identity. Separately, **user 1361 needs workspace grants** either way.
5. **Rotate the Google API key `AIzaSyDRz8…Upb-k`** -- live, exposed on the **public**
   `sealmindset/auditgithub` at commits `0042407` and `1e499d9`, also in shipped APKs and in
   plaintext in AuditBoard **I#1716**, which cannot be edited. Treat as compromised. Needs Google
   Cloud console access. Full value is in those commits; not repeated here, because this file is
   tracked on the same public repo.
6. **Rotate the GitHub PAT `ghp_5gLP…OgmUH`** -- in **tracked** files on that same public repo:
   `docs/GIT_SYNC_COMPLETE.md:156` and `docs/plans/GIT_SYNC_IMPLEMENTATION_STATUS.md:322`. Those two
   lines hold the full value and are what needs deleting after rotation.
7. **Rotate the GRC bearer token exposed by `NEXT_PUBLIC_AUDITBOARD_TOKEN`** at
   `frontend/app/(auth)/assessments/[id]/page.tsx:169-170` in the **sec-diligence** repo -- it ships
   to every browser. Rotation is the fix; deleting the line is not. Also still open there:
   `SEVERITY_MAP = {1:"low",2:"medium",3:"high",4:"critical"}` applied to `issue_rating_id` in
   `backend/app/services/auditboard.py` imports wrong severities.
8. **AuditBoard housekeeping**, all needing rights the API does not grant here: close **I#1717**
   (covers 0 findings now), add the supersede reason to **I#1715**, delete the **I#1714 `[TEST]`**
   record, decide on hand-entering `identified_date` for I#1716--I#1719.
9. **Decide the AI spend on rule equivalence: 475 unchecked pairs = 475 provider calls.** Nothing
   degrades if it is never run -- unchecked pairs stay separate.
10. **Commit and push.** Nothing is committed across **four** workstreams now sharing this working
    tree: selection actions + generators (this session), AuditBoard grouping/equivalence, Report
    Generator Wizard P1/P2, npm hunt. Read before including. Rob's standing answer: push to **both**
    remotes -- public `origin` (`sealmindset/auditgithub`) and private `sleepnumber`
    (`SleepNumberInc/auditgithub`). Untracked agent-tool directories (`.agent/`, `.codex/`,
    `.cursor/`, `.kiro/`, `.scratch/`, and a dozen more) should be **gitignored, not committed**.
11. **Still open from the Report Generator Wizard workstream:** the KB approval workflow -- all
    2,639 entries are `draft`, no endpoint approves one, and this **blocks P4 outright**;
    architecture-report backfill over 703 repos; authoring the top KB entries in impact order;
    deciding where per-finding AI output lives.
12. **Still open from the npm supply-chain hunt:** decide the anti-remediation vector's shape.
13. **Incidentals.** `docker-compose.yml:76` should pin the API host port so it stops moving.
    `src/api/routers/ai.py` has two loguru calls using `%s` formatting. This handoff's predecessor
    named the UI container `auditgh_web-ui`; it is **`auditgh_ui`**.

**No further AuditBoard writes without explicit confirmation.** No writes were made this session --
every probe was a GET, and no credential left the tenant.
