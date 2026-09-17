# Issue grouping and cross-scanner rule equivalence — technical companion

**Date:** 17 September 2026
**Leadership briefing:** `docs/GRC_Filing_Grouping_Status_Briefing.md`
**Generated names appendix:** `docs/GRC_Filing_Grouping_Appendix.md`, from `scripts/generate_grouping_appendix.py`

All figures in this document and in the briefing come from one run of
`scripts/generate_grouping_appendix.py` against `security_portal` on
2026-09-17. Denominators are stated with each figure. Nothing is rounded.

---

## 1. What is the problem

### 1.1 The retired grouping key

`auditboard_issues.scope` previously took two values, `specific` (one finding)
and `global`, where `global` keyed on `(scanner_name, file_path)`. That key is
wrong in both directions.

**It over-groups.** `file_path` is not a defect. Measured on the current
database:

| Key | Findings | Distinct `rule_id` inside | Repositories |
| --- | --- | --- | --- |
| `grype` + exactly `/package-lock.json` | 11,517 | 386 | 110 |
| `grype` + any path ending `package-lock.json` | 18,269 | 480 | 137 |
| `trivy-fs` + any path ending `package-lock.json` | 13,172 | 434 | 109 |
| `grype` + any path ending `pom.xml` | 4,057 | 274 | 74 |
| `trivy-fs` + any path ending `Dockerfile` | 2,575 | 12 | 205 |

The 11,517 figure is the exact-path measurement, which is what the retired key
actually compared; 18,269 is the same problem counted by file name across
subdirectories. Both are in the appendix, §A. A single issue under this key
asserts coverage of up to 480 unrelated advisories with independent fixes and
independent upstream release schedules.

**It under-groups.** The same advisory in 137 repositories produced 137
candidate issues, one per repository, because `file_path` differs per repo.

### 1.2 Cross-scanner rule naming

Identity now keys on `(scanner_name, rule_id)`. `rule_id` is populated on
767,974 of 767,974 findings — 100%. The identifiers that would settle
cross-scanner equality by string comparison are not available: `cve_id` is
populated on 0% of findings, `ghsa_id` only on `grype`. So `grype`'s
`GHSA-M7JM-9GC2-MPF2` and `trivy-fs`'s `CVE-2024-21538` are two identities for
one advisory, and file as two issues.

### 1.3 Constraints that shape every decision below

Measured against the live AuditBoard instance, not assumed:

- Issues cannot be deleted through the API.
- Descriptions cannot be edited after create. Write permissions are per field,
  not per record: a combined multi-field `PUT` is refused with
  `ModelActionPermissionDenied (Permission: issue:action.editDraft)`; a
  single-field `PUT` succeeds for `custom_text4` and the four user stamps.
- `identified_date` is settable only at create.

Therefore a wrong merge is permanent and a wrong grouping is permanent. Every
default in this implementation resolves toward "file separately", because the
recoverable error is a visible duplicate.

## 2. Where the problem is, and what now handles it

### 2.1 Measurement and grouping

`src/api/services/finding_groups.py` (812 lines) is the measurement layer.

| Concern | Location |
| --- | --- |
| Severity ordering; unknown severity ranks below `info` so a typo cannot promote an issue | `severity_rank`, `highest_severity` — lines 87, 96 |
| Path normalization, stripping `^/tmp/repo_scan_[^/]+/` then the repo name when it leads the remainder | `normalize_path` — line 124 |
| Defect identity `(scanner_name, rule_id)`; `None` when either half is missing | `Identity`, `identity_of` — lines 165, 185 |
| Approved merges as union-find, canonical member = lexicographic minimum | `EquivalenceMap` — line 200 |
| Tiers `specific` / `project` / `org`, plus read-only `global` | `GroupTier`, `FILEABLE_TIERS` — lines 273, 288 |
| Escalation rule, `> FILING_PROJECT_ESCALATION_THRESHOLD` projects | `recommended_tier` — line 295 |
| Location collection and rendering, capped at `FILING_MAX_LOCATIONS` and stating what it omitted | `collect_locations`, `render_locations` — lines 347, 404 |
| Reads only `approved` + `equivalent` rows | `load_equivalence_map` — line 466 |
| The measured population an issue speaks for | `measure_group` — line 555 |
| Earliest `first_seen_at`/`created_at` across the group, for `identified_date` | `earliest_identified_date` — line 657 |
| "An existing issue already covers this finding", all four tiers | `filing_match_condition` — line 687 |
| The inverse, keyed off the tier each issue was filed at | `findings_covered_condition` — line 749 |
| Critical/High/Medium floor, group tiers only | `is_filing_eligible` — line 792 |

573,526 of 767,974 findings (74.7%) carry a path under a per-scan temp
directory, which is why normalization is not optional: `/tmp/repo_scan_<id>/…`
stops resolving the moment the scan is gone.

`FILING_EXCLUDE_NON_ACTIONABLE` defaults true, removing the 546,977 findings
already carrying an exclusion reason from every filing population.

### 2.2 API surface

`src/api/routers/findings.py`:

- `GET /findings/{finding_id}/group?tier=` — `get_finding_group`, line 703.
  Rejects unknown tiers with 400; rejects `global` with a 400 stating it is
  readable but no longer fileable; returns a specific-only response with
  `blocked_reason` when the finding has no `rule_id`.
- `POST /findings/{finding_id}/auditboard-issue` — `create_auditboard_issue`,
  line 953. Resolves tier → `load_equivalence_map` → `measure_group`, applies
  the severity floor to group tiers only, renders the location list from the
  same measurement it counted from, sets `identified_date` from
  `earliest_identified_date`, rates at `population.severity`.
- `GET /findings/auditboard-filings` — `list_auditboard_filings`, line 1270,
  expanding approved merges into `identity_keys` server-side.
- `delete_findings_dry_run`, line 2005, computes `remaining_findings` per issue
  at that issue's own tier, so a pre-change `global` row still reports what it
  covered when filed.

Persisted per filing: `rule_id`, `repository_id` (NULL at org tier, on purpose,
so an org issue does not match only the repository the filer was looking at),
`location_count`, `locations_omitted`, `project_count`, `scope`.

### 2.3 Cross-scanner equivalence

`src/api/services/rule_equivalence.py` (746 lines).

**Blocking.** `_CANDIDATE_SQL`, line 175. Self-join of
`DISTINCT (repository_id, regexp_replace(file_path,'^/tmp/repo_scan_[^/]+/',''), scanner_name, rule_id)`
on equal repository and equal normalized path, with `a.scanner_name <
b.scanner_name` — strictly less than, which both restricts to cross-scanner
pairs and fixes the stored order. Same-scanner pairs are excluded by design:
two rules of one scanner are that scanner's own taxonomy, and merging them
would hide a distinction its authors drew deliberately.

Counts, both real, different denominators:

| Population | Pairs |
| --- | --- |
| Cross-scanner co-located pairs, Critical/High/Medium, actionable only | **478** |
| Same, all severities | **834** |
| Same, all severities, requiring ≥ 2 shared locations | 464 |

The severity floor is the default (`default_severities`, line 223, reading
`FILING_SEVERITIES`) because a pair outside the floor can never be filed as a
group, so asking about it spends a model call on nothing. `severities=[]` asks
about all 834. An earlier note recorded 478 without stating the floor; that is
the same measurement, now labelled.

**Prompt.** `PROMPT_TEMPLATE`, line 373; `build_prompt`, line 411. Pure
function. Carries both scanner/rule identifiers, up to
`SAMPLES_PER_RULE = 3` example titles, descriptions clipped to 400 characters,
severities and normalized paths per side, and the overlap counts. It states
that co-location is not evidence, and instructs a bias toward `distinct`. It
carries **no `code_snippet`** — a snippet is not needed to compare two rules,
and for the secret-scanner family the snippet is the credential.

**Parsing.** `parse_verdict`, line 472. Extracts the first `{...}` block, so a
prefaced answer is still read. Returns `None` — meaning nothing is recorded and
the pair stays a candidate — for empty input, no JSON block, invalid JSON, a
non-object, or a verdict outside `{equivalent, distinct}`. Confidence is
clamped to `[0,1]`. An `equivalent` verdict with confidence below
`MIN_CONFIDENCE = 0.80` (line 71), or with no readable confidence, is returned
as `distinct` with `downgraded_from` set and the rationale preserved, so a
reviewer can still approve by hand.

**Calling.** `ask_provider` / `ask_provider_batch`. Requires only
`execute_prompt`, which every provider in `src/ai_agent/providers` implements.
Default timeout 90s; default concurrency 4, capped at 8 in the API, because the
Foundry deployment is shared with triage and architecture analysis. Timeouts,
provider exceptions and unparseable replies all collapse to "no answer".
Results are returned in input order, not completion order.

**Persistence.** `record_proposal`, line 606, writes in canonical order against
`uq_rule_equivalence_pair`, which is also the verdict cache — the question is
about two rules, so 11,517 findings of one defect cost one call. A row with a
`review_decision` already set is never overwritten by a later proposal.
`review_decision` is left NULL on create.

`apply_review`, line 685, sets the decision, reviewer and `reviewed_at` from
the database clock rather than the container's.

### 2.4 Review queue

`src/api/routers/rule_equivalences.py` (509 lines), mounted at
`src/api/main.py:269`:

| Endpoint | Purpose | Permission |
| --- | --- | --- |
| `GET /rule-equivalences` | Queue, `status=pending|approved|rejected|all` | `findings:read` |
| `GET /rule-equivalences/stats` | Queue depth and candidate coverage | `findings:read` |
| `GET /rule-equivalences/candidates` | Blocked pairs with no row yet. Calls no provider. | `findings:read` |
| `POST /rule-equivalences/propose` | One provider call per candidate, `limit` 1–100 | `findings:write` |
| `POST /rule-equivalences/{id}/review` | Approve or reject | `findings:write` |
| `POST /rule-equivalences` | Record a merge by hand, marked `source: manual` in evidence | `findings:write` |

Existing permissions are reused rather than a new one seeded, because a merge
decision changes grouping and nothing else, and an unseeded permission would
lock every current role out of the queue.

UI: `src/web-ui/app/rule-merges/page.tsx` (556 lines), linked from
`components/app-sidebar.tsx` under AI Management. Shows queue depth, approved
merges in force, pairs decided separate, and candidate coverage; a per-row
Approve/Reject with an optional note; and the next unchecked pairs with their
overlap.

### 2.5 Secret handling

`src/api/services/issue_redaction.py` (91 lines) strips a secret-family
scanner's own `code_snippet` from the title, description and executive summary
before any AuditBoard write, and logs when it fires. Withheld entirely rather
than masked: masking requires guessing which token is the secret, and a wrong
guess leaks the line while looking safe. The browser withholds the same
snippets in `lib/finding-issue.ts`; the server copy is the one that holds
against a stale tab or a direct POST.

GRC issue **I#1716** carries a live Google API key
(`<redacted - see AuditBoard I#1716>`) in its body in plaintext, filed
before this check existed. The description cannot be edited. Rotation is the
only fix; the key is also in git history and in shipped APKs.

## 3. Current state, measured

| Measure | Value | Denominator / definition |
| --- | --- | --- |
| Findings | 767,974 | all rows in `findings` |
| Findings with `rule_id` | 767,974 | 100% |
| Findings already not-actionable | 546,977 | `excluded_from_actionable IS TRUE` |
| Findings on temp scan paths | 573,526 | `file_path LIKE '/tmp/repo_scan_%'` |
| Repositories | 2,540 | all rows in `repositories` |
| Distinct scanners | 10 | `DISTINCT scanner_name` |
| Distinct defects | 2,638 | `DISTINCT (scanner_name, rule_id)`, all severities |
| Fileable defects | 2,397 | Critical/High/Medium, actionable only |
| Fileable defects over the escalation threshold | 241 | of the 2,397, `> 10` distinct repositories |
| Candidate rule pairs | 478 / 834 | severity floor / all severities |
| Candidate pairs still unchecked | 475 | of 478 at the floor |
| Merge proposals recorded | 3 | all `pending`, all `distinct` |
| Approved merges in force | 0 | `approved` + `equivalent` |
| Issues filed by this system | 5 | I#1716–I#1720, appendix §C |

The three recorded proposals came from a smoke test of the live provider
(`anthropic_foundry`, `cogdep-aifoundry-dev-eus2-claude-sonnet-4-6`) on
2026-09-16: verdicts `distinct` at 0.85, 0.92 and 0.99. They are listed in full
in appendix §D. No AuditBoard writes were made during that test.

### 3.1 End-to-end verification of the merge path

Run in a transaction and rolled back, so nothing was persisted. Pair
`terrascan::appArmorProfile` ↔ `trivy-fs::Root file system is not read-only`,
measured at `org` tier on finding `343901a6-ca81-4a8e-8e0f-b3d03d169fee`:

| State of the merge row | Members | Findings | Projects |
| --- | --- | --- | --- |
| absent | 1 | 219 | 14 |
| present, `review_decision IS NULL` | 1 | 219 | 14 |
| present, `approved` + `equivalent` | 2 | 466 | 20 |

Canonical identity stayed `terrascan::appArmorProfile` in all three states — the
lexicographic minimum, so the key does not depend on which member the filer
opened. This is the proof that an unreviewed proposal is inert and an approved
one takes effect.

### 3.2 Route registration, and what was actually verified

`GET /findings/{finding_id}/group` and five `/rule-equivalences` paths carrying
six operations — `GET` and `POST` on `/rule-equivalences`, `GET
/rule-equivalences/stats`, `GET /rule-equivalences/candidates`, `POST
/rule-equivalences/propose`, `POST /rule-equivalences/{equivalence_id}/review` —
appear in the OpenAPI document of the application object built by
`src/api/main.py`.

An earlier probe that reported "41 routes, no matches" was an artifact of
iterating `app.routes`: this FastAPI version defers included routers behind
`_IncludedRouter` (`fastapi/routing.py:1586`), so router paths are not visible
at the top level. `app.openapi()['paths']` shows them.

**A correction.** An earlier draft of this section cited "an unauthenticated
request returns `401`, not `404`" as evidence that the route is registered.
That inference is invalid. `AuthenticationMiddleware`
(`src/api/middleware/auth.py:50`) runs before routing and, with
`AUTH_REQUIRED=true`, returns `401` for every non-public path. A control request
to `/definitely-not-a-route-xyz` returned `401` as well. The status code
therefore carries no information about routing, and no claim in this report
rests on it.

**What the running process was, and is.** The `api` container runs
`uvicorn src.api.main:app --host 0.0.0.0 --port 8000` with no `--reload`
(`docker inspect` on `.Config.Cmd`; `ps ax | grep -c "[u]vicorn.*reload"` = 0).
Before 2026-09-17 16:48 UTC that process had started at 2026-09-16 15:15:19 UTC,
whereas `src/api/services/rule_equivalence.py` was written at 17:57:33 and
`src/api/routers/rule_equivalences.py` at 17:58:58 the same day — 2h43m after
the process began. Without `--reload`, a process cannot load a module written
after it started, so the new endpoints were **on disk but not being served**.
The container was restarted at 2026-09-17 16:48 UTC and reports healthy;
`include_router` executes at import time, so "Application startup complete"
with no traceback establishes that the router was imported and mounted.

**The residual limit.** These routes were not exercised through the live socket
by this report, because every one of them requires a session cookie and the
blanket `401` cannot distinguish a registered route from a missing one. The
end-to-end check is a signed-in browser opening `/rule-merges`, which calls
`GET /rule-equivalences/stats` and `GET /rule-equivalences/candidates` with the
user's own session.

`src/web-ui` runs `next dev` with the repository bind-mounted at `/app`, so
`/rule-merges` and the sidebar entry were served by the running dev server from
the moment they were written and needed no restart. `/rule-merges` returns `307`
to `/login?redirect=%2Frule-merges` when signed out, which is the frontend's own
route guard and confirms the page is routable.

### 3.2.1 Deployment status

Everything described here runs in the local Docker Compose stack only
(`auditgh_api`, `auditgh_web-ui`). Nothing in this work has been deployed to a
shared, staging or production environment, and no such deployment is claimed.

### 3.3 Tests

| Suite | Tests | Result |
| --- | --- | --- |
| `tests/test_finding_groups.py` | 39 | pass |
| `tests/test_issue_redaction.py` | 20 | pass |
| `tests/test_rule_equivalence.py` | 36 | pass |
| Full suite | 528 | pass |

82 collection errors, all pre-existing and none touching this code: 55 from
`AttributeError: 'SQLiteTypeCompiler' object has no attribute 'visit_JSONB'`
and `visit_ARRAY` — 30 model tables including `findings.risk_factors` and
`repositories.topics` cannot be created on SQLite — and 27 from
`fixture 'db_session' not found` in `test_data_integrity.py` (19) and
`test_ingestion_pipeline.py` (8). Frontend `tsc --noEmit` and `eslint` clean on
the changed files.

## 4. How to address what remains

1. **Work the review queue.** 475 unchecked pairs at the severity floor.
   `POST /rule-equivalences/propose` with `limit` up to 100 per call, then
   approve or reject from `/rule-merges`. 475 provider calls at default
   concurrency 4. This is the only outstanding spend decision.
2. **Close I#1717.** Its findings were deleted; the per-tier dry run reports it
   now covers 0 findings. Requires a person with rights in AuditBoard.
3. **Rotate `<redacted - see AuditBoard I#1716>`.** In git history, in
   shipped APKs, and in the body of I#1716 in plaintext, which cannot be
   edited.
4. **Housekeeping in AuditBoard, both needing rights the API does not grant
   here:** add the supersede reason to I#1715, and remove the I#1714 `[TEST]`
   record.
5. **Decide on `identified_date` for I#1716–I#1719.** The field is settable only
   at create, so correcting it means hand-entry in AuditBoard.

## 5. Coverage limits

- **Blocking is co-location.** Only pairs where two scanners reported findings
  at the same normalized path in the same repository are candidates. Two
  scanners describing one defect that never land on a common file are not
  proposed at all, and no count here bounds how many of those exist. Absence of
  a proposal is not evidence of absence of duplication.
- **The severity floor bounds the candidate list.** 478 of 834 co-located pairs
  are in scope by default. The other 356 are real pairs that are simply not
  group-fileable at their severities.
- **`excluded_from_actionable` bounds every filing population.** 546,977
  findings are excluded by that flag. This report does not re-validate those
  exclusions.
- **The 2,638 defect count is a count of distinct scanner reports**, not of
  confirmed defects. False-positive rate is not measured here.
- **Severity is the maximum across contributing scanners**, with the per-scanner
  breakdown printed in the issue body. Where scanners disagree, the issue is
  rated at the higher figure by policy, not by evidence.
- **Nothing filed before 2026-09-16 was corrected.** Descriptions are immutable
  after create, so the five existing filings retain the grouping they were
  filed under, and appendix §C reports their coverage as measured at filing.
- **Secret values are withheld**, so no register entry and no document in this
  set can be used to enumerate exposed credentials. That is a deliberate gap in
  this evidence, not a claim about exposure.
- **Access that would close the remaining gaps:** AuditBoard delete rights (to
  remove I#1714), AuditBoard description-edit rights (which do not appear to
  exist on this instance at all), and Google Cloud console access to rotate the
  exposed key.
