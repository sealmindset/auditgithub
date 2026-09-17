# Report Generator Wizard — Technical Specification

**Status:** Draft for review. No code written against this yet.
**Date:** 2026-09-14
**Branch target:** new branch off `deployment-topology-p1-p2`
**Route:** `Repositories → /projects/[id] → Reports tab → wizard`

---

## 0. Decisions already made

Every row below was answered explicitly and is binding. Changing one changes the spec.

| # | Decision | Answer |
|---|---|---|
| 1 | Remediation taxonomy | Fixed enum, 11 values (§2). Each carries a two-line remediation description. |
| 2 | Who assigns category | Rules first, AI only on unmatched. Store `category_source` + confidence. |
| 3 | Effort | Refer, do not define. Drivers + band. **No hour assertion.** (§4) |
| 4 | Effort unit | Per remediation **action**, not per finding. Rolled up. |
| 5 | Contributor timeline | Backfill from `git log` during scan. Monthly granularity. |
| 6 | Deployment truth | observed > mapped > declared. `repo_deployment_map` gains a `url` column. Unresolved prints a reason, never blank. |
| 7 | OSINT scope | Both internal and external — **passive and free only** (§7). |
| 8 | Wizard prompt power | (b) — selects, adds, reorders, omits sections. Never produces a figure. |
| 9 | Report pair rule | Applies. One run emits briefing + companion + generated appendix. |
| 10 | Persist report runs | Yes — spec, figures, and rendered artifacts. |
| 11 | Saved templates | Yes, reusing `prompts` / `prompt_versions`. |
| 12 | Sync/async | Background job, status row, client polls. (§10.1 states the honest limit.) |
| 13 | Access control | Repo-scoped RBAC; contributor PII behind a separate toggle, default off; every generation logged. |
| 14 | Entry point | **Fold.** Existing `SecurityReportModal` becomes wizard preset #1. One entry point. |
| 15 | AuditBoard | One-way push v1. One issue per remediation action, org-scoped. Dry-run default. |
| 16 | KB key | Composite, precedence `cve_id` → `(scanner_name, rule_id)` → `cwe_id`. Add `rule_id` to `findings`. |
| 17 | Blast radius | **Exploitation** blast radius, not regulatory. |
| 18 | TTP source | Deterministic CWE → CAPEC → ATT&CK. AI writes prose only. Unmapped prints as unmapped. |
| 19 | KB governance | `draft` → `approved`. Only `approved` renders in a report. Versioned. |
| 20 | KB scope | Global, with optional per-organization mitigation overlay. |
| 21 | Action grouping scope | **Per-org by default**, per-repo selectable. |
| 22 | Preface when no architecture report exists | **Generate on demand, then cache.** The pipeline calls the existing `POST /api/v1/ai/architecture` when the repo has none, persists and versions the result, and renders the preface from the full report. One AI call per repo, once. Bulk backfill is allowed ahead of time. (§1.2, §10.2) |
| 23 | Architecture truncation at the existing call sites | **Fixed in place.** The 2,000/3,000-character bare slices are replaced by a budgeted excerpt that cuts on a heading boundary and states what it dropped. (§1.2, §10.2) |

---

## 1. What already exists (reused, not rebuilt)

| Capability | Location |
|---|---|
| Repo profile: creation date, description, topics, archived, visibility, license, stars/forks | `Repository` |
| Architecture report + diagram code + version history — **capability complete, data almost absent, see §1.2** | `Repository.architecture_report`, `.architecture_diagram`, `ArchitectureVersion`; routes at `src/api/routers/ai.py:1119-1780` |
| Findings with severity, type, scanner, CVE, CWE, package/fixed version, risk score, MTTR, AI triage | `Finding` |
| Contributor identity merge across aliases, Entra ID, employment status | `ContributorProfile`, `ContributorAlias` |
| Declared environment URLs | `RepositoryOperations.environment_urls` |
| Observed deployments | `Deployment`, `DeploymentTarget`, `WorkflowRun`, `CICDPipeline` |
| Inferred deployment map with provenance + confidence + explicit unresolved marker | `RepoDeploymentMap` |
| AI providers with failover (openai / claude / anthropic_foundry / ollama) | `src/ai_agent/providers/` |
| Prompt library with versioning and usage tracking | `Prompt`, `PromptVersion`, `PromptUsage` |
| Markdown → PDF / DOCX | `src/reporting/md_to_pdf.py`, `md_to_docx.py` |
| Repo cloning (enables real `git log`) | `execution/clone_repo.py` |
| Encrypted credential storage (Fernet) | `OrganizationCredential`, `src/api/secrets_store.py` |
| Existing AI security report + modal (becomes preset #1) | `POST /projects/{id}/security-report`, `SecurityReportModal` |

### 1.2 "Reused, not rebuilt" is a claim about capability, not about data

The table above lists what the system *can* do. For the report preface — the "what is this
repository, what does it do, how is it built" section that opens every report — the capability
exists and is complete: generate, refine, validate, version, restore, all on demand at
`POST /api/v1/ai/architecture`.

**The data behind it is almost entirely absent.** Measured 2026-09-14:

| | Count | Share |
|---|---|---|
| Repositories | 2,540 | |
| With an architecture report | **2** | 0.08% |
| With an architecture diagram | 2 | 0.08% |
| Rows in `architecture_versions` | **0** | — |
| With a GitHub description | 2,461 | 96.9% |
| With actionable findings | 703 | 27.7% |

The two that have one (`devops-sdp-infrastructure`, `snint-bip-proxy-fna`) carry 144 and 165
actionable findings, so this is not a case of architecture having been run only where there was
nothing to report. It has simply barely been run. The reports are substantial where they exist
— roughly 14,000 characters of prose plus 9,000 characters of `diagrams` Python that renders
the image.

Two consequences the pipeline design has to absorb. Both are now decided (§0 rows 22 and 23);
the second is built.

1. **A preface that reads `architecture_report` produces nothing for 2,538 of 2,540
   repositories.** *Decision: generate on demand, then cache.* The pipeline calls the existing
   `POST /api/v1/ai/architecture` when the repo has none, persists it on `repositories` and
   writes an `architecture_versions` row, and renders the preface from the full report. The cost
   is one AI call per repository over cloned source, paid once; 703 repositories have actionable
   findings, so a bulk backfill of that set bounds the wizard's latency ahead of time rather
   than charging it to the first user who asks for a report. A repository whose architecture
   generation fails prints the failure in the preface — it does not silently fall back to the
   GitHub description and present it as architecture.
2. **The existing security report already truncates it.** `src/api/routers/projects.py:1137`
   injected `architecture_report[:2000]` and line 1160 injected `[:3000]`. Against a ~14,000
   character report that silently discarded roughly 80% of the analysis, mid-sentence.
   *Decision: fixed in place, and it is.* `src/services/markdown_excerpt.py` takes whole
   `##` sections in order until the budget is spent, falls back to a paragraph/sentence/word
   boundary when the first section alone overruns, and appends
   `[... N of M sections omitted; X of Y characters shown ...]`. The two call sites now pass
   8,000 and 12,000 characters, and the prompt instructs the model to confine itself to the
   sections actually shown. Covered by `tests/test_markdown_excerpt.py` (9 tests), one of which
   pins the old bare-slice behavior so the regression is legible if anyone reintroduces it.

### 1.1 Known-wrong things this spec fixes

**Contributor first-commit.** `src/api/routers/contributor_profiles.py:1231` computes:

```python
first_commit = min((c.last_commit_at for c in group if c.last_commit_at), default=None)
```

That is the minimum of *last*-commit dates, not a first commit. Any contributor timeline drawn
from it today is wrong. §6 replaces it with a measured value.

### 1.3 The per-finding AI output that was never stored

The finding detail page has two AI features — "Details (Ask AI)" and "AI Remediation" — and the
schema to persist them: `findings.ai_remediation_text`, `ai_remediation_diff`, `ai_triage_recommendation`,
`ai_triage_reasoning`, `ai_confidence_score`, plus a `remediations` table with an FK to
`findings`. Measured 2026-09-14 across all 769,825 findings, **every one of those is empty**:

| | Rows |
|---|---|
| `remediations` | 0 |
| `findings.ai_remediation_text` populated | 0 |
| `findings.ai_remediation_diff` populated | 0 |
| `findings.ai_triage_recommendation` / `_reasoning` / `ai_confidence_score` | 0 / 0 / 0 |

Not disuse — a defect. `findings.id` and `findings.finding_uuid` are separate columns with
independent `gen_random_uuid()` defaults (`src/api/models.py:398`, `:404`), and every read
endpoint publishes `finding_uuid` as the finding's `id` (`src/api/routers/findings.py:506`).
`POST /ai/remediate` looked the caller's identifier up against the **primary key**:

```python
finding = db.query(models.Finding).filter(models.Finding.id == request.finding_id).first()
```

```sql
SELECT count(*) FROM findings WHERE id = finding_uuid;   -- 0 of 769,825
```

So `if finding:` was false on every call. No exception, no log: the model's answer was returned
to the browser and discarded, and the Generate button reappeared on the next visit. Every click
paid for a model call that was thrown away.

Fixed. `_resolve_finding()` in `src/api/routers/ai.py` tries the published identifier first and
the primary key second, the `Remediation` row is written against `finding.id` so the FK holds, a
miss is now logged rather than skipped silently, and a persistence failure rolls the session
back. Pinned by `tests/test_finding_identity.py` (11 tests), including one that reproduces the
old filter and asserts it finds nothing.

**What this does not settle.** Repairing the write path does not make per-finding storage the
right home for remediation prose. 222,844 actionable findings resolve to 2,639 KB keys (§3.0),
so `ai_remediation_text` offers 84 slots per distinct piece of advice, each separately generated
and therefore differently worded — and §4 cannot render an action whose findings each carry
their own paragraph. The split the KB implies is prose per *key* and diff per *instance*, with
the remediation card reading an approved KB entry before it calls a model. That read path is
**not built** and waits on the §3.7 approval API.

---

## 2. Remediation taxonomy

Fixed enum. The AI selects from this list and may not invent a value.

| Value | Meaning | Two-line remediation text (template) |
|---|---|---|
| `patch` | Apply a vendor-supplied fix with no version change | Apply the vendor patch for {ref}. No dependency version change is required. |
| `upgrade_dependency` | Move a package to a fixed version | Upgrade {package} from {current} to {fixed}. Verify {breaking_note}. |
| `configure` | Change a setting; no code change | Change {setting} in {location} to {value}. No application code is modified. |
| `code_change` | Rewrite application logic | Modify {file} so {behaviour}. Requires code review and test coverage. |
| `rotate_secret` | Revoke and reissue a credential | Revoke {secret_type} in {system} and issue a replacement. Purge it from git history. |
| `access_control` | Change who or what may reach the asset | Restrict {principal} access to {resource}. Re-grant on least privilege. |
| `infra_control` | Network or platform control | Place {control} in front of {asset}. This blocks exploitation without changing the code. |
| `remove_dependency` | Drop or replace the component | Remove {package} and replace with {alternative}. No fixed version exists upstream. |
| `compensating_control` | Detect rather than prevent | No fix is available. Add detection for {signal} and alert {owner}. |
| `accept_risk` | Documented acceptance | Risk accepted by {owner} on {date}. Re-review on {date}. |
| `false_positive` | Not a real finding | Not exploitable in this context because {reason}. Suppress the rule for {scope}. |

Placeholders resolve from the finding row and the KB entry. Any unresolved placeholder renders
as `unknown — {what would resolve it}`, never as a blank or a guess.

### 2.1 Classification: rules first, AI on the remainder

Deterministic rules run first. They are cheap, reproducible, and cover the bulk.

Implemented in `src/services/remediation_classifier.py`. Evaluated in this order — the first
match wins, and the order is the substance of the design, not an implementation detail:

| # | Condition | Category | Why it sits here |
|---|---|---|---|
| 1 | `status == 'accepted'` | `accept_risk` | A person decided. Nothing below overrides a person. |
| 2 | `ai_triage_recommendation == 'false_positive'` and confidence ≥ 0.8 | `false_positive` | A model that is unsure must not close a finding by itself. |
| 3 | `(scanner_name, rule_id)` in `SUPPRESSIONS` | per table, `excluded = true` | Rule-level suppression, below the analyst, above the type. |
| 4 | `finding_type == 'secret'` | `rotate_secret` | |
| 5 | `finding_type == 'oss'` | `upgrade_dependency` | See the correction below. |
| 6 | `finding_type == 'iac'` | `configure` | |
| 7 | `finding_type == 'sast'` | `code_change` | |
| — | anything else (`dast`, `malware`) | `NULL`, `category_source = 'none'` | Genuinely ambiguous; the rules decline rather than guess. |

**Correction to the original rule, forced by the data.** This spec previously keyed the OSS
branch on `fixed_version`: not null → `upgrade_dependency`, null → `remove_dependency`.
**`fixed_version` is empty on all 769,825 findings in this estate**, so that rule sends every
dependency finding to `remove_dependency` — the most expensive advice available, applied
universally, and wrong. The branch is removed. Dependency findings classify as
`upgrade_dependency` with a rationale that states the fixed version was not recorded, so the
gap is visible in the finding rather than hidden in the category.

`finding_type` is folded through an alias map before matching — ingest writes `vulnerability`,
`dependency` and `sca` where the API queries `oss`, and `secrets`/`infrastructure`/`terraform`
for `secret`/`iac`. Unknown types pass through unchanged so a new scanner shows up as
unclassified rather than being silently rebucketed.

Everything unmatched goes to the AI, which must return one enum value plus a confidence.

Four columns are stored on every finding so a reader can tell which decided:

- `remediation_category`
- `category_source` — `rule` | `ai` | `human` | `none`
- `category_confidence` — `1.00` for rules, model-reported for AI, `1.00` for human override
- `category_rationale` — free text; every rule decision writes one

The companion report breaks the category totals down by source. A rule-matched count and an
AI-inferred count are different claims and are never merged into one number.

### 2.2 Suppression: excluded is a third state, not a synonym for false positive

Two scanner rules account for **71.1%** of this estate and neither reports a credential.
Deleting the rows destroys the evidence for that claim; leaving them in buries the report.
So findings carry `excluded_from_actionable` and `exclusion_reason`: **kept, countable, and
left out of the work list**, reversibly and with a recorded reason.

`excluded` is not `false_positive`. `false_positive` asserts there is nothing there.
`excluded` asserts only that this row does not belong on a work list — which is the correct
and weaker claim when the scanner never opened the file.

| Rule | Findings | Disposition | Measurement |
|---|---|---|---|
| `whispers` / `comment` | 502,234 | `false_positive`, excluded | 502,234 findings resolve to **1,538 distinct values**. A 120-row random sample (seed `2026-09-14`, `ORDER BY md5(id::text \|\| seed)`) contained **zero** credentials. An exhaustive scan of all 1,538 distinct values for credential-shaped strings surfaced **one** candidate, handled below. |
| `whispers` / `file` | 44,779 | `rotate_secret`, excluded | Matches on filename alone, never on content: for **44,241 (98.8%)** the entire evidence is the file's own path. Not called a false positive, because that would assert 44,779 unread files are clean. |

The `file` rule names 14,559 files that plausibly hold a live credential — 6,553 `.git/config`,
6,318 `.tfvars`, 1,688 `.env`. Those are tracked as a **separate content scan** (`TODO.md` §
Security), not as a classification change. The exclusion is reversible per rule the moment that
scan produces real evidence.

**The one candidate found.** A password-reset token in
`saved from url=(0065)http://localhost:8080/#/password-recovery/…`, 32 findings, repo
`devops-sc-cookbook-recipes`, files `email-password/envs/{15dc,dev,prod}/{password_recovery,validate-login}.html`.
Re-included as actionable with `category_source = 'human'` and `investigation_status = 'triage'`.
It appears under a **prod** environment directory, which is why it is flagged and not closed.

Suppression also runs at ingest (`scripts/maintenance/ingest_scans.py`, `ingest_whispers`).
It **flags and stores**; it does not drop. Dropping at ingest would leave no way to re-derive
the 1,538-distinct-values measurement that justifies the suppression in the first place.

### 2.3 Result over the live corpus

Backfilled 2026-09-14 across all 769,825 findings via `scripts/backfill_rule_identity.py`:

| | Count |
|---|---|
| Findings scanned | 769,825 |
| `rule_id` recovered | 769,825 (100%) |
| Classified by deterministic rule | 769,633 |
| **Left for the model** | **192** |
| Excluded from the work list | 546,981 |
| **Actionable** | **222,844** |

Actionable, by category: `code_change` 125,532 · `upgrade_dependency` 36,473 ·
`configure` 32,047 · `rotate_secret` 28,600 · unclassified 192.

The two denominators reconcile: 222,844 + 546,981 = 769,825, and the category figures sum to
222,844. The exclusion total is 502,234 + 44,779 **− 32**, the 32 being the manually
re-included candidate in §2.2 — which is also why `rotate_secret` reads 28,600 rather than the
28,568 the rules alone produced.

The cost consequence: AI classification is priced against **192 findings**, not 769,825.

---

## 3. Finding Knowledge Base

Global, cross-project, reusable. One entry per unique finding signature, not per occurrence.

### 3.0 Size, measured — the KB is hundreds of entries, not hundreds of thousands

Built against the live corpus 2026-09-14 (`scripts/build_knowledge_base.py`):

| | Count |
|---|---|
| Actionable findings | 222,844 |
| **Distinct KB keys** | **2,639** |
| — advisory (`ghsa:`) keys | 1,158, covering 29,928 findings |
| — scanner rule (`rule:`) keys | 1,481, covering 192,916 findings |
| Findings with no derivable key | **0** |
| Keys occurring exactly once | **0** |

Coverage is extremely concentrated, and this is the fact that makes the KB affordable:

| Entries authored | Actionable findings covered |
|---|---|
| 10 | 50.9% |
| 166 | 80% |
| 979 | 95% |

A single entry — `rule:mobsf:android/Weak Cryptography/Weak Crypto` — covers **55,878
findings, 25.1% of the actionable estate**. The next nine are seven `horusec` rules, one
`whispers` rule and `retirejs/DOMPurify`.

The consequence for §10 and for any cost estimate: authoring priority is by findings covered,
not by entry count, and **coverage must be reported in findings, not in entries**. "12 of 2,639
entries approved" sounds like 0.5% done and may already be more than half the estate.

### 3.0.1 `findings.cwe_id` is unusable, and what replaces it

Across all 769,825 findings the `cwe_id` column holds exactly two values: empty (710,126 rows)
and the literal string **`HorusecEngine`** (59,699 rows). There is not one real CWE identifier
in this database. Horusec's ingest wrote its engine name into the CWE column.

This breaks two things as originally specified:

1. The §3.1 key precedence tier `cwe:` resolves nothing — the same defect `cve:` had.
   `normalize_cwe()` rejects the Horusec string explicitly, because keying on it would create
   one KB entry about nothing that 59,699 findings then point at.
2. **§3.4's TTP chain had no input at all.** CWE → CAPEC → ATT&CK starts at a CWE, and no
   finding carries one.

What closes it: the GitHub advisory API publishes CWEs, and the 1,158 advisory keys are
fetchable. After enrichment the KB carries **158 distinct CWEs** where the findings table
carried zero — so the TTP chain has an input for advisory entries. For the 1,481 scanner-rule
entries there is still no published CWE, and those entries record `mapping_source: none`
with the note `no CWE recorded on the underlying findings`. That is a stated result, not an
unfinished field.

### 3.0.2 Advisory enrichment — fetched, not generated

`src/services/ghsa_enrichment.py`. The local database is missing fields the report needs and
the published advisory has them:

| Field | In `findings` | In the advisory |
|---|---|---|
| `cve_id` | NULL on all 769,825 rows | present |
| `cwe_id` | `HorusecEngine` or empty | a real CWE list |
| `fixed_version` | empty on all 769,825 rows | per affected package |
| EPSS | not collected | present |

Result over all 1,158 advisory keys, one pass, **zero failures**:

| | Count |
|---|---|
| Advisories fetched | 1,158 |
| Carried a CWE | 1,139 |
| Carried a CVE | 1,112 |
| Carried an EPSS score | 1,112 |
| Carried a fixed version | 1,133 |
| Carried a description, imported as the entry summary | 1,158 |
| — of those, long enough to be bounded at 6,000 chars | 76 |
| Withdrawn upstream | 0 |

The `fixed_version` recovery is the consequential one: its absence is what forced the §2.1
rule change and what puts an unmeasured driver in every dependency effort estimate (§5.1).
It is now recoverable for the **29,928 findings** that carry an advisory — not for the
192,916 that carry only a scanner rule, and the report must not imply otherwise.

Everything written by this path is `source = 'import'` with `ai_confidence` NULL and the
`source_url` it came from, so a fetched fact is never countable alongside a generated one.
The fetch is public, free and passive; it sends the `GITHUB_TOKEN` already in the environment
only to `api.github.com` and only to read published advisories, because the anonymous quota is
60 requests an hour against 1,158 advisories. Responses are cached on disk, so a rebuild costs
no requests.

The advisory's own description is imported as the entry `summary`, bounded by the §1.2 excerpt
so a long advisory is cut on a heading boundary and says so rather than trailing off. Where an
advisory carries no description the summary stays NULL: falling back to the one-line title
would dress a headline up as an explanation and the entry would stop looking like it needs
authoring.

**All 2,639 entries are `draft`.** None renders into a report until approved.

#### `source` on an entry nobody has written

The first build labelled its 1,481 placeholder rows `source = 'ai'`. Nothing generated them —
`_stub_summary()` wrote "Knowledge base entry not yet authored" — so anyone counting `ai`
entries was counting 1,481 model outputs that never happened. That is precisely the confusion
`source` exists to prevent, and it appeared in the column's first use.

`KBSource` gains a fourth value, **`unauthored`**: the key exists, the content does not, nobody
wrote it. Advisory rows are created `unauthored` too and are promoted to `import` only when the
fetch actually succeeds. A row is `ai` once a model has written its content, and not before.

Live state after the relabel:

| `source` | Entries | What it means |
|---|---|---|
| `import` | 1,158 | fetched from the published advisory, cited to a URL |
| `unauthored` | 1,481 | a key with a finding count and no content |
| `ai` | 0 | nothing has been generated yet |
| `human` | 0 | nothing has been authored yet |

### 3.1 Key

Composite, first match wins:

1. `ghsa:{ghsa_id}` — e.g. `ghsa:GHSA-4v7x-pqxf-cx7m`
2. `cve:{cve_id}` — e.g. `cve:CVE-2021-23337`
3. `rule:{scanner_name}/{rule_id}` — e.g. `rule:semgrep/python.lang.security.audit.eval-detected`
4. `cwe:{cwe_id}` — e.g. `cwe:CWE-79`

**`ghsa:` was added in front of `cve:` because the original precedence resolved nothing.**
`cve_id` is NULL on all 769,825 findings; grype — the dependency scanner actually in use here —
reports GitHub advisories, and writes the GHSA into the finding title. A precedence starting at
`cve:` falls through to `rule:` on every dependency finding, which keys the KB by scanner rule
rather than by advisory and would split one advisory across scanners.

`rule_id` did not exist on `findings` and is added (§9). Semgrep, Trivy, Checkov and Gitleaks
all emit one; it was discarded at ingest. Six scanners write it only **inside the title string**,
so recovery is parsing, not a column read:

| Scanner | Title shape | Recovered `rule_id` |
|---|---|---|
| `whispers` | `Secret: comment` | `comment` |
| `trufflehog`, `gitleaks` | `Secret found: AzureDevopsPersonalAccessToken` | `AzureDevopsPersonalAccessToken` |
| `horusec` | `(1/1) * Possible vulnerability detected: Hard-coded password` | `Hard-coded password` |
| `retirejs` | `Vulnerable JS Library: DOMPurify 2.4.0` | `DOMPurify` (+ package and version) |
| `mobsf:*` | `[Weak Cryptography] Weak Crypto` | `Weak Cryptography/Weak Crypto` |
| `terrascan`, `semgrep`, `checkov` | title *is* the rule id | verbatim |

`rule_id_is_stable` records whether the recovered value is an identifier or prose. `trivy-fs`
emits a check *sentence* (`Storage account should have infrastructure encryption enabled`) —
usable as a key today, rewordable by an upstream release tomorrow. Keying a KB entry to prose
without recording that it is prose is how the KB silently loses its links on a scanner upgrade.

The retirejs title is the only surviving record of package and version anywhere in the row, so
the backfill writes those two fields from it — but only behind an explicit
`--with-retirejs-packages` flag and only into columns that are currently NULL, so it can never
overwrite something ingest recorded.

### 3.2 Table `finding_knowledge_base`

| Column | Type | Note |
|---|---|---|
| `id` | UUID pk | |
| `kb_key` | String unique | as §3.1 |
| `key_type` | String | `cve` \| `rule` \| `cwe` |
| `cve_id`, `cwe_id`, `rule_id`, `scanner_name` | String, nullable | whichever apply |
| `title` | Text | |
| `reference_ids` | JSONB | `[{type, id, url}]` — CVE, CWE, GHSA, CAPEC, ATT&CK, vendor advisory |
| `target_asset_type` | String | `dependency` \| `source_file` \| `iac_resource` \| `secret` \| `api_endpoint` \| `container_image` |
| `target_asset_detail` | Text | what the finding is *against*, in words |
| `blast_radius` | JSONB | §3.3 |
| `ttp` | JSONB | §3.4 |
| `exploitability` | JSONB | `{kev_listed, epss_score, epss_percentile, has_public_exploit, source, observed_at}` — passive OSINT, §7 |
| `mitigation_options` | JSONB | §3.5 |
| `status` | String | `draft` \| `approved` \| `deprecated` |
| `version` | Integer | incremented on approved edit |
| `source` | String | `ai` \| `human` \| `import` |
| `ai_confidence` | Numeric(3,2) | null when human-authored |
| `approved_by`, `approved_at` | UUID, DateTime | |
| `created_at`, `updated_at` | DateTime | |

Only `status = 'approved'` entries render into a report. Drafts are visible in the UI with a
badge, and a report generated while an entry is still draft prints
`knowledge base entry pending review` in that row rather than the draft text.

`finding_kb_version` mirrors `PromptVersion`: full snapshot per version, so an old report can be
re-rendered against the KB as it stood.

### 3.3 Blast radius — exploitation, not regulatory

```json
{
  "impact_class": "rce",
  "summary": "Attacker-controlled input reaches a deserializer running as the application user.",
  "attacker_gains": ["code execution in the application container", "access to the pod service account token"],
  "reachable_assets": ["application database via existing connection string", "internal service mesh"],
  "preconditions": ["endpoint reachable without authentication", "vulnerable version deployed"],
  "requires_adjacent_access": false
}
```

`impact_class` enum: `rce` · `data_exposure` · `auth_bypass` · `privilege_escalation` ·
`lateral_movement` · `dos` · `supply_chain` · `information_disclosure`.

> **Naming collision, deliberate.** `sec-diligence` has a `blast_radius.py` that computes
> *regulatory* blast radius (finding → clause → NIST 800-53 → HIPAA cite). That is a different
> thing. This field is what an attacker gets. Regulatory blast radius, if wanted later, is
> fetched by calling sec-diligence, not by copying its crosswalk into this repo.

### 3.4 TTP — deterministic mapping

```json
{
  "capec": [{"id": "CAPEC-586", "name": "Object Injection"}],
  "attack_tactics": [{"id": "TA0002", "name": "Execution"}],
  "attack_techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
  "mapping_source": "cwe_capec_attack",
  "mapping_note": null
}
```

Chain: `CWE → CAPEC` (MITRE-published `CWE → CAPEC` relationships) `→ ATT&CK` (CAPEC's
`taxonomy_mappings`). Both are public, versioned, offline data files committed to the repo.

`mapping_source` values: `cwe_capec_attack` | `curated` | `none`.

When no published mapping exists, `mapping_source` is `none`, the arrays are empty, and the
report prints **"no published CWE→CAPEC→ATT&CK mapping"**. The model is never asked to supply a
technique ID. It may only write prose *about* techniques already present in the mapping.

**Reachability of this chain, measured.** The CWE input does not come from `findings` — see
§3.0.1, there is none there. It comes from advisory enrichment, which means:

| KB entries | CWE available? | Findings covered |
|---|---|---|
| 1,139 advisory entries | yes — 158 distinct CWEs | 29,928 (13.4% of actionable) |
| 19 advisory entries | advisory published no CWE | — |
| 1,481 scanner-rule entries | **no** | 192,916 (86.6% of actionable) |

So the TTP section can be populated for about **one finding in eight**, and `mapping_source:
none` is the majority outcome by a wide margin. A report that renders ATT&CK technique IDs
across this estate without saying that would be describing an eighth of it. The briefing
document states this in its own vocabulary, per the coverage-limits rule.

Closing the gap for scanner rules needs a per-scanner rule→CWE mapping table. Semgrep and
Checkov publish one in rule metadata that ingest discards; Horusec, MobSF and Whispers — which
between them are the four largest entries in this KB — do not publish one at all. That is an
authoring task, not a fetch, and it is not in P2.

### 3.5 Mitigation options

```json
[
  {
    "remediation_category": "upgrade_dependency",
    "stack": "node",
    "summary": "Upgrade lodash to 4.17.21.\nNo API changes between 4.17.x releases.",
    "steps": ["npm install lodash@4.17.21", "npm audit", "run test suite"],
    "is_breaking": false,
    "removes_finding": true
  },
  {
    "remediation_category": "compensating_control",
    "stack": "any",
    "summary": "Where the upgrade is blocked, restrict which input reaches the merge call.\nDetection only; the vulnerability remains present.",
    "steps": ["..."],
    "is_breaking": false,
    "removes_finding": false
  }
]
```

`stack` is matched against the repository's detected stack (`LanguageStat`, `Dependency`
ecosystem, `RepositoryOperations.iac_type`). Options whose stack does not apply are not shown.

### 3.6 Per-organization overlay

`finding_kb_org_overlay`: `(kb_id, organization_id)` unique, carrying replacement or additional
`mitigation_options` and `notes`. The global entry stays generic; local standards live in the
overlay. Report merges overlay over global and labels any overlaid row as organization-specific.

### 3.7 KB API

Read endpoints are open to any authenticated user, since the content is generic:

```
GET    /api/v1/kb                     list, filter by key_type, status, cwe, cve, scanner
GET    /api/v1/kb/{kb_key}            single entry, merged with caller's org overlay
GET    /api/v1/kb/{kb_key}/versions   version history
POST   /api/v1/kb                     create draft            (kb:write)
PATCH  /api/v1/kb/{id}                edit draft              (kb:write)
POST   /api/v1/kb/{id}/approve        draft → approved        (kb:approve)
PUT    /api/v1/kb/{id}/overlay        org overlay upsert      (kb:overlay, org-scoped)
```

---

## 4. Remediation actions — the grouping unit

Forty `lodash` CVEs are one `npm upgrade`, not forty units of work. The action is what gets
estimated, reported and pushed to AuditBoard.

### 4.1 Action key

Deterministic signature so the same work groups identically on every run. Implemented in
`src/services/remediation_grouping.py`.

| Category | Key shape | Example |
|---|---|---|
| `upgrade_dependency` | `upgrade:{ecosystem}:{package}:{target_version}` | `upgrade:npm:lodash:4.17.21` |
| `upgrade_dependency`, package unknown | `upgrade:advisory:{ghsa\|cve}` | `upgrade:advisory:ghsa-4v7x-pqxf-cx7m` |
| `rotate_secret` | `rotate:{rule_id}:{repository_id}:{normalized_path}` | `rotate:AWSAccessKey:r1:app/config.yml` |
| `configure` | `configure:{rule_id}` | `configure:CKV_AWS_18` |
| `code_change` | `code:{rule_id}` | `code:semgrep/python.lang.security.audit.eval-detected` |
| `patch` | `patch:{cve_id}` | `patch:CVE-2024-3094` |
| others | `{category}:{kb_key}` | |
| any, when the fields above are absent | `{category}:{scanner_name}:{rule_id}` | fallback |

Two constraints on the fallback, both load-bearing:

**It never falls back to the finding id.** `package_name` is empty across this estate, so a
naive fallback would emit one action per finding and render 36,473 dependency findings as
36,473 units of work. That is not a large backlog; it is a missing column, and the report must
not present the second as the first. The advisory-keyed shape above exists for exactly this
case.

**Secrets group narrowly, on purpose.** No secret value or hash is stored anywhere in this
schema, so two findings from one detector are two different credentials until something proves
otherwise. Grouping them by `{rule_id}` alone would mean an engineer rotates one key, closes
the action, and the other credential stays live. The key therefore includes repository and file
path: same credential at the same location collapses across re-scans, different locations stay
separate.

**Path normalization is a prerequisite, not a nicety.** About three quarters of `file_path`
values point into an ephemeral checkout directory (`/tmp/repo_scan_8f3a/…`,
`/var/folders/…/repo-scan…/…`) that no longer exists. Unnormalized, the same file scanned twice
produces two different paths — so `files_count` (an effort driver, §5.1) changes between two
scans of identical code, and the secret keys above never collapse. `normalize_file_path()`
strips the scan root and returns a repo-relative path; a path it does not recognize is returned
unchanged rather than mangled into something that looks authoritative.

### 4.2 Scope

`per-org` is the default (decision 21). One action spans every repository in the organization
carrying that finding, which is what actually saves engineering time. `per-repo` is selectable
in the wizard for a single-repo report.

### 4.3 Table `remediation_action`

| Column | Type | Note |
|---|---|---|
| `id` | UUID pk | |
| `organization_id` | UUID fk | |
| `action_key` | String | §4.1 |
| `scope` | String | `org` \| `repository` |
| `repository_id` | UUID fk, nullable | set when `scope = 'repository'` |
| `remediation_category` | String | §2 enum |
| `kb_id` | UUID fk, nullable | |
| `title`, `summary` | Text | `summary` is the two-liner |
| `detail` | Text | full steps |
| `findings_count`, `repositories_count`, `files_count` | Integer | effort drivers, §5 |
| `has_fixed_version`, `is_breaking_change` | Boolean | effort drivers |
| `primary_role` | String | effort driver |
| `supporting_roles` | JSONB | |
| `technology` | JSONB | named, not defined — §5.2 |
| `effort_band` | String | `S` \| `M` \| `L` \| `XL` |
| `effort_score` | Integer | the number the band was cut from; kept so the band is checkable |
| `effort_reasons` | JSONB | which drivers produced the band |
| `effort_unknowns` | JSONB | which drivers could **not** be measured — §5.3 |
| `max_severity` | String | |
| `aggregate_risk_score` | Integer | |
| `status` | String | `open` \| `in_progress` \| `done` \| `accepted` |
| `auditboard_issue_id` | BigInteger, nullable | idempotency, §13 |
| `auditboard_instance` | Text, nullable | which AuditBoard an id belongs to; an id is meaningless without it |
| `auditboard_push_status` | String, nullable | `never` \| `dry_run` \| `pushed` \| `failed` |
| `auditboard_pushed_at` | DateTime, nullable | |
| `created_at`, `updated_at` | DateTime | |

Deliberately absent: **no `effort_hours` column, in any unit** (§5), and **no
`auditboard_status`** — AuditBoard's own workflow state is authoritative there, and a local
copy of it is a cache that goes stale silently and gets reported as fact.

As built: `migrations/versions/024_add_remediation_actions.py`, tables `remediation_actions`
and `remediation_action_findings`.

Unique on `(organization_id, action_key, scope, repository_id)`.

`remediation_action_finding` is the one-to-many join: `(action_id, finding_id)` unique.

---

## 5. Effort — refer, do not define

> Decision 3. The report states what is measurable and bands the rest. It does not assert
> "4 hours", because an hour count is not derivable from anything in this database and would
> violate prove-it-or-do-not-report-it.

### 5.1 Drivers — all measured, all queryable

| Driver | Source | Provable? | State in this estate |
|---|---|---|---|
| `findings_count` | count of joined findings | yes | measured |
| `repositories_count` | distinct `repository_id` across joined findings | yes | measured |
| `files_count` | distinct **normalized** `file_path` (§4.1) | yes | measured |
| `has_fixed_version` | `Finding.fixed_version is not null` | yes | **false on every row** — an ingest defect, scored as an unknown, not as "no upgrade needed" |
| `is_major_upgrade` | semver major delta between `package_version` and `fixed_version` | yes | three-state: `True` / `False` / `None` when either version is absent or unparseable (`latest`, `*`) |
| `is_transitive` | dependency depth | yes when recorded | frequently unrecorded |
| `environments` | §8 deployment resolution | yes | measured where resolved |
| `primary_role` | derived from category (table below) | derived, stated as such | derived |
| `technology` | §5.2 | yes | measured |

Role derivation: `upgrade_dependency`/`code_change`/`remove_dependency` → `developer`;
`configure`/`infra_control` → `devops`; `rotate_secret` → `security` + `devops`;
`access_control` → `security`; `patch` → `devops`; `compensating_control` → `security`;
`accept_risk`/`false_positive` → `product_owner`.

### 5.2 Technology — named, never defined

`technology` lists what the fix touches, drawn from data already held:

```json
{
  "languages": ["TypeScript", "Python"],
  "ecosystems": ["npm"],
  "iac": ["terraform"],
  "cicd": ["github_actions"],
  "hosting": "azure"
}
```

Sources in order: `LanguageStat`, `Dependency.ecosystem`, `RepositoryOperations.iac_type`,
`CICDPipeline.platform`, `RepositoryOperations.hosting_platform`. No new taxonomy is invented,
and no judgement about difficulty is attached to any of these values.

### 5.3 Band

A committed, testable pure function of the drivers — not a model call, so it is reproducible.
Implemented as an additive score in `src/services/effort.py`, cut into bands at fixed
thresholds: `score ≤ 3 → S`, `≤ 6 → M`, `≤ 10 → L`, else `XL`.

A score rather than the prose ruleset this section previously carried, for one reason: prose
rules with `or` in them are unorderable. "Breaking change, **or** >5 repositories" gives the
same band to a one-line patch across six repos and to a major-version jump in one, and there is
no way to express that having both is worse than having either. A score adds.

Two category floors override the score upward:

- `rotate_secret` scores **at least 4**. One exposed credential is still revoke, reissue,
  redeploy every consumer, and purge git history — a coordinated, outage-risking operation
  whose cost does not scale down to the single finding that triggered it.
- `remove_dependency` scores **at least 6**. Replacing a component is never small.

**Unknowns are scored as cost, never as zero.** An unmeasured driver — no fixed version, an
unparseable target version, unrecorded transitivity — adds to the score and is recorded by
name in `effort_unknowns`. Scoring a missing measurement as zero makes every estimate
optimistic by construction, and makes the worst-understood work look like the cheapest.
`is_major_upgrade` is three-state for the same reason: `None` is not `False`.

`band_label()` always renders the word **estimated**, and appends *"incomplete inputs"* when
`effort_unknowns` is non-empty, so a band built on missing data cannot be quoted as though it
were built on measurements.

**Severity does not enter the score.** Severity drives priority; conflating the two is how
"critical" comes to mean "hard", and how a one-line config change gets budgeted like a rewrite.
There is a test asserting this.

Bands are never summed into a project total that implies a schedule. The report sums the
*drivers* (findings, repositories, files) — those are counts, and counts are provable.

---

## 6. Contributor timeline

### 6.1 New columns on `contributors`

| Column | Type | Note |
|---|---|---|
| `first_commit_at` | DateTime | measured from `git log`, not inferred |
| `active_months` | JSONB | `{"2024-03": 12, "2024-04": 3, ...}` commits per month |
| `dormant_since` | DateTime, nullable | `last_commit_at` when ≥90 days ago |
| `timeline_source` | String | `git_log` \| `github_api` \| `not_collected` |

### 6.2 Collection

Repositories are already cloned by `execution/clone_repo.py`. One pass per scan:

```
git log --all --no-merges --format='%aI%x09%aE%x09%aN'
```

Bucketed by author email into months. Costs no GitHub API quota. Runs once as a backfill, then
incrementally per scan using `last_commit_sha` as the boundary.

Authors are then resolved to `ContributorProfile` through `ContributorAlias`, so "Rob Vance"
appearing under three email addresses is one line on the timeline, not three.

### 6.3 Rendering

Per repository: a monthly band per contributor profile, with first commit, last commit, commit
count, share of total, and current state (`active` / `dormant since {date}` / `departed`, the
last only where `ContributorProfile.employment_status` says so).

Repository status is derived and labelled: `active` (commit within 90 days), `slowing`,
`dormant` (no commit in 365 days), `archived` (`Repository.is_archived`).

**Coverage limit, printed in the report:** a `git log` timeline shows who committed, not who
reviewed, approved, or currently owns the repository. Where `RepositoryOperations.team_owner`
is null, the report prints `owner not recorded` rather than naming the most recent committer as
the owner.

---

## 7. OSINT — passive and free only

Decision 9: both internal and external, **no paid sources, nothing that sends traffic to a
discovered application**.

### 7.1 Allowed in v1

| Source | What it gives | Cost |
|---|---|---|
| DNS resolution (A/AAAA/CNAME/MX/TXT) of already-known hostnames | whether a declared environment URL still resolves, and to where | free |
| Certificate Transparency (crt.sh) | subdomains and certificates issued for the org's domains | free |
| npm / PyPI / Maven / NuGet registry metadata | package existence, maintainer count, deprecation, last publish | free |
| OSV.dev | vulnerability records per package version | free |
| CISA KEV | whether a CVE is known-exploited | free |
| FIRST EPSS | exploitation probability score | free |
| GitHub public metadata | already collected | free |

### 7.2 Explicitly excluded in v1

- Any HTTP request to a discovered dev/qa/stage/prod URL. **This is the boundary that matters.**
  Probing those URLs sends real traffic to your own production systems, and it is off.
- Shodan, Censys, breach and credential-leak databases — paid, and out of scope by decision.
- Port scanning, subdomain brute-forcing, or anything that generates traffic to a host.

Each collection writes an `osint_observation` row with `source`, `observation_type`, `value`,
`evidence` JSONB, `collected_at`, `confidence`, and `is_passive = true`.

**Coverage limit, printed in the report:** passive collection proves presence, not absence. "No
certificate found for `x.example.com`" means CT logs carry no record — not that the host does
not exist. Closing that gap requires an active probe, which is deliberately not enabled.

---

## 8. Deployment resolution

### 8.1 Precedence

```
observed   Deployment + DeploymentTarget          (CI/CD actually deployed it)
   >
mapped     RepoDeploymentMap                      (inferred, carries confidence + evidence)
   >
declared   RepositoryOperations.environment_urls  (AI-discovered or human-entered)
```

### 8.2 New column

`repo_deployment_map.url` (String 512), plus `url_source` and `url_confidence`. Confirmed in
decision 6.

### 8.3 Rendering

Every row prints: `environment` · `url` · `source` · `confidence` · `last_observed_at`.

A repository with no resolvable environment prints:

```
unresolved — no deploy workflow found in .github/workflows and no observed Deployment rows
```

Never blank, never omitted. `RepoDeploymentMap.is_resolved = false` already carries
`unresolved_reason`; that string is what renders.

Where resolution is blocked by access rather than by absence, the report names the exact
privilege: e.g. *"GitHub Actions deployment history requires `actions:read` on the repository;
the configured credential holds `contents:read` only."* A silent zero is never printed for an
access gap.

---

## 9. Schema changes

Migrations `023` through `029`, following the existing numbered convention
(`migrations/versions/0NN_*.py`, `revision = '0NN'`, `down_revision = '0NN-1'`).

| # | Migration | Contents |
|---|---|---|
| 023 | `add_finding_rule_identity_and_category` | `findings`: `rule_id`, `rule_id_is_stable`, `ghsa_id`, `remediation_category`, `category_source`, `category_confidence`, `category_rationale`, `category_assigned_at`, `excluded_from_actionable`, `exclusion_reason` + 5 indexes — **applied** |
| 024 | `add_remediation_actions` | `remediation_actions`, `remediation_action_findings` — **written, not yet applied** |
| 025 | `add_finding_knowledge_base` | `finding_knowledge_base`, `finding_kb_versions`, `finding_kb_org_overlays` — **applied** |
| 026 | `add_contributor_timeline` | `contributors`: `first_commit_at`, `active_months`, `dormant_since`, `timeline_source` |
| 027 | `add_deployment_url` | `repo_deployment_map`: `url`, `url_source`, `url_confidence` |
| 028 | `add_report_runs` | `report_run`, `report_template` |
| 029 | `add_osint_and_auditboard` | `osint_observation`, `auditboard_sync_log` |

Each migration's docstring states what it implements and what it deliberately does not migrate,
matching the style set by `022_add_organization_credentials.py`.

### 9.0 Operational warning: migrations do not reach the live database

**The `security_portal` database has no `alembic_version` table.** Its schema comes from
`models.Base.metadata.create_all(bind=engine)` at `src/api/main.py:243`, which creates missing
*tables* but **never adds a column to a table that already exists**. So for any migration in
the table above that only adds columns — 023, 026, 027 — writing the migration and adding the
model field produces a system that starts cleanly, passes its imports, and then fails at the
first write to the new column.

Until that divergence is resolved, every column-adding migration needs a matching idempotent
DDL path that an operator actually runs. 023's is
`scripts/backfill_rule_identity.py --apply-schema`: it reads `information_schema.columns`, adds
only what is absent, and creates indexes with `CREATE INDEX CONCURRENTLY IF NOT EXISTS` after
an explicit `COMMIT`, because `CONCURRENTLY` cannot run inside a transaction. Re-running it is
a no-op.

This is a defect in the deployment story, not a design choice, and it should be closed by
stamping the live database and adopting Alembic properly. It is recorded here because a reader
of §9 would otherwise reasonably assume the migration list is sufficient.

Table names as built are plural (`remediation_actions`, `remediation_action_findings`),
matching the existing convention in `src/api/models.py`; earlier singular names in §4.3 have
been corrected.

### 9.1 `report_run`

| Column | Type | Note |
|---|---|---|
| `id` | UUID pk | |
| `organization_id`, `repository_id` | UUID fk | `repository_id` null for org-scope runs |
| `template_id` | UUID fk, nullable | → `report_template` |
| `prompt` | Text | free text from the wizard |
| `spec` | JSONB | selected data points, filters, audience, formats |
| `audience` | String | `leadership` \| `technical` \| `both` |
| `status` | String | `pending` \| `running` \| `succeeded` \| `failed` \| `cancelled` |
| `progress_pct`, `progress_stage` | Integer, String | polled by the wizard |
| `error_message` | Text | |
| `figures` | JSONB | **every number in both documents** — §10.2 |
| `artifacts` | JSONB | `[{kind, format, object_key, bytes, sha256}]` |
| `coverage_limits` | JSONB | `[{area, limit, privilege_that_closes_it}]` |
| `ai_provider`, `ai_model`, `token_usage` | String, String, JSONB | |
| `requested_by` | UUID fk | |
| `started_at`, `completed_at`, `created_at` | DateTime | |

### 9.2 `report_template`

`id`, `organization_id`, `name`, `description`, `spec` JSONB, `prompt_id` FK → `prompts`,
`is_shared` Boolean, `created_by`, timestamps.

Decision 11: the prose half reuses `prompts` + `prompt_versions` so wizard prompts get the same
versioning, usage tracking and audit log as every other prompt in the product. Only the
data-point selection lives in `spec`.

---

## 10. Generation pipeline

### 10.1 Job execution — the honest limit

There is **no queue in this stack**. No Celery, no RQ, no arq. The only async primitive in the
API is FastAPI `BackgroundTasks`, and the established pattern for long AI work is the
`RepositoryOpsDiscovery` status row that the client polls.

This spec follows that pattern: `report_run` is created `pending`, a `BackgroundTasks` handler
moves it to `running` and updates `progress_pct` / `progress_stage`, and the wizard polls
`GET /api/v1/report-runs/{id}`.

**What this does not give you:** an API restart loses in-flight runs. They will show `running`
forever until a janitor marks them `failed`. That is acceptable for v1 — a report can be
re-requested — and it is written down rather than discovered later. Closing it properly needs a
durable queue; Redis is already in the compose stack, so RQ or arq is a small addition when it
becomes worth doing.

### 10.2 Stages

| Stage | What runs | AI involved? |
|---|---|---|
| 0. Preface source | If `repositories.architecture_report` is empty, call `POST /api/v1/ai/architecture` for this repo, persist it and write an `architecture_versions` row. If it is already populated, reuse it — this stage is a no-op on the second run. | yes, first time only |
| 1. Figures | Deterministic SQL for every count, total and breakdown. Written to `report_run.figures`. | no |
| 2. Grouping | Findings → remediation actions (§4). Effort drivers + band computed (§5). | no |
| 3. KB join | Each action pulls its approved KB entry, merged with the org overlay. | no |
| 4. Narrative | Model receives `figures` as read-only context and the user's prompt. Writes prose, chooses and orders sections. | yes |
| 5. Validation | §10.3 | no |
| 6. Render | Markdown → PDF / DOCX via `src/reporting`. | no |
| 7. Persist | Artifacts to MinIO, hashes and keys to `report_run.artifacts`. | no |

Stage 0 is the expensive one and the only stage whose cost depends on prior state: it clones and
analyses source. Measured today, it would fire for 2,538 of 2,540 repositories, and for 701 of
the 703 that have actionable findings. Two things follow. **Run the backfill before the wizard
ships**, over the 703, so the common path is a cache read. And **stage 0 failing does not fail
the run** — the preface prints that architecture could not be generated and names the reason,
because a report whose findings are all correct should not be withheld over its opening section.
The report body never infers architecture from the GitHub description; a description is a
description.

### 10.3 Figure validation — the enforcement of "one set of figures"

After stage 4 and before stage 6, every numeral in the generated prose is extracted and checked
against `report_run.figures`. A numeral that is not present in `figures`, and is not on a short
allowlist (dates, section numbers, version strings, CVE and CWE identifiers), **fails the run**.

This is the mechanism that makes decision 8 real. The model may frame, order and explain. It may
not produce a number. If it does, the run fails loudly rather than shipping a figure nobody can
trace.

### 10.4 Output — the report pair

Decision 9. One run at audience `both` emits three artifacts:

| Artifact | Audience | Content |
|---|---|---|
| `{repo}-briefing.md` | leadership | No technical background assumed. Sections in the required order: what are we talking about / what is the problem / what happens if we don't fix it / are there benefits beyond this / what is involved in resolving it / what we are not claiming. Names the companion file. |
| `{repo}-companion.md` | technical | What is the problem / where is the problem / how do we address it. Every location by an identifier the owner acts on. Findings needing different fixes counted separately. |
| `{repo}-appendix.md` | both | **Generated from the query results, not written.** Every finding, every remediation action, every location by name. States what it deliberately omits. |

Markdown is the source of truth. PDF and DOCX are build products from the committed renderers
and are produced in the same run.

Both documents draw from the same `report_run.figures`. The briefing never rounds a number to
read more cleanly, and every figure in it is derivable from the companion. `coverage_limits`
renders into the briefing in the briefing's own vocabulary — "no evidence of X" written out as
not the same claim as "X did not happen".

---

## 11. Wizard

`/projects/[id]` gains a **Reports** tab. The existing "Security report" button and
`SecurityReportModal` are removed as a separate entry point and become preset #1 inside the
wizard (decision 14 — fold).

### 11.1 Steps

**1 — Preset or blank.** Presets: *Security assessment* (the current modal's behaviour),
*Remediation plan* (the report described in this spec), *Repository profile*, *Blank*. Saved
org templates appear alongside.

**2 — Audience.** Leadership · Technical · Both. Default **Both**.

**3 — Prompt.** Free text: what kind of report, for whom, what to emphasise. Placeholder shows a
worked example. A note below the field states plainly that the prompt shapes wording and section
order, and that all figures come from the data regardless of what the prompt asks for.

**4 — Data points.** Checkbox tree:

- **Repository profile** — creation date, purpose/description, topics, language mix, size, license, visibility, archived state
- **Architecture** — narrative, diagram, component analysis
- **Findings** — totals by severity, by remediation category, by severity × category, by scanner, by status
- **Remediation actions** — grouped actions, effort drivers, effort band, KB detail (blast radius, TTP, mitigation options)
- **Contributors** — timeline, first/last commit, activity bands, current maintainer, employment status *(PII toggle, §12)*
- **Deployment topology** — environments, URLs, source, confidence, unresolved reasons
- **OSINT (passive)** — DNS, CT, registry metadata, KEV/EPSS
- **Dependencies / SBOM**
- **API surface** — endpoints, OpenAPI spec

**5 — Scope and filters.** Severity floor, finding types, status, date range, grouping scope
(**per-org** default, per-repo selectable).

**6 — Output.** Formats (MD always; PDF, DOCX optional). Optional: save as template. Optional:
**push remediation actions to AuditBoard** — which opens §8's dry-run flow, never firing
directly from this step.

**Generate** → `report_run` created → progress panel (stage + percent) → artifacts list with
per-format download. Past runs list below, newest first, each re-downloadable and re-runnable.

---

## 12. Security, RBAC and privacy

New permissions: `report:generate`, `report:read`, `kb:write`, `kb:approve`, `kb:overlay`,
`auditboard:write`.

- Generation requires access to the repository, enforced through the existing
  `UserRepositoryAccess` / `UserOrganizationAccess` path. An org-scoped run covers only
  repositories the requester can already see, and the report states how many repositories were
  excluded for access reasons — a count, never a silent narrowing.
- **Contributor PII toggle**, default **off**. When off, contributor sections render role and
  activity shape without names, emails, Entra identifiers or employment status. When on, the
  run is recorded in `AuthAuditLog` with the requester and the repositories covered.
- Every generation is logged regardless of the toggle.
- Reports contain deployment URLs and, optionally, personal data. Artifacts are stored in MinIO
  under keys scoped by organization, and download goes through the API with the same permission
  check as generation — never a public bucket URL.

---

## 13. AuditBoard integration

### 13.1 What is known, and what is not

**Known — read path, proven in code.** `~/Documents/sec-diligence/backend/app/services/auditboard.py`
calls `GET {base}/api/v1/issues` with `Authorization: Bearer …` against
`https://sleepnumber.auditboardapp.com`, paginates on `limit`/`page`, and reads
`data["issues"]` and `data["meta"]["total"]`. Severity arrives as
`issue_rating_id` / `deficiency_level_id` in `1..4` mapping to low/medium/high/critical.

**Not known — write path.** No create call exists in either project. This spec therefore treats
`POST /api/v1/issues` as **unverified**. Before any of §13.3 is built:

1. Confirm the token carries write scope.
2. Confirm the create endpoint, its required fields, and its response shape.
3. Confirm which parent audit or entity new issues attach to.

Step 1 is a single dry-run POST against a disposable record, approved by you (decision 2a).
Until it passes, §13.3 ships behind a feature flag that is off.

> **Security requirements, stated plainly and not abbreviated.**
> The existing sec-diligence client calls `httpx.AsyncClient(verify=False)`, disabling TLS
> certificate verification against your corporate GRC system. That is not carried into AuditGH;
> the client here verifies certificates.
> Creating records in AuditBoard is outward-facing and hard to reverse — a bad run leaves real
> issues assigned to real people. Push therefore defaults to dry run, requires the
> `auditboard:write` permission, and requires an explicit confirmation naming the number of
> issues and the target instance before anything is sent.

### 13.2 Credentials

Stored in AuditGH's own `organization_credentials` table as credential type `auditboard_api`,
Fernet-encrypted by `src/api/secrets_store.py`, seeded once by an operator. The container has no
mount to `~/Documents/sec-diligence`, so reading that `.env` at runtime is not an option and is
not attempted.

The credential row records its privilege level and known access gaps, as `022` established — so
a failed push can state *which* scope was missing rather than reporting a generic error.

### 13.3 Push contract

One AuditBoard issue per `remediation_action`, org-scoped by default (decision 8). One-to-many:
the issue covers every finding joined to that action, across every repository.

| AuditBoard field | Source |
|---|---|
| `title` | `remediation_action.title` |
| `description` | `summary` (two-liner) + blast radius + TTP + the generated findings table |
| rating | reverse of the read map — `critical → 4`, `high → 3`, `medium → 2`, `low → 1`, from `max_severity` |
| owner | **mandatory wizard input.** No default, no inference. The push is blocked until one is chosen. |
| parent audit / entity | per-org setting `auditboard_default_parent`. If unset, push is blocked with a message naming the setting. |
| external reference | AuditGH `remediation_action.id` and a deep link back to the action |

The findings table embedded in the description is generated, one row per finding: repository,
file path, line, severity, finding ID, and a link back into AuditGH.

**Idempotency.** `remediation_action.auditboard_issue_id` is written on first successful push.
A re-run with a value present issues a `PATCH` rather than a `POST`, so regenerating a report
never duplicates issues.

**Direction.** One-way, AuditGH → AuditBoard, in v1 (decision 2d). Closing an issue in
AuditBoard does not close findings here. Two-way sync is a later decision, not an oversight.

**Audit.** Every attempt — dry run and live — writes an `auditboard_sync_log` row with mode,
redacted request payload, response status, response body, resulting issue ID, and the user who
performed it.

---

## 14. Phasing

Each phase is independently shippable and independently useful.

| Phase | Contents | Unblocks |
|---|---|---|
| **P1** ✅ | Taxonomy enum, `rule_id` recovery and ingest, rule-based classification, suppression, remediation actions, grouping, effort drivers and bands | everything below |
| **P2** ◑ | Knowledge base: schema, key derivation, advisory enrichment **(done)**; CWE→CAPEC→ATT&CK data files, draft/approved workflow, org overlay, KB API and UI **(not started)** | richer report content |
| **P3** | Contributor timeline backfill (`git log`), deployment resolution precedence, `repo_deployment_map.url` | repo profile section |
| **P4** | `report_run`, generation pipeline, figure validator, report pair + generated appendix, renderers, Reports tab and wizard | the deliverable |
| **P5** | Passive OSINT collectors, `osint_observation` | exposure section |
| **P6** | AuditBoard: verify write path, credential wiring, dry run, push, sync log | filing |

P1 first, and not negotiable as an order: the taxonomy and the action grouping are what every
other phase reads from. Building the wizard before them would mean a wizard with nothing to
select.

**P1 status — complete 2026-09-14.** Delivered:

| Artifact | Path |
|---|---|
| Taxonomy, roles, two-line text | `src/api/constants/remediation.py` |
| Rule recovery, classification, suppression | `src/services/remediation_classifier.py` |
| Action grouping, path normalization | `src/services/remediation_grouping.py` |
| Effort drivers and bands | `src/services/effort.py` |
| Schema | `migrations/versions/023_*.py`, `024_*.py`, `src/api/models.py` |
| Backfill + idempotent DDL | `scripts/backfill_rule_identity.py` |
| Reproducible sampling | `scripts/sample_findings.py` |
| Tests | `tests/test_remediation_taxonomy.py` — 42, passing |

Results are in §2.3. The AI fallback in the P1 row is **specified but not built**: the
deterministic rules left only 192 findings unclassified, so the model pass moved behind the
knowledge base in priority. It is not a gap that blocks P2; it is 192 rows carrying
`category_source = 'none'`, which is visible and countable rather than silently miscategorized.

Tests and scripts run **inside the `auditgh_api` container** — the host Python environment has
a pydantic/pydantic-core version mismatch that breaks collection before any test executes.

**P2 status — first slice complete 2026-09-14.** Delivered:

| Artifact | Path |
|---|---|
| KB vocabulary (closed sets) | `src/api/constants/kb.py` |
| Key derivation | `src/services/kb_key.py` |
| Advisory enrichment | `src/services/ghsa_enrichment.py` |
| Schema | `migrations/versions/025_*.py`, 3 models in `src/api/models.py` |
| Build + enrich script | `scripts/build_knowledge_base.py` |
| Tests | `tests/test_kb_key_and_enrichment.py` — 22, passing (64 with P1) |

In the database: 2,639 entries, all `draft`; 1,158 advisory entries enriched with zero
failures. Results in §3.0–§3.0.2.

**Not built, and the order they should be built in:**

1. **Approval workflow and the KB API (§3.7).** Nothing can render until entries are approved,
   and right now nothing can be approved — there is no endpoint. This blocks P4 outright.
2. **Authoring the top entries.** Ten entries reach half the estate; the content is the
   deliverable, and the schema without it is empty furniture.
3. **CWE→CAPEC→ATT&CK data files (§3.4).** Now has an input for 13.4% of actionable findings.
4. **Org overlay write path and KB UI.** Table exists; no API, no UI.

---

## 15. What this specification does not claim

- **AuditBoard write capability is unverified.** Read is proven in existing code. Create is not.
  Until the dry-run POST in §13.1 succeeds, no claim is made that AuditGH can file issues.
- **Effort bands are estimates, not measurements.** The drivers behind them are measured; the
  band is a documented function of those drivers, and the function is a judgement. No hour count
  is asserted anywhere, and bands are never summed into anything resembling a schedule.
- **CWE→CAPEC→ATT&CK coverage is partial, and more partial than this section first assumed.**
  The original limit was that some CWEs lack a CAPEC mapping. The measured limit is earlier in
  the chain: **86.6% of actionable findings have no CWE at all** to begin the mapping from, and
  the CWEs that do exist were fetched from advisories rather than read from the scan data
  (§3.0.1). Unmapped findings print as unmapped, and the mapped-versus-unmapped count is
  reported rather than hidden.
- **The knowledge base is empty of authored content.** 2,639 entries exist; all are `draft`,
  and a draft never renders. The advisory fields in 1,158 of them are fetched fact, but blast
  radius, mitigation options and the TTP chain — the parts a reader would call "the knowledge"
  — are not written yet. A report generated today would print "knowledge base entry pending
  review" for every finding.
- **Passive OSINT proves presence, not absence.** No certificate in CT logs is not evidence that
  a host does not exist. Closing that gap requires an active probe, which is deliberately off.
- **AI-assigned categories are not measurements.** The split between rule-matched and
  AI-inferred is reported separately for exactly this reason.
- **The job runner is not durable.** An API restart loses in-flight report runs (§10.1). Closing
  it needs a queue on the Redis already present in the stack.
- **P1 is built and tested; P2–P6 are not.** This section previously read "nothing here has been
  built or tested", which stopped being true on 2026-09-14. P1's artifacts and test count are
  listed in §14, and its figures in §2.3 were produced by running the backfill against
  `security_portal`, not estimated. Everything from §3 (knowledge base) onward remains design.
  Every figure cited about the current codebase — the 136-line AuditBoard client,
  `contributor_profiles.py:1231`, the absence of a queue — was read from the source on
  2026-09-14 and can be re-checked at the paths given.
- **The suppression of 547,013 findings rests on a sample, not on a census.** For the `comment`
  rule the sample was 120 of 1,538 distinct values, plus an exhaustive string scan of all 1,538
  for credential-shaped content — strong, but a scan for *shapes*, and a credential that looks
  like prose would pass it. For the `file` rule nothing was sampled at all, because there is
  nothing to sample: the scanner recorded only filenames. That is why those 44,779 are marked
  excluded and not false positive, and why the content scan is an open item rather than a
  closed one. **"No credential found" is not "no credential present."**
- **Effort bands have never been calibrated against a completed remediation.** The drivers are
  measured and the scoring function is committed and tested, so the bands are reproducible — but
  reproducible is not accurate. Calibration needs the elapsed time of past remediations, which
  this database does not record. Until it does, a band is an ordering, not a duration.
