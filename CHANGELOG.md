# Changelog

All notable changes to the AuditGitHub project will be documented in this file.

## [Unreleased]

### Added — reports are written for one reader with three questions (2026-08-07)

**Uncommitted.** Working tree only, on branch `deployment-topology-p1-p2`.

**The problem.** A report went to someone wearing several hats, and it was organised the way
the data was collected rather than the way that person reads it. They open the same document
three times with three different questions, and had to reconstruct the answer each time.

**Added — `src/reporting/briefing.py`, the three-part structure**

    Part 1  What Happened            "My boss is asking me about this."
    Part 2  What To Do, In Order     "What do I actually do, and first?"
    Part 3  Evidence, Targets, Fixes "Engineering wants proof and targets."

Part 3 splits into **3.1 Proof** (the full evidence, unsummarised), **3.2 Target Resources**
(every finding with the id the earlier parts cite) and **3.3 Mitigations and Safeguards**.
Not three audiences — one reader, three moments. Each part is complete on its own, so
forwarding only Part 2 does not forward something unsupported.

**The split of labour.** Ordering and every figure are computed in code; only the phrasing
may come from a model, because the failure modes differ.
- **Ordering → code.** `rank_actions` is a pure function of severity and blast radius. A
  priority list that reshuffles between renders is not a plan.
- **Numbers → code.** The model is *forbidden from writing a digit*. It emits `{critical}`;
  prose containing a literal digit is discarded and retried once. A summary that misstates a
  count is worse than no summary — it is confidently wrong in the one section a
  non-technical reader repeats verbatim.
- **Phrasing → the model,** every claim carrying the finding ids it rests on. An unknown id
  is rejected.

**Risk and effort are separate axes, never multiplied.** Effort (S/M/L/XL, with what the work
needs and who has to be free) is displayed and orders items *within* a deadline band only. A
critical is Immediate whatever it costs. Folding cost into the score would let a two-week fix
rank below a five-minute one of the same severity, which is how genuinely urgent and
genuinely hard work sinks to the bottom of a list and stays there. Part 2 says so in print.

**Unknowns are counted, not rounded down.** A finding with no recorded blast radius ranks as
`unknown`, and the count is printed in Parts 1, 2 and 3.2 — an unestablished reach must not
silently rank as a small one. Same for unsized effort: assumed mid-range and labelled as
assumed, because guessed-cheap is the estimate that wrecks a plan.

**Changed — authored once, at analysis time**
- `POST /ai/zero-day` now returns a `briefing` object, written there and echoed back on
  export. Authoring on export would make the document a function of when it was printed;
  this way a re-exported report is byte-identical to the first one. Failure is never fatal —
  the analysis returns without a briefing and the export falls back to the rule-written
  wording, which the document states.
- Scan reports get the same three parts (`src/reporting/pdf_generator.py`,
  `src/reports/generator.py`). The scanner detail that used to be the whole document becomes
  3.1, in full.
- Deterministic authoring is a supported configuration, not just an error path. A site with
  no LLM gets a complete, readable report; the document names which way it was written.

**Fixed**
- **Broken page cross-references.** A hand-written `#part-2-what-to-do` no longer matched
  `_slugify("Part 2 — What To Do, In Order")`. This does not fail — it renders as a link to
  nothing and a blank page number, the one class of error a reader cannot detect. Anchors
  are now derived from the titles with the renderer's own slugifier.
- **`ZDAReportsView.tsx` still built Markdown client-side** for saved reports — the same
  defect fixed in `ZeroDayView.tsx` earlier, missed in its twin. The `.md` of a saved report
  carried neither the coverage caveats nor the summary and plan the PDF of that same report
  opened with. Both generators deleted; all formats now come off the server's one builder.
- **A single-finding step did not name its target.** Part 2 has no separate target column, so
  "Resolve: Hardcoded key" was a row nobody could be assigned. The resource is now in the
  title when the finding title does not already carry it.
- **Stored rationales were matched by title alone**, so the same scanner finding in two
  repositories made one inherit the other's justification. Keyed on title *and* target.
- Mid-word column breaks in Part 3.3 (`overflow-wrap: anywhere` let auto table layout starve
  an ID column to one character — "C2" as "C" over "2"); parts missing from the TOC;
  heading-level collisions in the embedded evidence body.
- Escaping moved to `src/reporting/mdwrite.py`. Two escapers drift, and silently: a missed
  pipe does not raise, it shifts every column one place to the left.

**Verification**
- 43 tests in `tests/test_briefing.py`, 32 in `tests/test_report_rendering.py`, all passing.
- Rendered PDFs inspected as images: part openers, TOC weighting, resolved page references,
  the six-column Part 2 table and the effort legend.
- **Not verified:** the zero-day endpoint itself. The host cannot import `ai.py` (loguru,
  psycopg2) and Docker was down, so `_author_zda_briefing` compiles but has not run against
  a live provider.

### Fixed — reports render as documents instead of transcribing their own Markdown source (2026-08-07)

**Uncommitted.** Working tree only, on branch `deployment-topology-p1-p2`.

**The defect.** The PDF export escaped the report Markdown and pushed it into a single
text run, so a reader received a PDF containing the literal characters `## 1. Summary`,
`| Spec | Verdict |` and `**Confirmed malicious**`. The DOCX export had the same bug in a
twin function. The output was a valid PDF of the wrong thing, which is why it survived —
a "did it render" check passes on it.

**Added — `src/reporting/`, one Markdown → HTML → PDF renderer for the whole project**
- `md_to_pdf.py`: markdown-it-py (CommonMark + the core `table` and `strikethrough` rules,
  so no plugin dependencies) → HTML → WeasyPrint. CSS Paged Media supplies the furniture a
  screen stylesheet cannot: cover page, `target-counter` TOC page numbers, running header,
  `Page N of M` folio, table headers that repeat across a page break.
- `md_to_docx.py` walks the **same token stream**. One parse, two outputs — a second parser
  is a second set of divergence bugs.
- Two security properties, both tested: the parser runs `html: False` (report bodies are
  LLM-generated, so markup passthrough is an injection channel), and the WeasyPrint
  `url_fetcher` refuses every non-`file:`/`data:` URL. Without the fetcher, one `<img>` in a
  generated report turns every export into a callback to whoever wrote it.
- Renders are reproducible when the timestamp is pinned — these are evidence documents, and
  a reader must be able to tell an edited finding from a re-exported one.

**Changed — every producer now goes through it**
- `src/api/routers/ai.py`: the six zero-day export endpoints are thin wrappers over one
  builder. `_pdf_evidence_sections()` and `_docx_evidence_sections()` deleted.
- `src/api/utils/zda_report.py` gained the Markdown serialiser. The analysis text passes
  through **verbatim** — it is already Markdown, and escaping it was the original bug; only
  the generated scaffolding around it is escaped.
- `src/reporting/pdf_generator.py` rewritten off dead reportlab code.
- `ReportFormat.PDF` added to `src/reports/generator.py` and `--format pdf` to the CLI.
- `scripts/report/md2pdf.py` — renders any Markdown file with the same house style
  (playbooks, handover docs, hunt reports). YAML front matter sets the cover; flags override.

**Changed — Markdown export moved server-side**
- `ZeroDayView.tsx` built its own Markdown client-side, in two functions that **omitted the
  coverage and blind-spot sections** the PDF carried. A reader exporting Markdown got a
  document that read as complete and was not. Both deleted; `POST /zero-day/export/md` and
  `/zero-day/export/repos/md` added, so all four formats come off one builder.

**Fixed — pre-existing, all five report formats**
- `_safe_name()` in `src/reports/generator.py`. Repository names arrive as `owner/repo`, and
  the slash made `open()` target a directory that does not exist, so every report for a
  fully-qualified repository failed with `FileNotFoundError` rather than writing anywhere.
- `ReportGenerator.generate_scan_report()` returned success while writing Markdown to a
  *different* path for an unsupported suffix. It now writes nothing and returns `False`.

**Verification**
- 32 tests in `tests/test_report_rendering.py`, all passing. They assert markup became
  *structure* — a real `<h2>`, a real `<table>` — not that a file was produced.
- Cover and body pages inspected as images: emoji verdict marks (✅/⚠️/❌) render as glyphs
  where the old reportlab path degraded them to tofu boxes.
- **Not verified:** the six API endpoints have not been exercised. The host cannot import
  `ai.py` (needs loguru, psycopg2) and Docker was down. Needs a container run.
- `Dockerfile.api` gained pango/cairo/harfbuzz and `fonts-dejavu-core` +
  `fonts-noto-color-emoji`. `python:3.11-slim` ships no fonts, and WeasyPrint on a fontless
  image produces a PDF of empty boxes rather than an error.

### Changed — CHAINDROP analysis folded into the npm supply-chain hunt corpus (2026-08-06)

**Uncommitted.** Working tree only, on branch `deployment-topology-p1-p2`. The checkout is
shared with another active session whose in-flight KQL work sits in three of the same files,
so nothing was staged. See `handoff.md` for what belongs to whom.

**Added — three detection rules, 6 → 9 in `github_conf/detections/npm_supply_chain_rules.json`**
- `npm-shaihulud-token-monitor` (high, quarantine-only) — the token-revocation watchdog, which is the only artefact that survives deleting `setup.mjs`, `math_init.js`, `.claude/` and `.vscode/`. A host cleaned on that basis is still armed.
- `npm-shaihulud-bun-fetch` (medium, isolate-selective) — the dropper's Bun release fetch. The earliest network event in the chain: it precedes credential collection, where the C2 rule only fires after collection completed.
- `npm-shaihulud-runner-mem-scrape` (high, isolate-full) — `sudo python3` reading `/proc/<Runner.Worker pid>/mem` for `"isSecret":true`. It writes no file and opens no connection, so the hash, C2 and exfil-artefact rules are all blind to it.
- All three are `armed: false`, undeployed, and have **no proof-of-concept coverage** — recorded as such on every surface rather than counted as detection. The KQL library covers 6 of 9 rules, so for those three the 30-day history is unexamined, not clean.
- Verified: 9/9 validate clean under the deployer's own checks. Dry run remains the default and `--force` still does not override `armed: false`.

**Added — `github_conf/ioc/chaindrop_stepsecurity_2026_08.json`**
- One source per file, so a claim can be attributed and a contradiction recorded instead of averaged away. First file in the corpus with a non-empty `contradicts` array.
- **Open Tier 0 escalation:** StepSecurity puts the propagation close at 13:20 UTC; the registry oracle bounds the last malicious publish at 12:11:19.909Z. Left unresolved on purpose. Interim rule written into all four documents: hunt to 13:20Z, report 12:11:19.909Z.

**Changed — incident response ordering (safety-critical)**
- Both playbooks opened with "rotate credentials before eradication". The watchdog polls `https://api.github.com/user` every 60 s for 24 h and **executes the payload when the token stops authenticating** — revocation is its trigger, not its remedy. A watchdog-removal step, with runnable Linux and macOS commands, now precedes rotation.
- Framed as a narrow carve-out, not a reversal: the payload still exfiltrates first, so cleaning everything before rotating still destroys evidence while credentials stay live. Order is remove watchdog → rotate → eradicate.
- Rotation scope widened to AI tooling credentials, all 16 CloudTrail regions, Vault, Kubernetes and SSH; a host that contacted the C2 is scoped as arbitrary code execution, because the exfil channel is bidirectional and a `code` field in the response reaches `eval()`.

**Fixed**
- `npm-shaihulud-c2-contact`'s remediation text described "the four attacker-controlled domains (npm-cache.com, js-mirror.com, pypi-get.com, and the `/router` path)" — counting a URL path as a domain. The fourth domain is `awqhnjewqjkl.icu`; `/router` is separately the exfil path.
- `awqhnjewqjkl.icu` had been present in an ingested source file while every rule and indicator list omitted it. The lesson — **ingesting a source file creates the appearance of coverage** — is now encoded in three places, including a required source-file-versus-rules diff step when a campaign is added.
- Stale six-rule references corrected across both playbooks and the handover appendices.

**Added — prevention that needs no Microsoft approval**
- Package-manager-native release-age gates (npm 11.10+ `min-release-age`, pnpm 10.16+, Yarn 4.10+, Bun 1.3+, Dependabot `cooldown`) as the no-Artifactory path.
- Egress allowlist on build agents, which stops the chain at its first hop; review-time diffing of release tooling, since SLSA provenance was defeated twice in this campaign — once by self-minted attestations and once by the project's own legitimate release workflow.
- Removing passwordless `sudo` from self-hosted runner service accounts, which prevents the memory-scrape class rather than detecting it.

**Known blind spot recorded, not closed**
- The payload declines to run under a Russian locale, and those hosts read clean on every behavioural rule — only the file/hash rules still fire. Estate locale enumeration is outstanding.

### Added — Deployment Topology P1/P2 and Shared GitHub Budget Governor (2026-08-06)

Branch `deployment-topology-p1-p2`, commit `5b749b9`.

**Added — deployment capability map (P1, run against the live estate)**
- Parses the ~84 centrally-shared reusable workflows once and propagates each deployment contract to every consumer repository, resolving concrete environments and Azure/AWS identifiers from per-repository GitHub Environments and Actions variables.
- 4,207 map rows across 374 repositories; 288 repositories reach a production environment.
- Coverage is data: every repository is resolved with evidence, explicitly unresolved with a reason, or a counted unknown. A repository with no rows is never reported as "deploys nowhere".
- Every row carries `method`, `confidence`, `evidence`, and the claim it does **not** make (`deployment_capability_not_observation`).
- New tables `reusable_workflow_targets` and `repo_deployment_map` plus a `repo_deployment_coverage` view (migration 020).
- 4 API routes under `/cicd/topology/*` and CLI `scripts/sync_deployment_topology.py`.

**Added — deployment observation (P2, code complete, not yet run)**
- Reads the GitHub Deployments API and writes `method='github_deployment'` rows alongside — never over — P1's inference, so wired-but-never-used and used-but-not-wired are both visible.
- First writer for the previously unused `deployments` / `deployment_targets` tables.
- Resumable by design: repositories are probed oldest-observation-first and committed as they complete, so a run stopped at the budget floor continues on the next invocation.
- `POST /cicd/topology/observe`, `GET /cicd/topology/activity`, CLI `scripts/sync_deployment_observations.py`, migration 021.
- Deployment payload **values are dropped at ingest**; only key names are stored, because a payload is supplied by whoever created the deployment and can carry credential material.

**Added — shared GitHub API budget governor**
- Every GitHub caller in the deployment shares one PAT and one 5000/hr limit with nothing arbitrating between them; an org import exhausted the window (`X-RateLimit-Used: 5019`) and the first topology run consequently wrote nothing.
- Budget is now **observed** from `X-RateLimit-*` headers of real responses, not asserted by `GET /rate_limit` (which reported 4990 remaining while the next real request 403'd).
- Three tiers with reserved floors: interactive is never gated, on-demand leaves 400 calls, background leaves 2000 and additionally waits for an idle estate. No Redis means background work is refused rather than allowed blind.
- `GET /scheduler/github-budget` exposes the live snapshot and a per-tier would-admit decision.

**Changed — scheduler deprioritized**
- The ~2,500 per-repo scan cron jobs are no longer registered at startup (`SCHEDULER_AUTO_REGISTER_REPO_SCANS=false`); schedules stay in the database and run on demand.
- When enabled: deterministic per-schedule minute spread instead of all firing at `hh:00`, one scan at a time, and deferrals recorded as `last_execution_status='deferred_rate_budget'` rather than skipped silently.

**Fixed**
- Scheduled scans ran `subprocess.run` inside an async handler, blocking the API event loop for up to the 2-hour scan timeout — one scheduled scan stalled every request in the process. Now `asyncio.create_subprocess_exec`.
- `scripts/setup_database.sh` applied a hardcoded list of migrations 001–006 and had been silently skipping 007–020; it now applies every migration in sorted order, with dev-only seed files gated behind `SEED_MOCK_USERS=true`.

**Security findings recorded as data**
- 46 contracts hand `toJSON(secrets)` to a composite action pinned to a moving `@v2` tag, or use `secrets: inherit` (`reusable_workflow_targets.secrets_bulk_exposure`).
- 9 consumer references point at deleted branches of central workflow repositories: their CI is broken today, and the dangling ref means anyone able to push a branch of that name gains code execution in every consumer with the consumer's secrets.

**Rights**
- No new access required. One gap recorded with evidence: `GET /orgs/{org}/actions/variables` returns 403, which lowers precision (rows get `unresolved_reason='org_variables_forbidden'`) but not coverage. GitHub throttling is classified separately from denial throughout, so a rate-limited run can never be filed as an access request.

**Tests:** 86 added (55 parser, 12 budget governor, 19 observation).

### Fixed — Security Findings (MEDIUM) (2026-05-22)
- Added `timeout=30` to 12 HTTP requests calls across 5 files (instrumentation, jira, scan_engagement, scan_hardcoded_ips, verify_sbom)
- Changed temp directory permissions from 0o755 to 0o700 in scan_repos.py
- Made uvicorn bind address configurable via BIND_HOST env var (defaults to 127.0.0.1)
- Set ECR image tag mutability default to IMMUTABLE
- Set VPC subnet map_public_ip_on_launch to false
- Upgraded 8 npm dependencies via npm audit fix (js-cookie, lodash, picomatch, dompurify, mermaid, uuid, brace-expansion, next)
- 2 npm vulnerabilities remain (postcss via next — awaiting Next.js patch release)
- 3 SQL injection f-string patterns confirmed safe (allowlist validation already present)

### Fixed — Schema Path & Auth Bootstrap (2026-05-22)
- Fixed `ai_org_agent.py` schema.sql path to `scripts/setup/` (was `setup/`)
- Fixed auth bootstrap variable name from hardcoded `rob_vance` to generic `admin_user`

### Added — Security Workstation Integration (2026-05-07)
- Security workstation: auth fixes, scanner hardening, UI cleanup
- Fixed ZDA export 403 error for users with `findings:read` permission
- Aligned RFC-2024-003 with EA Design Pattern for managed AI services
- Added DevOps/SRE questions (Q22-Q26) to RFC-2024-003
- Added RFC-2024-003: AWS Bedrock Safeguards defense-in-depth
- Added defense-in-depth security layers for AWS Bedrock beyond IAM
- Enhanced AI architecture diagrams, WAF auditor, diagram editor panel
- Added multi-org management, per-org scan credentials, Docker port fixes
- Added WAF security feature: static scanner, API router, UI tab
- Added on-demand scanning, auto-port detection, enhanced Terraform scanner, AWS WAF auditor

### Added — Azure Device-Code Login Automation (2025-03-07)

**Context:** Automates the Azure CLI `az login --use-device-code` flow end-to-end using Playwright browser automation, eliminating manual copy-paste of device codes and browser navigation.

**Phase:** Complete — ready for use.

#### New Files
- `scripts/azure-login/az_login.py` — Main Python orchestrator
  - Spawns `az login --use-device-code` as a subprocess in a background thread
  - Extracts the device code from CLI stdout via regex
  - Launches a Playwright Chromium browser (headed mode for MFA visibility)
  - Navigates to `https://login.microsoft.com/device`, enters code, clicks Next
  - Selects the target Azure account via 5 progressive selector strategies
  - Detects MFA requirement (Authenticator number-matching, SMS, FIDO) and pauses for manual user interaction with clear terminal prompts
  - Handles "Stay signed in?" prompt automatically
  - Runs `az account set --subscription <name>` after successful auth
  - Verifies with `az account show` and displays account details
  - Saves debug screenshots on errors to `scripts/azure-login/screenshots/`
  - Full CLI argument support (`--email`, `--subscription`, `--timeout`, `--slow-mo`, `--headless`, `--debug`, `--log-file`)
  - Configurable via env vars: `AZURE_LOGIN_EMAIL`, `AZURE_SUBSCRIPTION`, `AZURE_MFA_TIMEOUT`, `AZURE_SLOW_MO`

- `scripts/azure-login/az-login.sh` — Shell wrapper
  - Pre-flight checks for `az` CLI, Python 3, and Playwright
  - Auto-installs Playwright and Chromium browser if missing
  - Passes all CLI args through to the Python script
  - Provides troubleshooting guidance on failure

- `scripts/azure-login/requirements.txt` — `playwright>=1.40.0`
- `scripts/azure-login/IMPLEMENTATION_SPEC.md` — Detailed implementation specification
- `scripts/azure-login/screenshots/.gitkeep` — Debug screenshot directory

#### Modified Files
- `.gitignore` — Added `scripts/azure-login/screenshots/*.png`

#### How to Use
```bash
# Quick start (uses defaults: admin@company.example, my-azure-subscription)
./scripts/azure-login/az-login.sh

# Custom account and subscription
./scripts/azure-login/az-login.sh --email user@company.com --subscription "my-sub"

# Debug mode with log file
./scripts/azure-login/az-login.sh --debug --log-file /tmp/az-login.log

# Direct Python execution
python scripts/azure-login/az_login.py --help
```

#### Flow Summary
1. Pre-flight checks (az CLI, Playwright, Chromium)
2. Spawns `az login --use-device-code` → captures device code
3. Opens browser → enters code → clicks Next
4. Selects account → handles password if needed
5. **MFA pause** — user completes MFA on their device (number displayed in terminal)
6. `az account set --subscription "my-azure-subscription"`
7. `az account show` verification with formatted output
