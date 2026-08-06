# Changelog

All notable changes to the AuditGitHub project will be documented in this file.

## [Unreleased]

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
