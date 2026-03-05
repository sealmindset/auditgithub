# AGH Local — Implementation Plan

## Daughter Project: Local Security Scanning for Developer Workstations

**Project Name:** `agh-local` (working name)
**Relationship:** Independent repository; shares scan tooling DNA with AuditGitHub Hub (AGH)
**Goal:** Snyk-like shift-left security scanning — developers find and fix vulnerabilities before committing

---

## 1. Executive Summary

### What

A standalone developer security tool that runs the same scan engines as AGH (gitleaks, semgrep, bandit, checkov, trivy) against local code, reports findings directly in the IDE and terminal, and optionally syncs results to the AGH server for team visibility.

### Why

Today, AGH scans repositories after code is pushed to GitHub. Vulnerabilities are discovered post-commit — after the code is in the shared repo, potentially in a PR, and visible to the team. This creates:

- **Longer feedback loops** — developer context-switches away from the code before seeing findings
- **Noisy PRs** — security findings appear as PR comments or dashboard alerts after the fact
- **Wasted CI cycles** — scans run on code that could have been fixed locally in seconds

AGH Local moves the scan left: same tools, same rules, same policy gates — but running on `localhost` before `git push`.

### What "Done" Means

- Developer installs via `pip install agh-local` or VS Code extension marketplace
- `agh scan` runs a Docker-based scan against the current directory in < 60 seconds for a typical repo
- Findings appear in the terminal (table/JSON/SARIF) and VS Code Problems panel
- Pre-commit hook catches secrets; pre-push hook enforces policy gates
- Optional: `agh push` uploads SARIF to AGH server for team dashboard
- Works fully offline (no AGH server required for local scanning)

---

## 2. Architecture

### 2.1 High-Level Components

```
Developer Workstation
+---------------------------------------------------------------+
|                                                               |
|  VS Code Extension          CLI (agh)          Pre-commit     |
|  +------------------+   +----------------+   +-------------+  |
|  | Diagnostics      |   | agh scan       |   | agh-secrets |  |
|  | Tree View        |   | agh findings   |   | agh-policy  |  |
|  | CodeLens         |   | agh push       |   +------+------+  |
|  | Status Bar       |   | agh policy     |          |         |
|  | Policy Checker   |   | agh auth       |          |         |
|  +--------+---------+   +-------+--------+          |         |
|           |                     |                    |         |
|           +----------+----------+--------------------+         |
|                      |                                         |
|                      v                                         |
|              Scanner Engine                                    |
|              +------------------------------+                  |
|              |  Docker: agh-scanner:lite     |                  |
|              |  ~500MB image                 |                  |
|              |  gitleaks, semgrep, bandit,   |                  |
|              |  checkov, trivy               |                  |
|              |  Shared configs baked in      |                  |
|              +---------------+--------------+                  |
|                              |                                 |
|                              v                                 |
|                     Local Results                              |
|                     (SARIF / JSON)                              |
|                     ~/.agh/results/                             |
+-------------------------------+-------------------------------+
                                |
                          (optional)
                                |
                                v
                     AGH Server (existing)
                     +------------------------+
                     | POST /sarif-import     |
                     | Device Flow auth       |
                     | Findings dashboard     |
                     +------------------------+
```

### 2.2 Execution Modes

| Mode | Description | Server Required | Use Case |
|------|-------------|-----------------|----------|
| **Local-only** | Scan + report locally | No | Developer workstation, air-gapped environments |
| **Connected** | Scan locally, push results to AGH | Yes (auth required) | Team visibility, trending, compliance |
| **CI** | Scan in pipeline, output SARIF | No (or optional push) | GitHub Actions, Jenkins, Azure DevOps |

### 2.3 Scanner Engine: Docker vs. Native

The CLI supports two execution backends:

```
agh scan --path .
    |
    +---> Docker available?
    |       |
    |       YES --> docker run agh-scanner:lite -v $(pwd):/scan ...
    |                (preferred: consistent, no local installs)
    |
    +---> No Docker?
            |
            +---> Check for native tools in PATH
            |       gitleaks? semgrep? bandit? checkov? trivy?
            |
            +---> Run available tools directly
            |       (warn about missing tools)
            |
            +---> No tools at all?
                    Error: "Install Docker or individual tools. See docs."
```

**Priority order:** Docker > native tools > error with install instructions.

This means the developer experience is:
1. **Best:** Install Docker, run `agh scan` — everything just works
2. **Good:** Have some tools locally, `agh scan` uses what's available
3. **Minimal:** `agh scan --tool gitleaks` with just gitleaks installed (e.g., for pre-commit secret scanning)

---

## 3. Repository Structure

```
agh-local/
  README.md
  LICENSE
  .github/
    workflows/
      ci.yaml                  # Test CLI + build Docker image
      release.yaml             # Publish to PyPI + Docker Hub + VS Code Marketplace

  cli/
    pyproject.toml             # Package metadata (from AGH cli/)
    src/
      agh/
        __init__.py
        cli.py                 # Main CLI entry point (from AGH cli/agh_cli.py)
        config.py              # Config loader (from AGH cli/agh_config.py)
        formatters.py          # Table/JSON/SARIF output (from AGH cli/agh_formatters.py)
        scanner/
          __init__.py
          engine.py            # Docker vs. native detection + dispatch
          docker_runner.py     # Docker execution wrapper
          native_runner.py     # Direct tool execution
          language_detect.py   # Auto-detect languages in project
          parsers/
            __init__.py
            gitleaks.py        # Parse gitleaks JSON -> normalized findings
            semgrep.py         # Parse semgrep JSON -> normalized findings
            bandit.py          # Parse bandit JSON -> normalized findings
            checkov.py         # Parse checkov JSON -> normalized findings
            trivy.py           # Parse trivy JSON -> normalized findings
        sync/
          __init__.py
          push.py              # Upload SARIF to AGH server
          auth.py              # Device Flow + API key auth (from AGH cli)
        policy/
          __init__.py
          checker.py           # Policy gate evaluation (from AGH cli)
    tests/
      test_cli.py
      test_engine.py
      test_parsers.py
      test_policy.py
      fixtures/                # Sample scanner outputs for parser tests

  scanner/
    Dockerfile.lite            # Lightweight scanner image (~500MB)
    configs/
      .gitleaks.toml           # Gitleaks config (from AGH)
      policy.yaml              # Default policy gates (from AGH)
      semgrep-rules/           # Custom semgrep rules (from AGH)
        api-endpoints.yaml
        api-auth.yaml
        python.yaml
        hardcoded-ips-hostnames.yaml

  vscode-extension/            # VS Code extension (from AGH vscode-extension/)
    package.json
    src/
      extension.ts
      aghClient.ts
      auth.ts
      diagnosticProvider.ts
      findingsTreeProvider.ts
      scanRunner.ts            # Modified: calls agh CLI instead of direct tool execution
      codeLensProvider.ts
      statusBar.ts
      policyChecker.ts
    tsconfig.json

  shared/
    finding-schema.json        # JSON Schema v2024-12 for normalized findings
    sarif-profile.json         # SARIF 2.1.0 profile for AGH findings
    VERSION                    # Schema version (semver)

  docs/
    getting-started.md
    configuration.md
    ci-integration.md
    ide-integration.md
```

---

## 4. Component Design

### 4.1 Normalized Finding Schema

All scanner outputs are normalized to this format before display or export. This is the **contract** between `agh-local` and the AGH server.

```json
{
  "$schema": "https://json-schema.org/draft/2024-12/schema",
  "title": "AGH Finding",
  "version": "1.0.0",
  "type": "object",
  "required": ["scanner", "severity", "file_path", "line", "title", "rule_id"],
  "properties": {
    "scanner":     { "type": "string", "enum": ["gitleaks", "semgrep", "bandit", "checkov", "trivy"] },
    "severity":    { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
    "file_path":   { "type": "string" },
    "line":        { "type": "integer", "minimum": 1 },
    "column":      { "type": "integer", "minimum": 0, "default": 0 },
    "end_line":    { "type": "integer" },
    "end_column":  { "type": "integer" },
    "title":       { "type": "string" },
    "description": { "type": "string" },
    "rule_id":     { "type": "string" },
    "cwe_id":      { "type": "string" },
    "cve_id":      { "type": "string" },
    "confidence":  { "type": "string", "enum": ["high", "medium", "low"] },
    "snippet":     { "type": "string" },
    "fix_hint":    { "type": "string" },
    "metadata":    { "type": "object" }
  }
}
```

**Versioning:** The schema version lives in `shared/VERSION`. The AGH server's SARIF import endpoint validates against this version. Breaking changes increment the major version.

### 4.2 Lightweight Docker Image (`Dockerfile.lite`)

```dockerfile
FROM python:3.11-slim AS base

# Tool versions pinned for reproducibility
ARG GITLEAKS_VERSION=8.18.2
ARG SEMGREP_VERSION=1.56.0
ARG BANDIT_VERSION=1.7.7
ARG CHECKOV_VERSION=3.2.0
ARG TRIVY_VERSION=0.49.1

# Install gitleaks (binary)
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz \
    | tar xz -C /usr/local/bin gitleaks

# Install trivy (binary)
RUN curl -sSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    | tar xz -C /usr/local/bin trivy

# Install Python-based tools
RUN pip install --no-cache-dir \
    semgrep==${SEMGREP_VERSION} \
    bandit==${BANDIT_VERSION} \
    checkov==${CHECKOV_VERSION}

# Copy configs
COPY configs/.gitleaks.toml /etc/agh/.gitleaks.toml
COPY configs/semgrep-rules/ /etc/agh/semgrep-rules/
COPY configs/policy.yaml /etc/agh/policy.yaml

# Scanner entrypoint script
COPY entrypoint.sh /usr/local/bin/agh-scan
RUN chmod +x /usr/local/bin/agh-scan

WORKDIR /scan
ENTRYPOINT ["agh-scan"]
```

**Target size:** ~500MB (vs. 8GB for the full AGH scanner image)

**Entrypoint behavior:**
```bash
agh-scan [--tool TOOL] [--format json|sarif] [--config /path/to/policy.yaml]
# Defaults: all tools, json format, /etc/agh/policy.yaml
# Mounts: /scan (code to scan), /output (results)
```

### 4.3 CLI Design

```
agh <command> [options]

Commands:
  scan        Run security scanners against local code
  push        Upload scan results to AGH server
  policy      Evaluate policy gates against scan results
  auth        Authenticate with AGH server
  status      Show tool availability and auth state
  config      Manage local configuration
  version     Show version and schema version

agh scan [options]
  --path, -p       Target directory (default: .)
  --tool, -t       Specific tool (repeatable): gitleaks|semgrep|bandit|checkov|trivy
  --format, -f     Output format: table|json|sarif (default: table)
  --output, -o     Write results to file (default: stdout)
  --docker         Force Docker execution (error if unavailable)
  --native         Force native tool execution (skip Docker)
  --severity, -s   Minimum severity to report: critical|high|medium|low|info
  --config         Path to policy.yaml (default: auto-detect)
  --no-cache       Skip tool cache (fresh scan)
  --quiet, -q      Only output findings (no progress/banners)

agh push [options]
  --file, -f       SARIF file to upload (default: last scan result)
  --server         AGH server URL (default: from config)
  --org            Organization ID (default: from config)
  --dry-run        Show what would be uploaded without sending

agh policy check [options]
  --path, -p       Target directory (default: .)
  --config         Path to policy.yaml (default: auto-detect)
  --strict         Fail on any finding (override policy)

agh auth login [options]
  --api-key        Direct API key authentication
  --device-flow    Browser-based Device Flow (default)
  --server         AGH server URL

agh status
  # Output:
  # Auth: authenticated as rob.vance@sleepnumber.com (org: sleepnumberlabs)
  # Server: http://localhost:8000 (reachable)
  # Docker: available (agh-scanner:lite v1.2.0)
  # Native tools: gitleaks (8.18.2), semgrep (1.56.0), bandit (not found), ...
```

### 4.4 Language Detection

Before running scanners, detect project languages to skip irrelevant tools:

| Signal | Language | Tools to Run |
|--------|----------|-------------|
| `*.py`, `requirements.txt`, `pyproject.toml` | Python | gitleaks, semgrep, bandit, trivy |
| `*.js`, `*.ts`, `package.json` | JavaScript/TypeScript | gitleaks, semgrep, trivy |
| `*.go`, `go.mod` | Go | gitleaks, semgrep, trivy |
| `*.java`, `pom.xml`, `build.gradle` | Java | gitleaks, semgrep, trivy |
| `*.tf`, `*.hcl` | Terraform | gitleaks, checkov |
| `Dockerfile`, `docker-compose.yml` | Docker | gitleaks, checkov, trivy |
| `*.yaml`, `*.yml` (k8s manifests) | Kubernetes | gitleaks, checkov |
| Any | All | gitleaks (always), trivy (always) |

**Bandit** only runs on Python projects. **Checkov** only runs when IaC files are detected. **Gitleaks** and **trivy** always run.

### 4.5 VS Code Extension Changes

The existing extension in AGH (`vscode-extension/`) is ported with one key change: **the extension calls the `agh` CLI** instead of invoking tools directly.

**Why:** Single execution engine. The CLI handles Docker vs. native detection, language detection, config loading, and output normalization. The extension is a UI layer.

```
Before (current AGH extension):
  extension.ts -> scanRunner.ts -> exec("gitleaks detect ...")
                                -> exec("semgrep scan ...")
                                -> parse each tool's JSON independently

After (agh-local extension):
  extension.ts -> scanRunner.ts -> exec("agh scan --format json --quiet")
                                -> parse normalized findings JSON
                                -> diagnosticProvider.ts maps to VS Code diagnostics
```

**Extension settings:**
```json
{
  "agh.scanOnSave": false,
  "agh.scanOnOpen": true,
  "agh.minimumSeverity": "medium",
  "agh.useDocker": true,
  "agh.serverUrl": "",
  "agh.organizationId": "",
  "agh.scanners": ["gitleaks", "semgrep", "bandit", "checkov", "trivy"]
}
```

### 4.6 Pre-Commit / Pre-Push Hooks

Distributed as a `.pre-commit-hooks.yaml` in the repo root so any project can use them:

```yaml
# .pre-commit-hooks.yaml (in agh-local repo — consumed by other repos)
- id: agh-secrets
  name: AGH Secret Detection
  entry: agh scan --tool gitleaks --quiet --format table
  language: python
  stages: [pre-commit]
  pass_filenames: false

- id: agh-policy
  name: AGH Policy Gate
  entry: agh policy check --strict
  language: python
  stages: [pre-push]
  pass_filenames: false

- id: agh-scan
  name: AGH Full Scan
  entry: agh scan --quiet --severity high --format table
  language: python
  stages: [pre-push]
  pass_filenames: false
```

**Consumer repo usage:**
```yaml
# .pre-commit-config.yaml (in any project repo)
repos:
  - repo: https://github.com/sleepnumber/agh-local
    rev: v1.0.0
    hooks:
      - id: agh-secrets
      - id: agh-policy
```

---

## 5. Config Sync Strategy

### Problem

Semgrep rules, gitleaks config, and policy.yaml live in the AGH main repo. The daughter project needs its own copies. Drift between the two is the primary maintenance risk.

### Solution: Published Config Package + Pinned Versions

```
AGH Main Repo                          agh-local Repo
+---------------------------+          +---------------------------+
| semgrep-rules/            |  copy    | scanner/configs/          |
| .gitleaks.toml            | -------> | semgrep-rules/            |
| policy.yaml               |  at      | .gitleaks.toml            |
+---------------------------+  release | policy.yaml               |
                                       +---------------------------+
                                       | shared/VERSION = "1.0.0"  |
                                       +---------------------------+
```

**Sync mechanism:**
1. AGH main repo tags config releases (e.g., `configs-v1.2.0`) when rules change
2. `agh-local` CI has a dependency check: compare config versions weekly
3. Updating configs in `agh-local` is a deliberate PR — not automatic
4. Docker image bakes in configs at build time, so the image version pins the config version
5. `agh scan --update-configs` pulls latest from a known URL (future enhancement)

**Version contract:**
- `shared/VERSION` in `agh-local` declares the finding schema version
- AGH server's `/sarif-import` endpoint checks `tool.driver.version` in SARIF for compatibility
- Major version mismatch = reject with helpful error message

---

## 6. Authentication & Server Integration

### 6.1 Offline-First Design

AGH Local **must work without a server**. The server integration is opt-in:

```
First run (no auth):
  $ agh scan
  [scans locally, shows results in terminal]
  # No server interaction. No auth prompt. Just works.

Optional server connect:
  $ agh auth login --server https://agh.sleepnumber.com
  [Opens browser for Device Flow]
  [Saves token to ~/.agh/credentials.json]

  $ agh push
  [Uploads last scan SARIF to server]
  Uploaded 14 findings to sleepnumberlabs/my-repo
```

### 6.2 Auth Methods

| Method | Use Case | Storage |
|--------|----------|---------|
| **Device Flow** (RFC 8628) | Interactive developer login | `~/.agh/credentials.json` (mode 0600) |
| **API Key** | CI/CD pipelines, automation | Env var `AGH_API_KEY` or credentials file |
| **None** | Local-only scanning | N/A |

### 6.3 Push Flow

```
agh push
  |
  v
Load credentials from ~/.agh/credentials.json
  |
  v
Read last scan result from ~/.agh/results/latest.sarif
  |
  v
POST /api/proxy/sarif-import
  Headers:
    Authorization: Bearer <token>  (or X-API-Key: <key>)
    X-Organization-ID: <org_id>
    Content-Type: application/json
  Body: SARIF 2.1.0 JSON
  |
  v
Server deduplicates against existing findings
  |
  v
Response: { "imported": 14, "deduplicated": 3, "new": 11 }
```

---

## 7. Pitfalls & Mitigations

| # | Pitfall | Mitigation |
|---|---------|-----------|
| 1 | **Config drift** between AGH and agh-local | Versioned configs with deliberate sync PRs; CI weekly check |
| 2 | **Finding schema break** | `shared/VERSION` semver; server validates version on import |
| 3 | **Docker not available** (corporate lockdown) | Native tool fallback with clear `agh status` output showing what's missing |
| 4 | **Docker image too large** | Lite image targets ~500MB; only 5 tools; no CodeQL/Nuclei/etc. |
| 5 | **Slow scans on large repos** | Language detection skips irrelevant tools; `--tool` flag for targeted scans; incremental scan via git diff (future) |
| 6 | **Pre-commit hook too slow** | Secret scan only (gitleaks) in pre-commit (~2-5s); full scan in pre-push |
| 7 | **Auth token expiry** | Refresh token rotation; clear error: "Run `agh auth login` to re-authenticate" |
| 8 | **Scanner version mismatch** | CLI prints tool versions; Docker image pins exact versions; `agh version --tools` shows all |
| 9 | **macOS ARM vs x86** | Docker image multi-arch (linux/amd64 + linux/arm64); native tools via Homebrew |
| 10 | **VS Code extension can't find CLI** | Extension checks PATH + common install locations; settings allow explicit path |
| 11 | **Results directory grows unbounded** | Auto-prune: keep last 10 scan results in `~/.agh/results/`; configurable |
| 12 | **Multiple orgs** | `agh config set org <org_id>` or `--org` flag; credentials file supports profiles |

---

## 8. Implementation Phases

### Phase 1: Core CLI + Docker Scanner (MVP)

**Goal:** `agh scan` works against any local repo using Docker

**Scope:**
- [ ] Create `agh-local` repository
- [ ] Port `cli/agh_cli.py` -> `cli/src/agh/cli.py` with refactored module structure
- [ ] Implement `scanner/engine.py` (Docker detection + dispatch)
- [ ] Implement `scanner/docker_runner.py` (volume mount, run, collect output)
- [ ] Implement 5 result parsers (gitleaks, semgrep, bandit, checkov, trivy)
- [ ] Build `Dockerfile.lite` with pinned tool versions
- [ ] Implement `language_detect.py` (skip irrelevant tools)
- [ ] Port `cli/agh_formatters.py` for table/JSON/SARIF output
- [ ] Create `shared/finding-schema.json`
- [ ] Copy scanner configs from AGH (semgrep-rules, .gitleaks.toml, policy.yaml)
- [ ] Implement `~/.agh/results/` local result storage
- [ ] Write tests: parser tests with fixtures, engine tests with Docker mock
- [ ] Publish to PyPI as `agh-local`
- [ ] Publish Docker image to registry as `agh-scanner:lite`

**Exit Criteria:**
```bash
pip install agh-local
cd my-project
agh scan                     # Full scan via Docker, table output
agh scan --format sarif -o results.sarif   # SARIF export
agh scan --tool gitleaks     # Single tool, fast
agh status                   # Shows Docker available, tools, no auth
```

**Estimated Effort:** L (2-3 weeks)

### Phase 2: Native Tool Fallback + Policy Gates

**Goal:** Works without Docker; policy gates block bad code

**Scope:**
- [ ] Implement `scanner/native_runner.py` (detect tools in PATH, exec directly)
- [ ] Engine fallback: Docker -> native -> error with install instructions
- [ ] Port `policy/checker.py` from AGH CLI
- [ ] `agh policy check` command with gate evaluation
- [ ] Policy auto-detection (walk up directory tree for `policy.yaml`)
- [ ] `agh config` command for managing settings
- [ ] Add `--severity` filter to `agh scan`
- [ ] Add `--quiet` flag for CI-friendly output
- [ ] Tests: native runner tests, policy evaluation tests

**Exit Criteria:**
```bash
agh scan --native            # Uses tools from PATH
agh policy check             # Evaluates gates, exit code 0 or 1
agh scan --severity high     # Only critical + high findings
```

**Estimated Effort:** M (1-2 weeks)

### Phase 3: Server Integration (Auth + Push)

**Goal:** Optional sync with AGH server

**Scope:**
- [ ] Port `auth.py` from AGH CLI (Device Flow + API key)
- [ ] Implement `sync/push.py` (upload SARIF to `/sarif-import`)
- [ ] `agh auth login` with browser-based Device Flow
- [ ] `agh auth login --api-key` for CI
- [ ] `agh push` command (upload last scan or specific file)
- [ ] `agh push --dry-run` for preview
- [ ] `agh findings` command (fetch server findings for comparison)
- [ ] Credentials storage with profiles (multiple servers/orgs)
- [ ] Tests: auth flow mocks, push with mock server

**Exit Criteria:**
```bash
agh auth login --server https://agh.internal.com
agh scan
agh push                     # Uploads SARIF, shows import stats
agh findings --severity high # Fetches from server
```

**Estimated Effort:** M (1-2 weeks)

### Phase 4: Pre-Commit Hooks

**Goal:** Automated scanning in git workflow

**Scope:**
- [ ] Create `.pre-commit-hooks.yaml` in repo root
- [ ] `agh-secrets` hook (pre-commit, gitleaks only, ~3s)
- [ ] `agh-policy` hook (pre-push, full gate evaluation)
- [ ] `agh-scan` hook (pre-push, full scan with severity filter)
- [ ] Installation docs: `pre-commit install --hook-type pre-commit --hook-type pre-push`
- [ ] Test: hook execution with sample repos

**Exit Criteria:**
```yaml
# In any consumer repo:
repos:
  - repo: https://github.com/sleepnumber/agh-local
    rev: v1.0.0
    hooks:
      - id: agh-secrets    # Blocks commit if secrets found
      - id: agh-policy     # Blocks push if policy gates fail
```

**Estimated Effort:** S (3-5 days)

### Phase 5: VS Code Extension

**Goal:** Full IDE integration with inline findings

**Scope:**
- [ ] Port `vscode-extension/` from AGH
- [ ] Modify `scanRunner.ts` to call `agh` CLI instead of direct tool execution
- [ ] `diagnosticProvider.ts` maps normalized findings to VS Code diagnostics
- [ ] `findingsTreeProvider.ts` groups by severity in sidebar
- [ ] `codeLensProvider.ts` annotates lines with findings
- [ ] `statusBar.ts` shows finding counts
- [ ] Settings: autoScanOnSave, minimumSeverity, useDocker, serverUrl
- [ ] `policyChecker.ts` evaluates gates on save/push
- [ ] Auth integration via `agh auth` CLI commands
- [ ] Package and publish to VS Code Marketplace
- [ ] Test: extension activation, command execution, diagnostic display

**Exit Criteria:**
- Install extension from marketplace
- Open a project -> findings appear in Problems panel
- Sidebar tree view shows findings grouped by severity
- Status bar shows finding counts
- CodeLens annotations on affected lines
- Settings allow configuring scanners, severity threshold, server URL

**Estimated Effort:** L (2-3 weeks)

### Phase 6: CI/CD Templates

**Goal:** Easy integration with common CI platforms

**Scope:**
- [ ] GitHub Actions reusable workflow (`agh-local/.github/workflows/agh-scan.yaml`)
- [ ] GitHub Actions action (`action.yml`) for marketplace
- [ ] Azure DevOps pipeline template
- [ ] Jenkins shared library
- [ ] SARIF upload to GitHub Code Scanning (via `--format sarif`)
- [ ] Exit code convention: 0 = clean, 1 = findings, 2 = error
- [ ] Documentation: CI integration guide

**Exit Criteria:**
```yaml
# In consumer repo's .github/workflows/security.yaml:
- uses: sleepnumber/agh-local@v1
  with:
    severity: high
    policy: strict
    push-to-server: true
    server-url: ${{ secrets.AGH_URL }}
    api-key: ${{ secrets.AGH_API_KEY }}
```

**Estimated Effort:** M (1-2 weeks)

### Phase 7: Incremental Scanning + Caching (Future)

**Goal:** Fast re-scans by only scanning changed files

**Scope:**
- [ ] `git diff --name-only` to detect changed files since last scan
- [ ] Per-file result caching in `~/.agh/cache/`
- [ ] `agh scan --incremental` flag (default in pre-commit hooks)
- [ ] Cache invalidation on config/rule changes
- [ ] Benchmark: full scan vs. incremental on AGH repo itself

**Estimated Effort:** M (1-2 weeks)

---

## 9. Work Items Summary

| Epic | Phase | Size | Dependencies |
|------|-------|------|-------------|
| Core CLI + Docker Scanner | 1 | L | None |
| Native Fallback + Policy | 2 | M | Phase 1 |
| Server Integration | 3 | M | Phase 1 |
| Pre-Commit Hooks | 4 | S | Phase 2 |
| VS Code Extension | 5 | L | Phase 1 |
| CI/CD Templates | 6 | M | Phase 2, 3 |
| Incremental Scanning | 7 | M | Phase 1 |

**Critical path:** Phase 1 -> Phase 2 -> Phase 4 (developer gets scan + hooks)

**Parallel work:** Phase 3 and Phase 5 can start after Phase 1 completes, independent of Phase 2.

```
Phase 1 (Core) ----+---> Phase 2 (Native + Policy) ---> Phase 4 (Hooks)
                   |
                   +---> Phase 3 (Server Integration) ---> Phase 6 (CI/CD)
                   |
                   +---> Phase 5 (VS Code Extension)

                   Phase 7 (Incremental) — after Phase 1, anytime
```

---

## 10. Distribution Plan

| Channel | Package | Audience |
|---------|---------|----------|
| **PyPI** | `agh-local` | Python devs, CI pipelines |
| **Homebrew** | `brew install agh` (future) | macOS developers |
| **Docker Hub** | `sleepnumber/agh-scanner:lite` | Docker-first, CI |
| **VS Code Marketplace** | `agh-security` | IDE users |
| **GitHub Releases** | Standalone binaries (future, via PyInstaller) | Air-gapped environments |
| **pre-commit** | `repo: https://github.com/sleepnumber/agh-local` | Git workflow integration |

---

## 11. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Time to first scan | < 5 min from `pip install` | Manual testing |
| Full scan duration | < 60s for typical repo (< 10K files) | Benchmark suite |
| Pre-commit hook speed | < 5s (gitleaks only) | Benchmark suite |
| Docker image size | < 600MB | CI build output |
| False positive rate | < 10% of findings | Developer feedback |
| Server push success | > 99% of uploads accepted | AGH server logs |
| Findings fixed pre-commit | Trackable via "source: local" tag on server | AGH dashboard |
