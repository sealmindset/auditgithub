# RFC: AGH Local — IDE-to-PR Security Scanning Pipeline

**RFC Number:** AGH-2026-003
**Status:** Draft
**Authors:** Security Engineering
**Audience:** DevOps Engineering, Platform Engineering, Release Engineering
**Date:** 2026-03-05
**Review requested by:** 2026-03-19

---

## 1. Problem Statement

Security scanning happens too late. Today, AGH (Audit GitHub Hub) scans repositories **after** code reaches GitHub. Developers discover vulnerabilities in PR reviews or dashboard alerts — hours or days after writing the code, when context is lost and fix cost is highest.

**We need scanning at the point of authorship**, using the same tools and policies that AGH enforces centrally.

---

## 2. Proposal Summary

Introduce **AGH Local** — a standalone daughter project that brings AGH's scan engines to the developer's workstation and enforces organization security policy through the entire commit-to-merge pipeline.

**Three new components:**

| Component | What | Managed By |
|-----------|------|-----------|
| `agh-policy` | Git repo containing org/repo security policies, tool configs, and GH Actions workflow templates | Security Engineering (mother) |
| `agh-local` | CLI tool + VS Code extension that runs scans locally, driven by policy | Developer (self-service install) |
| AGH Policy Enforcer | GitHub App that validates repos have required workflows and checks pass | Security Engineering (mother) |

**What this is NOT:**
- Not a replacement for AGH server-side scanning (mother continues to verify independently)
- Not a results aggregation pipeline (local scan results stay local — no data flows to AGH)
- Not a new CI/CD platform (uses GitHub Actions natively)

---

## 3. End-to-End Flow (Fishbone)

### 3.1 The Full Developer Lifecycle

```
INSTALL           CONFIGURE         DEVELOP            COMMIT             PUSH              PR                 MERGE
  |                  |                 |                  |                 |                 |                   |
  v                  v                 v                  v                 v                 v                   v
+--------+     +-----------+     +----------+     +------------+    +----------+    +--------------+    +---------------+
| pip    |     | agh init  |     | agh scan |     | pre-commit |    | pre-push |    | GH Actions   |    | Branch        |
| install|     |           |     | (on      |     | hook       |    | hook     |    | workflow      |    | protection    |
| agh-   |     | Pulls     |     | demand)  |     |            |    |          |    |              |    |               |
| local  |     | policy    |     |          |     | Gitleaks   |    | Full     |    | All 5 tools  |    | Required      |
|        |     | from      |     | Developer|     | secrets    |    | policy   |    | Severity     |    | checks pass   |
| -or-   |     | agh-      |     | controls |     | scan       |    | gate     |    | gates        |    | Reviews       |
|        |     | policy    |     | frequency|     |            |    | check    |    | CWE check    |    | approved      |
| VSCode |     | repo      |     |          |     | BLOCK if   |    |          |    | SARIF upload |    |               |
| ext    |     |           |     | Findings |     | secrets    |    | BLOCK or |    | Code coverage|    | Mother scans  |
| install|     | Generates |     | shown in |     | found      |    | WARN per |    |              |    | independently |
|        |     | GH Actions|     | terminal |     |            |    | policy   |    | BLOCK if     |    | post-merge    |
|        |     | workflow  |     | or IDE   |     |            |    | mode     |    | gates fail   |    |               |
+--------+     +-----------+     +----------+     +------------+    +----------+    +--------------+    +---------------+
    |                |                 |                  |                 |                 |                   |
    |           RISK GATE #1      RISK GATE #2       RISK GATE #3     RISK GATE #4      RISK GATE #5        RISK GATE #6
    |           Policy applied    Dev sees issues    Secrets blocked   Policy enforced   CI enforcement      Merge protected
    |           to this repo      before commit      at commit time    at push time      in pipeline         by GH App
    |                                                                                                           |
    |                                                                                                           v
    |                                                                                                   +---------------+
    |                                                                                                   | RISK GATE #7  |
    |                                                                                                   | Mother (AGH)  |
    |                                                                                                   | verifies via  |
    |                                                                                                   | independent   |
    |                                                                                                   | scan. Findings|
    |                                                                                                   | assigned via  |
    |                                                                                                   | git blame.    |
    +---------------------------------------------------------------------------------------------------+---------------+
```

### 3.2 Risk Gates Explained

| Gate | Where | What Blocks | What Passes | Managed By | Configurable? |
|------|-------|-------------|-------------|-----------|---------------|
| **#1 — Policy Applied** | `agh init` | Nothing blocked | Policy pulled, workflow generated | Security Eng | Policy repo |
| **#2 — Dev Awareness** | `agh scan` (manual) | Nothing blocked (informational) | Developer sees findings in terminal/IDE | Developer | Scan frequency is developer's choice |
| **#3 — Secret Prevention** | `git commit` (pre-commit hook) | **Any secret detected** (zero tolerance) | Clean commit | Policy: always enforced | No — secrets always block |
| **#4 — Policy Enforcement** | `git push` (pre-push hook) | Configurable: block or warn | Push proceeds | Policy: `developer_experience.mode` | Yes — strict vs advisory |
| **#5 — CI Verification** | GitHub Actions (PR) | Severity gate failure, CWE violations, missing SARIF | All checks green | Policy: `severity_gates`, `cwe_enforcement` | Yes — per org/repo policy |
| **#6 — Merge Protection** | Branch protection rules | Required checks not passing, reviews not approved | PR merges | Policy: `branch_protection.mode` | Yes — enforced vs advisory |
| **#7 — Mother Verification** | AGH server (post-merge) | N/A (monitoring, not blocking) | Findings assigned to developers | AGH Scheduler | Scan frequency via AGH |

### 3.3 What Happens at Each Stage (Detail)

**INSTALL (one-time)**
```bash
# Option A: CLI only
pip install agh-local

# Option B: VS Code Extension (includes CLI)
# Install "AGH Security" from VS Code Marketplace

# Option C: Both
pip install agh-local
# + install VS Code extension
```

> **DevOps input needed:** Package distribution strategy — internal PyPI mirror? Artifactory? Direct from GitHub releases? Homebrew tap for macOS?

**CONFIGURE (per-repo, one-time)**
```bash
cd my-project
agh init
```

This command:
1. Detects the GitHub org from `git remote` (e.g., `sleepnumberlabs`)
2. Fetches policy from `agh-policy` repo (public or private with auth)
3. Resolves effective policy (org default + repo-specific override if exists)
4. Generates `.github/workflows/agh-scan.yaml` from policy template
5. Generates `.pre-commit-config.yaml` entries (or appends to existing)
6. Prints summary of what policy requires

Developer commits the generated files in their next PR.

> **DevOps input needed:** Should `agh init` be part of a repo creation template/cookiecutter? Should new repos auto-receive a PR from the GitHub App instead?

**DEVELOP (ongoing, developer-controlled)**
```bash
agh scan                    # Full scan, all policy-required tools
agh scan --tool semgrep     # Single tool for quick check
```

Or in VS Code: findings appear in Problems panel automatically.

Developer controls frequency. No server call. No telemetry. Results stay local.

**COMMIT**
```
git commit -m "feat: add login endpoint"
  |
  pre-commit hook fires
  |
  agh scan --tool gitleaks --quiet
  |
  +-- secrets found?
  |     YES -> commit BLOCKED, findings printed
  |     NO  -> commit proceeds
```

> **DevOps input needed:** Pre-commit hooks require `pre-commit install` in each repo. Should this be enforced via repo template? Husky as an alternative for Node.js repos?

**PUSH**
```
git push origin feature/login
  |
  pre-push hook fires
  |
  agh policy check
  |
  +-- strict mode?
  |     YES -> gates fail = push BLOCKED
  |     NO  -> gates fail = WARNING printed, push proceeds
```

> **DevOps input needed:** Strict vs advisory mode is set per org/repo in policy. Who decides which repos are strict? Security? DevOps? Repo owners?

**PR (GitHub Actions)**
```
PR opened against main
  |
  agh-scan.yaml workflow triggers
  |
  Jobs run in parallel:
    agh-secrets    (gitleaks)
    agh-sast       (semgrep + bandit)
    agh-iac        (checkov)
    agh-dependencies (trivy)
  |
  Then:
    agh-cwe-check  (scan SARIF for blocked CWEs)
    agh-policy-gate (final pass/fail)
  |
  SARIF uploaded to GitHub Code Scanning
  |
  +-- all checks pass?
        YES -> PR is mergeable (pending reviews)
        NO  -> PR blocked (if branch protection = enforced)
             or check shows failed but merge allowed (if advisory)
```

> **DevOps input needed:**
> - Runner infrastructure: GitHub-hosted or self-hosted runners?
> - Docker-in-Docker: scanner tools run as GH Actions (not Docker container), but some tools need container access. Any restrictions?
> - SARIF upload: requires `security-events: write` permission on the workflow. Any org-level restrictions on this?
> - Secret scanning: GitHub Advanced Security's native secret scanning — overlap with gitleaks? Use both or consolidate?

**MERGE**
```
PR approved + all checks green
  |
  Merge to main
  |
  Mother (AGH) scheduler detects new commits
  |
  AGH runs independent full scan
  |
  Findings compared to what GH Actions found
  |
  +-- new findings?
        YES -> assigned to developer via git blame
             -> visible on AGH dashboard
             -> notification (email/Slack, configurable)
        NO  -> repo marked compliant
```

---

## 4. Policy Architecture (How Mother Prescribes)

### 4.1 Policy Flow

```
Security Engineering                          Developers
       |                                          |
       v                                          |
+------------------+                              |
| agh-policy repo  |                              |
| (GitHub)         |                              |
|                  |    agh init / agh scan        |
| org/             | <----------------------------+
|   sleepnumberlabs/                              |
|     policy.yaml  |    GH Actions workflow       |
|     semgrep-rules/| --------------------------> |
|     gitleaks.toml |                              |
|                  |    GitHub App enforcement      |
| repos/           | --------------------------> |
|   {repo}/        |                              |
|     policy.yaml  |                              |
+------------------+                              |
```

### 4.2 What Policy Controls

| Policy Section | What It Defines | Who Cares |
|---------------|-----------------|-----------|
| `required_tools` | Which scanners must run, minimum versions, language triggers | DevOps (tool availability), Dev (what runs locally) |
| `severity_gates.block_on` | Severity levels that block merge (zero tolerance) | Security (risk), Dev (what they must fix) |
| `severity_gates.warn_on` | Severity levels that warn but don't block | Dev (awareness) |
| `cwe_enforcement.block_on` | Specific vulnerability classes that always block | Security (compliance) |
| `coverage` | Code coverage thresholds | Dev leads, QA |
| `sarif` | SARIF upload requirements | DevOps (GH Code Scanning setup) |
| `github_actions.required_checks` | Named checks that must exist and pass | DevOps (CI config), GitHub App |
| `branch_protection` | Merge rules, required reviews, check enforcement | DevOps (repo admin), Security (enforcement) |
| `developer_experience.mode` | Strict (block) vs advisory (warn) for local hooks | Dev leads (team readiness) |

### 4.3 Policy Inheritance

```
org/sleepnumberlabs/policy.yaml         # Baseline for all repos
  |
  +-- repos/sleepnumberlabs/android-consumer-app/policy.yaml
  |     (overrides: stricter severity, more reviews)
  |
  +-- repos/sleepnumberlabs/internal-docs/policy.yaml
  |     (overrides: relaxed coverage, fewer tools)
  |
  +-- all other repos: inherit org baseline as-is
```

> **DevOps input needed:** Who has write access to `agh-policy` repo? Should policy changes require PR review by DevOps + Security? What's the approval flow for policy changes?

---

## 5. Infrastructure Requirements

### 5.1 New Infrastructure

| Component | Hosting | Resources | Managed By |
|-----------|---------|-----------|-----------|
| `agh-policy` repo | GitHub (existing org) | Negligible (config files only) | Security Eng |
| `agh-local` CLI | PyPI (or internal mirror) | Package hosting | DevOps |
| `agh-local` Docker image | Container registry (GHCR, ACR, or Docker Hub) | ~500MB image | DevOps |
| VS Code extension | VS Code Marketplace (or internal gallery) | Extension package | DevOps |
| GitHub App | Hosted service (Azure App Service, container, or Lambda) | Lightweight webhook processor | DevOps + Security |

### 5.2 GitHub Actions Impact

| Concern | Impact | Mitigation |
|---------|--------|-----------|
| Runner minutes | 5 parallel jobs per PR, ~3-5 min total | Runs only on PR + push to main (not every commit) |
| Concurrent jobs | One workflow per PR | Standard GitHub Actions concurrency limits apply |
| SARIF storage | ~50KB per scan per tool | GitHub retains per `sarif.retain_days` (90 default) |
| Secrets | No AGH secrets needed in CI | Tools run without API keys; policy repo is accessible |
| Permissions | `security-events: write`, `pull-requests: write`, `contents: read` | Standard, no elevated permissions |

> **DevOps input needed:**
> - Self-hosted runners: any repos that can't use GitHub-hosted runners (network access, compliance)?
> - Actions allowlist: are the required GH Actions (gitleaks-action, semgrep-action, trivy-action, checkov-action, codeql-action) on the org's allowed list?
> - Concurrency limits: any org-level concurrency restrictions that would queue scans?

### 5.3 Developer Workstation Requirements

| Requirement | Why | Alternative |
|-------------|-----|------------|
| Docker Desktop | Preferred scan engine (consistent, no local tool installs) | Native tool install via Homebrew/pip |
| Python 3.9+ | CLI runtime | Docker-only mode (no Python needed for scanning) |
| Git 2.x | Pre-commit hooks, remote detection | Already present on all dev machines |
| ~1GB disk | Docker image cache + scan results | Prune with `docker image prune` |
| Network (first run) | Pull policy repo, pull Docker image | After first run, works offline with cached policy |

> **DevOps input needed:**
> - Docker Desktop licensing: are all developers licensed? Any machines without Docker?
> - Proxy/VPN: can developers reach GitHub (agh-policy repo) and container registry from their workstations?
> - Homebrew/pip access: any restrictions on installing packages from public registries?

---

## 6. GitHub App: Policy Enforcer

### 6.1 What It Does

| Event | App Response |
|-------|-------------|
| New repo created in org | Opens PR to add `agh-scan.yaml` workflow |
| PR opened | Verifies `agh-scan.yaml` exists and matches current policy version |
| PR checks complete | Verifies all required checks from policy passed |
| `agh-scan.yaml` modified by developer | Flags drift: "This workflow is managed by AGH policy. Changes will be overwritten." |
| Policy updated in `agh-policy` repo | Regenerates workflows, opens PRs to update affected repos |
| Branch protection config in policy | Applies branch protection rules via GitHub API |

### 6.2 Permissions Required

```
GitHub App: "AGH Policy Enforcer"
  Repository permissions:
    Contents:       Read & Write    (commit workflow files via PR)
    Pull requests:  Read & Write    (open PRs, comment)
    Checks:         Read & Write    (create check runs for compliance)
    Administration: Read & Write    (branch protection — configurable per repo)
    Statuses:       Read & Write    (set commit statuses)
    Metadata:       Read            (detect new repos)

  Organization permissions:
    Members:        Read            (map developers to AGH users)

  Webhook events:
    push, pull_request, check_suite, repository, branch_protection_rule
```

> **DevOps input needed:**
> - GitHub App hosting: where does this run? Azure App Service? AKS? Lambda?
> - Administration: Write permission is needed for branch protection. Is this acceptable org-wide, or should it be opt-in per repo?
> - Rate limits: GitHub API rate limits for the App. With N repos, how many API calls per hour? Need to size the token bucket.

---

## 7. What We Need From DevOps

### 7.1 Decisions Needed

| # | Decision | Options | Impact |
|---|----------|---------|--------|
| 1 | **Package distribution** | PyPI public, internal PyPI mirror, GitHub Releases, Homebrew tap | How developers install `agh-local` |
| 2 | **Container registry** | GHCR, ACR, Docker Hub, internal registry | Where scanner Docker image lives |
| 3 | **VS Code extension distribution** | Public marketplace, internal VSIX gallery, manual install | How IDE extension is distributed |
| 4 | **GitHub App hosting** | Azure App Service, AKS pod, AWS Lambda, GitHub-hosted | Where webhook processor runs |
| 5 | **Runner type** | GitHub-hosted, self-hosted, mix | GH Actions execution environment |
| 6 | **GH Actions allowlist** | Add gitleaks/semgrep/trivy/checkov/codeql actions | Required for CI workflow to run |
| 7 | **Branch protection authority** | GitHub App manages, repo owners manage, hybrid | Who controls merge rules |
| 8 | **Repo creation template** | Include `agh init` in template, GitHub App auto-provisions, manual | How new repos get the workflow |
| 9 | **Pre-commit enforcement** | Repo template, Husky alternative for Node repos, honor system | How hooks get installed |
| 10 | **Policy repo access** | Public (internal), private (auth required), mirrored | How developers and CI access policy |

### 7.2 Infrastructure To Provision

| Item | Effort | Blocks |
|------|--------|--------|
| Container registry namespace for `agh-scanner` image | S | Phase 2 (CLI) |
| PyPI/package hosting for `agh-local` | S | Phase 2 (CLI) |
| GitHub App registration in org | M | Phase 5 (Enforcer) |
| Hosting for GitHub App webhook processor | M | Phase 5 (Enforcer) |
| VS Code extension publishing pipeline | S | Phase 6 (Extension) |
| `agh-policy` repo creation with branch protection + CODEOWNERS | S | Phase 1 (Policy) |

### 7.3 Review Checkpoints

We'd like DevOps review at these milestones:

| Milestone | What to Review | When |
|-----------|---------------|------|
| Policy schema finalized | Does policy.yaml cover all CI concerns? Anything missing? | Phase 1 |
| Generated GH Actions workflow | Will this run on our runners? Any actions blocked? Permissions OK? | Phase 3 |
| GitHub App spec | Permissions acceptable? Hosting plan? | Phase 5 (design) |
| First repo rollout | End-to-end test on a pilot repo | After Phase 3 |

---

## 8. Security Model

### 8.1 Trust Boundaries

```
+---------------------+          +---------------------+         +------------------+
| Developer Machine   |          | GitHub              |         | AGH Server       |
| (untrusted)         |          | (trusted infra)     |         | (trusted)        |
|                     |          |                     |         |                  |
| agh-local runs      |   push  | GH Actions runs     |  scan   | Mother scans     |
| scans locally       | ------> | same tools in CI    | <------ | independently    |
|                     |          |                     |         |                  |
| Results stay local  |          | SARIF uploaded to   |         | Findings on      |
| (no exfiltration)   |          | Code Scanning       |         | dashboard        |
+---------------------+          +---------------------+         +------------------+
        |                                  |                              |
   Developer can                    CI is the                     Mother is the
   skip local scan                  enforcement                   verification
   (their choice)                   point (required)              layer (trust
                                                                  but verify)
```

**Key insight:** We don't trust the developer's local machine. Local scanning is a **developer productivity tool**, not an enforcement point. Enforcement happens in CI (GitHub Actions) and verification happens server-side (AGH).

### 8.2 What Could Go Wrong

| Risk | Mitigation |
|------|-----------|
| Developer skips local scan | CI catches everything — local scan is optional productivity tool |
| Developer removes GH Actions workflow | GitHub App detects drift, opens PR to restore, flags non-compliance |
| Developer modifies workflow to skip checks | GitHub App validates workflow content matches policy template hash |
| Developer force-pushes to main | Branch protection prevents (when enforced) |
| Policy repo compromised | Branch protection + CODEOWNERS on `agh-policy` repo; changes require Security review |
| GitHub App token compromised | Minimal permissions; Administration:write is opt-in per repo |
| Scanner tool has false negatives | Mother's independent scan catches what CI missed |

---

## 9. Rollout Plan

### Phase 0: Pilot (1-2 repos, 2 weeks)

- Select 2 repos: 1 actively developed, 1 stable
- Security Eng sets up `agh-policy` repo with org policy
- Manually run `agh init` on pilot repos
- Validate GH Actions workflow runs correctly
- Gather DevOps feedback on runner performance, permissions, etc.

### Phase 1: Voluntary Adoption (org-wide, 4 weeks)

- Announce `agh-local` availability to all developers
- Include in onboarding docs
- GitHub App opens PRs to add workflow (developer chooses to merge)
- Branch protection in **advisory** mode (checks run but don't block)

### Phase 2: Required CI (org-wide, 4 weeks after Phase 1)

- GitHub App sets branch protection to **enforced** on designated repos
- Required checks must pass for merge
- Grace period: 2 weeks warning, then enforcement

### Phase 3: Full Enforcement (ongoing)

- All new repos auto-provisioned via GitHub App
- Policy updates propagate immediately
- Mother verification scanning active
- Compliance dashboard visible to leadership

> **DevOps input needed:** Does this rollout cadence work? Which repos should pilot? Any repos that need exemption?

---

## 10. Open Questions

| # | Question | For | Impact |
|---|----------|-----|--------|
| 1 | Can we add third-party GH Actions (gitleaks, semgrep, trivy, checkov, codeql) to the org allowlist? | DevOps / GitHub Admin | Blocks CI workflow entirely |
| 2 | Self-hosted runners: any repos that require them? What's the runner image? | DevOps | Workflow may need runner label changes |
| 3 | Docker Desktop licensing: universal across dev org? | DevOps / IT | Affects whether Docker-based local scanning is viable for all devs |
| 4 | Where should the GitHub App run? Existing infra preference? | DevOps | Hosting decision for Phase 5 |
| 5 | Branch protection: who has final say — repo owner or security policy? | DevOps / Security / Engineering Leads | Governance model for enforcement |
| 6 | GitHub Advanced Security: already enabled? SARIF upload requires it for private repos. | DevOps / GitHub Admin | May need GHAS license for Code Scanning on private repos |
| 7 | Existing CI workflows: will `agh-scan.yaml` conflict with current workflows? | DevOps / Repo Owners | Naming, trigger, runner conflicts |
| 8 | Network egress: can GH Actions runners reach the `agh-policy` repo and public registries (PyPI, Docker Hub)? | DevOps / Network | Tool installation in CI |
| 9 | Repo creation automation: is there an existing template/cookiecutter? Can we add `agh init` to it? | DevOps | Onboarding automation |
| 10 | Monitoring: where should GitHub App health metrics go? Datadog? Grafana? CloudWatch? | DevOps | Observability for Phase 5 |

---

## 11. Timeline

```
Week 1-2     Week 3-4     Week 5-6     Week 7-8     Week 9-10    Week 11-12
   |            |            |            |            |             |
   v            v            v            v            v             v
 Policy      Core CLI     agh init     Auth +       GH App       VS Code
 repo +      + Docker     + GH Actions  Private     Policy       Extension
 schema      scanner      generation   policy      Enforcer
                                       repos
   |            |            |                         |
   |      DevOps review:    DevOps review:       DevOps review:
   |      runner compat     workflow + perms      App hosting +
   |      registry setup    pilot repos           branch protection
   |
 DevOps review:
 policy schema
```

---

## 12. Appendix: Glossary

| Term | Definition |
|------|-----------|
| **Mother** | AGH server — defines policy, runs independent verification scans |
| **Daughter** | AGH Local — developer-side CLI/extension, runs local scans |
| **Policy** | YAML definition of required tools, severity gates, CWE blocks, CI checks, branch rules |
| **agh-policy** | GitHub repo containing all policy definitions and tool configurations |
| **agh-local** | Python CLI + VS Code extension for local security scanning |
| **AGH Policy Enforcer** | GitHub App that validates repo compliance with policy |
| **Severity gate** | Threshold that blocks merge (e.g., zero critical/high findings) |
| **CWE enforcement** | Specific vulnerability classes (e.g., SQL injection) that always block |
| **Advisory mode** | Checks run, warnings shown, but merge is not blocked |
| **Enforced mode** | Checks must pass for merge to proceed |
| **SARIF** | Static Analysis Results Interchange Format — standard output format for security tools |
| **Device Flow** | OAuth 2.0 RFC 8628 — browser-based auth for CLI tools (no client secret on disk) |
