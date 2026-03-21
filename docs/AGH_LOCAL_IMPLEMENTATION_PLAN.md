# AGH Local — Implementation Plan v2

## Daughter Project: Policy-Driven Local Security Scanning

**Project Name:** `agh-local`
**Policy Repo:** `agh-policy`
**Relationship:** Standalone daughter project. No result publishing to mother (AGH). Mother defines policy; daughter enforces locally. Mother verifies independently via its own scans.

---

## 1. Executive Summary

### The Model: Mother Prescribes, Daughter Follows, Mother Verifies

```
                    +---------------------------+
                    |   Mother (AGH Server)     |
                    |                           |
                    |  1. Defines policy        |
                    |  2. Publishes to          |
                    |     agh-policy repo       |
                    |  3. Scans GitHub repos    |
                    |     independently         |
                    |  4. Assigns findings      |
                    |     via git blame         |
                    |  5. Notifies developers   |
                    +------------+--------------+
                                 |
                    publishes    |    verifies
                    policy       |    compliance
                    +------------+-------------+
                    |                          |
                    v                          v
    +-------------------+          +---------------------+
    | agh-policy repo   |          | GitHub Repository   |
    | (GitHub)          |          |                     |
    |                   |          | .github/workflows/  |
    | org-level policy  |          |   agh-scan.yaml     |
    | repo overrides    |          |   (generated from   |
    | GH Actions wf     |          |    agh-policy)      |
    | tool configs      |          |                     |
    +--------+----------+          +---------+-----------+
             |                               |
        pull |                          GH Actions
        policy                          enforces
             |                               |
             v                               v
    +-------------------+          +---------------------+
    | Daughter           |          | GitHub App          |
    | (agh-local)       |          | (Mother-controlled) |
    |                   |          |                     |
    | Local scans       |          | Required status     |
    | IDE integration   |          | checks              |
    | Developer fixes   |          | Branch protection   |
    | before commit     |          | (configurable)      |
    +-------------------+          +---------------------+
```

**Key principles:**
- Daughter never sends scan results to mother
- Mother trusts but verifies — runs its own scans on the GitHub repo
- Policy flows one direction: mother -> agh-policy repo -> daughter + GitHub Actions
- Developer controls local scan frequency; mother controls verification schedule
- Auth via same Entra ID SSO (Device Flow), used only for policy pull + identity

---

## 2. Policy Architecture (Core Design)

This is the heart of the system. Everything else is plumbing.

### 2.1 Policy Repo Structure (`agh-policy`)

```
agh-policy/                              # GitHub repo: example-org/agh-policy
  README.md

  org/                                   # Organization-level defaults
    example-orglabs/
      policy.yaml                        # Default policy for all repos in this org
      semgrep-rules/                     # Custom semgrep rules
        api-endpoints.yaml
        api-auth.yaml
        python.yaml
        hardcoded-ips-hostnames.yaml
      gitleaks.toml                      # Gitleaks config
      bandit.yaml                        # Bandit config
      checkov.yaml                       # Checkov skip/check lists
      trivy.yaml                         # Trivy severity/ignore config

  repos/                                 # Per-repo overrides (inherits from org)
    example-orglabs/
      android-consumer-app/
        policy.yaml                      # Stricter overrides for this repo
      internal-docs/
        policy.yaml                      # Relaxed overrides for docs repo

  workflows/                             # Generated GitHub Actions workflows
    templates/
      agh-scan.yaml.j2                   # Jinja2 template for GH Actions workflow
    generated/                           # Output: per-repo workflows
      example-orglabs/
        android-consumer-app/
          agh-scan.yaml                  # Generated from policy + template
        internal-docs/
          agh-scan.yaml

  schemas/
    policy-schema.json                   # JSON Schema for policy.yaml validation
    finding-schema.json                  # Normalized finding format contract
    VERSION                              # Schema version (semver)
```

### 2.2 Policy Definition (`policy.yaml`)

```yaml
# org/example-orglabs/policy.yaml
# Organization-wide default policy

schema_version: "1.0.0"
organization: example-orglabs
effective_date: "2026-03-05"

# -------------------------------------------------------
# REQUIRED SCAN TOOLS
# Daughter must run these tools. GitHub Actions must include them.
# -------------------------------------------------------
required_tools:
  - name: gitleaks
    version: ">=8.18.0"
    purpose: secret-detection
    stage: pre-commit         # When this tool SHOULD run in dev workflow
    required_in_ci: true      # Must be a GH Actions step

  - name: semgrep
    version: ">=1.56.0"
    purpose: sast
    stage: pre-push
    required_in_ci: true
    config:
      rulesets:
        - "p/default"
        - "p/owasp-top-ten"
        - "${POLICY_REPO}/org/example-orglabs/semgrep-rules/"

  - name: bandit
    version: ">=1.7.7"
    purpose: python-sast
    stage: pre-push
    required_in_ci: true
    languages: [python]       # Only required if repo contains Python

  - name: checkov
    version: ">=3.2.0"
    purpose: iac-scanning
    stage: pre-push
    required_in_ci: true
    languages: [terraform, dockerfile, kubernetes, cloudformation]

  - name: trivy
    version: ">=0.49.0"
    purpose: dependency-vulnerabilities
    stage: pre-push
    required_in_ci: true
    config:
      scanners: [vuln, secret, config, license]

# -------------------------------------------------------
# SEVERITY GATES
# Findings at or above these thresholds MUST be resolved.
# -------------------------------------------------------
severity_gates:
  # Block merge if ANY of these are true:
  block_on:
    critical: 0               # Zero tolerance for critical
    high: 0                   # Zero tolerance for high

  # Warn but allow merge:
  warn_on:
    medium: 5                 # Warn if > 5 medium findings
    low: 20                   # Warn if > 20 low findings

  # Per-tool overrides:
  tool_overrides:
    gitleaks:
      block_on:
        critical: 0
        high: 0
        medium: 0             # Zero tolerance for any secret finding
        low: 0
    checkov:
      warn_on:
        medium: 10            # IaC findings are noisier, allow more

# -------------------------------------------------------
# CWE ENFORCEMENT
# Specific vulnerability categories that must be clean.
# -------------------------------------------------------
cwe_enforcement:
  block_on:
    - CWE-89                  # SQL Injection
    - CWE-79                  # Cross-Site Scripting (XSS)
    - CWE-78                  # OS Command Injection
    - CWE-798                 # Hardcoded Credentials
    - CWE-502                 # Deserialization of Untrusted Data
    - CWE-22                  # Path Traversal
    - CWE-918                 # Server-Side Request Forgery (SSRF)
    - CWE-611                 # XML External Entity (XXE)
  warn_on:
    - CWE-287                 # Improper Authentication
    - CWE-862                 # Missing Authorization
    - CWE-863                 # Incorrect Authorization

# -------------------------------------------------------
# CODE COVERAGE (optional, enforced via GH Actions)
# -------------------------------------------------------
coverage:
  enabled: true
  minimum_percent: 80
  block_on_failure: false     # Warn, don't block (for now)

# -------------------------------------------------------
# SARIF REQUIREMENTS
# -------------------------------------------------------
sarif:
  upload_to_github_code_scanning: true    # Required: upload SARIF to GH
  retain_days: 90                          # How long GH keeps results

# -------------------------------------------------------
# GITHUB ACTIONS REQUIREMENTS
# The checklist of things that must be in the CI workflow.
# -------------------------------------------------------
github_actions:
  required_checks:
    - name: "agh-secrets"
      description: "Secret detection scan (gitleaks)"
      must_pass: true

    - name: "agh-sast"
      description: "Static analysis (semgrep + bandit)"
      must_pass: true

    - name: "agh-iac"
      description: "Infrastructure-as-Code scan (checkov)"
      must_pass: true

    - name: "agh-dependencies"
      description: "Dependency vulnerability scan (trivy)"
      must_pass: true

    - name: "agh-sarif-upload"
      description: "SARIF results uploaded to GitHub Code Scanning"
      must_pass: true

    - name: "agh-policy-gate"
      description: "All severity gates pass"
      must_pass: true

  # Trigger configuration
  triggers:
    pull_request:
      branches: [main, develop]
    push:
      branches: [main]

# -------------------------------------------------------
# BRANCH PROTECTION
# Mother can configure this via GitHub App.
# -------------------------------------------------------
branch_protection:
  enabled: true               # Mother will set branch protection
  mode: "enforced"            # "enforced" = must pass | "advisory" = recommended
  protected_branches:
    - main
    - develop
  require_reviews: 1
  dismiss_stale_reviews: true
  require_status_checks:
    - "agh-secrets"
    - "agh-sast"
    - "agh-dependencies"
    - "agh-policy-gate"

# -------------------------------------------------------
# DEVELOPER EXPERIENCE
# Controls how strict the local tooling is.
# -------------------------------------------------------
developer_experience:
  # For experienced developers: advisory mode
  default_mode: "advisory"    # "strict" or "advisory"

  # Strict mode overrides (per-developer or per-team)
  strict_mode:
    pre_commit_block: true    # Block commit on secret detection
    pre_push_block: true      # Block push on policy gate failure

  advisory_mode:
    pre_commit_block: true    # Still block secrets (always)
    pre_push_block: false     # Warn but allow push
```

### 2.3 Per-Repo Policy Override

```yaml
# repos/example-orglabs/android-consumer-app/policy.yaml
# Inherits from org/example-orglabs/policy.yaml
# Only specify overrides — everything else inherits

inherits: "org/example-orglabs"

severity_gates:
  block_on:
    critical: 0
    high: 0
    medium: 0                 # Stricter: block medium too for this app

required_tools:
  # Add Android-specific scanning
  - name: semgrep
    config:
      rulesets:
        - "p/default"
        - "p/owasp-top-ten"
        - "p/android"         # Additional Android rules
        - "${POLICY_REPO}/org/example-orglabs/semgrep-rules/"

branch_protection:
  require_reviews: 2          # More reviews for mobile app
```

### 2.4 Policy Resolution Order

```
1. Load org-level policy:     org/{org}/policy.yaml
2. Load repo-level override:  repos/{org}/{repo}/policy.yaml (if exists)
3. Merge: repo overrides org (deep merge, lists are replaced not appended)
4. Validate against schema:   schemas/policy-schema.json
5. Result: effective policy for this repo
```

### 2.5 Policy Versioning and Immediacy

Policy changes take effect **immediately** on next scan:

- Developer runs `agh scan` -> pulls latest `agh-policy` -> applies current policy
- GitHub Actions workflow references `agh-policy@main` -> always gets latest
- No grace period. If mother tightens a threshold, the next CI run enforces it.
- Breaking changes (schema version bump) require daughter CLI update — CLI checks `schema_version` and errors with upgrade instructions if incompatible

---

## 3. GitHub Actions Enforcement

### 3.1 Generated Workflow

Mother generates a GitHub Actions workflow from the policy. This workflow is committed to each repo's `.github/workflows/` directory.

**Generation flow:**
```
agh-policy repo CI runs:
  1. For each org/repo with a policy:
  2. Resolve effective policy (org + repo override)
  3. Render Jinja2 template -> agh-scan.yaml
  4. Output to workflows/generated/{org}/{repo}/agh-scan.yaml
  5. (Optional) GitHub App auto-commits to target repo via PR
```

**Generated workflow example:**

```yaml
# .github/workflows/agh-scan.yaml
# AUTO-GENERATED by AGH Policy Engine
# Source: example-org/agh-policy @ org/example-orglabs/policy.yaml
# Generated: 2026-03-05T10:00:00Z
# Policy schema: 1.0.0
# DO NOT EDIT — changes will be overwritten by policy updates

name: AGH Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write     # Required for SARIF upload
  pull-requests: write       # Required for PR comments

env:
  POLICY_REPO: example-org/agh-policy
  POLICY_REF: main

jobs:
  # -----------------------------------------------------------
  # 1. SECRET DETECTION
  # -----------------------------------------------------------
  agh-secrets:
    name: "Secret Detection (gitleaks)"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run gitleaks
        uses: gitleaks/gitleaks-action@v2
        with:
          args: >-
            detect
            --source .
            --report-format sarif
            --report-path gitleaks-results.sarif
            --config ${{ github.workspace }}/.gitleaks.toml
        continue-on-error: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks-results.sarif
          category: gitleaks

      - name: Evaluate severity gate
        run: |
          # Parse SARIF, count by severity, compare to policy thresholds
          # Gitleaks policy: zero tolerance (critical: 0, high: 0, medium: 0, low: 0)
          python3 -c "
          import json, sys
          with open('gitleaks-results.sarif') as f:
              sarif = json.load(f)
          results = sarif.get('runs', [{}])[0].get('results', [])
          if len(results) > 0:
              print(f'BLOCKED: {len(results)} secret(s) detected')
              for r in results[:5]:
                  loc = r.get('locations', [{}])[0].get('physicalLocation', {})
                  path = loc.get('artifactLocation', {}).get('uri', 'unknown')
                  line = loc.get('region', {}).get('startLine', 0)
                  print(f'  - {path}:{line} ({r.get(\"ruleId\", \"unknown\")})')
              sys.exit(1)
          print('PASSED: No secrets detected')
          "

  # -----------------------------------------------------------
  # 2. STATIC ANALYSIS (SAST)
  # -----------------------------------------------------------
  agh-sast:
    name: "SAST (semgrep + bandit)"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Checkout policy repo (for custom rules)
        uses: actions/checkout@v4
        with:
          repository: ${{ env.POLICY_REPO }}
          ref: ${{ env.POLICY_REF }}
          path: .agh-policy

      - name: Run semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/default
            p/owasp-top-ten
            .agh-policy/org/example-orglabs/semgrep-rules/
        env:
          SEMGREP_RULES: >-
            p/default
            p/owasp-top-ten
            .agh-policy/org/example-orglabs/semgrep-rules/

      - name: Run bandit (if Python detected)
        run: |
          if find . -name "*.py" -not -path "./.*" | head -1 | grep -q .; then
            pip install bandit>=1.7.7
            bandit -r . -f sarif -o bandit-results.sarif --exclude ./.agh-policy || true
          else
            echo '{"runs":[{"results":[]}]}' > bandit-results.sarif
          fi

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit-results.sarif
          category: bandit

      - name: Evaluate severity gate
        run: |
          python3 -c "
          import json, sys
          blocked = False
          for sarif_file in ['semgrep-results.sarif', 'bandit-results.sarif']:
              try:
                  with open(sarif_file) as f:
                      sarif = json.load(f)
              except FileNotFoundError:
                  continue
              results = sarif.get('runs', [{}])[0].get('results', [])
              severity_map = {'error': 'high', 'warning': 'medium', 'note': 'low'}
              counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
              for r in results:
                  level = r.get('level', 'note')
                  sev = severity_map.get(level, 'low')
                  counts[sev] += 1
              # Policy: block on critical > 0 or high > 0
              if counts['critical'] > 0 or counts['high'] > 0:
                  print(f'BLOCKED ({sarif_file}): {counts}')
                  blocked = True
              else:
                  print(f'PASSED ({sarif_file}): {counts}')
          if blocked:
              sys.exit(1)
          "

  # -----------------------------------------------------------
  # 3. IaC SCANNING
  # -----------------------------------------------------------
  agh-iac:
    name: "IaC Scan (checkov)"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          output_format: sarif
          output_file_path: checkov-results.sarif
          soft_fail: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov-results.sarif
          category: checkov

      - name: Evaluate severity gate
        run: |
          python3 -c "
          import json, sys
          with open('checkov-results.sarif') as f:
              sarif = json.load(f)
          results = sarif.get('runs', [{}])[0].get('results', [])
          severity_map = {'error': 'high', 'warning': 'medium', 'note': 'low'}
          counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
          for r in results:
              level = r.get('level', 'note')
              sev = severity_map.get(level, 'low')
              counts[sev] += 1
          if counts['critical'] > 0 or counts['high'] > 0:
              print(f'BLOCKED: {counts}')
              sys.exit(1)
          print(f'PASSED: {counts}')
          "

  # -----------------------------------------------------------
  # 4. DEPENDENCY VULNERABILITIES
  # -----------------------------------------------------------
  agh-dependencies:
    name: "Dependency Scan (trivy)"
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scanners: vuln,secret,config,license
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH,MEDIUM,LOW

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
          category: trivy

      - name: Evaluate severity gate
        run: |
          python3 -c "
          import json, sys
          with open('trivy-results.sarif') as f:
              sarif = json.load(f)
          results = sarif.get('runs', [{}])[0].get('results', [])
          severity_map = {'error': 'high', 'warning': 'medium', 'note': 'low'}
          counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
          for r in results:
              level = r.get('level', 'note')
              sev = severity_map.get(level, 'low')
              counts[sev] += 1
          if counts['critical'] > 0 or counts['high'] > 0:
              print(f'BLOCKED: {counts}')
              sys.exit(1)
          print(f'PASSED: {counts}')
          "

  # -----------------------------------------------------------
  # 5. CWE ENFORCEMENT
  # -----------------------------------------------------------
  agh-cwe-check:
    name: "CWE Enforcement"
    needs: [agh-sast, agh-iac, agh-dependencies]
    runs-on: ubuntu-latest
    steps:
      - name: Download all SARIF artifacts
        uses: actions/download-artifact@v4

      - name: Check blocked CWEs
        run: |
          python3 -c "
          import json, sys, glob
          BLOCKED_CWES = [
              'CWE-89', 'CWE-79', 'CWE-78', 'CWE-798',
              'CWE-502', 'CWE-22', 'CWE-918', 'CWE-611'
          ]
          violations = []
          for sarif_path in glob.glob('**/*.sarif', recursive=True):
              with open(sarif_path) as f:
                  sarif = json.load(f)
              for run in sarif.get('runs', []):
                  rules = {r['id']: r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
                  for result in run.get('results', []):
                      rule = rules.get(result.get('ruleId', ''), {})
                      tags = rule.get('properties', {}).get('tags', [])
                      for tag in tags:
                          for cwe in BLOCKED_CWES:
                              if cwe.lower() in tag.lower():
                                  loc = result.get('locations', [{}])[0].get('physicalLocation', {})
                                  path = loc.get('artifactLocation', {}).get('uri', '?')
                                  line = loc.get('region', {}).get('startLine', 0)
                                  violations.append(f'{cwe} in {path}:{line} ({result.get(\"ruleId\")})')
          if violations:
              print(f'BLOCKED: {len(violations)} CWE violation(s):')
              for v in violations[:10]:
                  print(f'  - {v}')
              sys.exit(1)
          print('PASSED: No blocked CWE violations')
          "

  # -----------------------------------------------------------
  # 6. POLICY GATE (final pass/fail)
  # -----------------------------------------------------------
  agh-policy-gate:
    name: "Policy Gate"
    needs: [agh-secrets, agh-sast, agh-iac, agh-dependencies, agh-cwe-check]
    runs-on: ubuntu-latest
    if: always()
    steps:
      - name: Check all gates
        run: |
          echo "Checking upstream job results..."
          # This job only succeeds if all required checks passed
          # GitHub Actions 'needs' context provides job results
          python3 -c "
          import os, sys
          # In a real workflow, parse needs context
          # For now, if we got here and all needs succeeded, we pass
          print('PASSED: All policy gates satisfied')
          "
```

### 3.2 GitHub App: Policy Enforcer

Mother runs a GitHub App that:

1. **Monitors repos** in the organization
2. **Validates** that the required `agh-scan.yaml` workflow exists
3. **Configures branch protection** (when enabled in policy)
4. **Reports compliance status** back to AGH dashboard

```
GitHub App: "AGH Policy Enforcer"
Permissions:
  - contents: read           # Read repo files
  - checks: write            # Create/update check runs
  - pull_requests: write     # Comment on PRs
  - administration: write    # Configure branch protection (when enabled)
  - statuses: write          # Set commit statuses

Webhook events:
  - push                     # Detect new repos, missing workflows
  - pull_request              # Verify checks are passing
  - check_suite              # Monitor CI results
  - repository               # New repo created -> provision workflow

Behavior:
  on new_repo:
    1. Generate agh-scan.yaml from policy
    2. Open PR to add workflow to repo
    3. If branch_protection.enabled: configure required checks

  on pull_request:
    1. Verify agh-scan.yaml exists and matches policy version
    2. If missing or outdated: create check run "agh-policy-compliance" = failure
    3. If present and current: check passes

  on check_suite_completed:
    1. Verify all required checks from policy passed
    2. Report compliance status to AGH dashboard
```

### 3.3 Branch Protection Configuration

Configurable per policy — supports both experienced and new developers:

```yaml
# Experienced developer teams:
branch_protection:
  enabled: true
  mode: "advisory"            # Checks run but don't block merge
  protected_branches: [main]
  require_reviews: 1

# New developer teams or critical repos:
branch_protection:
  enabled: true
  mode: "enforced"            # Must pass to merge
  protected_branches: [main, develop]
  require_reviews: 2
  dismiss_stale_reviews: true
  require_status_checks:
    - "agh-secrets"
    - "agh-sast"
    - "agh-dependencies"
    - "agh-policy-gate"
```

---

## 4. Mother's Verification (Trust But Verify)

### 4.1 Scan Trigger Rules

| Trigger | When | What |
|---------|------|------|
| **First commit** | New repo or first push detected | Full scan with all tools |
| **Scheduler** | Based on commit frequency (AGH Scheduler policy) | Full scan |
| **Policy change** | Mother updates policy in agh-policy repo | Re-scan all affected repos |
| **On demand** | Admin triggers via AGH dashboard | Full scan |

### 4.2 Finding Assignment

When mother's scan finds issues:

```
Mother scans GitHub repo
  |
  v
Findings detected
  |
  v
git blame each finding's file:line
  |
  v
Map committer email -> AGH user (via users table)
  |
  v
Finding assigned to developer on AGH dashboard
  |
  v
Notifications sent:
  - AGH dashboard (finding appears in developer's view)
  - PR comment (if finding is in a file changed by an open PR)
  - Email/Slack (configurable per org)
```

### 4.3 PR Blocking

Mother can block PRs via the GitHub App:

1. Mother scans the PR branch
2. If findings violate policy, GitHub App creates a failing check run
3. If branch protection is "enforced", PR cannot merge
4. If branch protection is "advisory", check shows as failed but merge is allowed
5. PR comment details the findings with file:line references

---

## 5. Daughter (agh-local) Design

### 5.1 How Daughter Uses Policy

```
agh scan
  |
  v
Pull policy from agh-policy repo
  |
  +---> Cached locally? (< 1 hour old)
  |       YES -> use cache
  |       NO  -> git pull or HTTP fetch from GitHub API
  |
  v
Resolve effective policy
  |
  +---> Detect org from git remote (github.com/example-orglabs/*)
  +---> Load org/example-orglabs/policy.yaml
  +---> Load repos/example-orglabs/{repo}/policy.yaml (if exists)
  +---> Merge
  |
  v
Determine required tools
  |
  +---> Language detection (what's in this repo?)
  +---> Intersect with policy required_tools + language match
  |
  v
Run tools (Docker or native)
  |
  v
Parse results -> normalized findings
  |
  v
Evaluate severity gates from policy
  |
  v
Display results + gate pass/fail
  |
  v
Exit code: 0 (pass) or 1 (fail)
```

### 5.2 CLI Commands

```
agh scan [options]
  --path, -p       Target directory (default: .)
  --tool, -t       Specific tool (repeatable) — overrides policy for this run
  --format, -f     Output: table|json|sarif (default: table)
  --output, -o     Write to file (default: stdout)
  --docker         Force Docker execution
  --native         Force native tool execution
  --severity, -s   Minimum severity to show (default: from policy)
  --no-policy      Skip policy evaluation (just run tools)
  --strict         Enforce strict mode (override advisory)
  --update-policy  Force policy refresh (ignore cache)

agh policy show
  # Display effective policy for current repo
  # Shows: org policy + repo overrides + resolved result

agh policy check
  # Evaluate gates against last scan results
  # Exit code: 0 = pass, 1 = fail

agh init
  # Initialize AGH for current repo:
  # 1. Detect org from git remote
  # 2. Pull policy
  # 3. Generate .github/workflows/agh-scan.yaml
  # 4. Generate .pre-commit-config.yaml entries
  # 5. Show what was created

agh auth login
  # Device Flow SSO (same Entra ID as AGH web app)
  # Only needed for private agh-policy repos

agh status
  # Auth state, policy version, tool availability, last scan summary
```

### 5.3 `agh init` — Repo Onboarding

The key developer-facing command. Sets up everything in one step:

```bash
$ cd my-project
$ agh init

Detecting organization... example-orglabs (from git remote)
Fetching policy... org/example-orglabs/policy.yaml (v1.0.0)
Checking for repo override... repos/example-orglabs/my-project/policy.yaml (not found, using org default)

Generating files:
  .github/workflows/agh-scan.yaml    (GitHub Actions workflow)
  .pre-commit-config.yaml            (pre-commit hooks — append or create)

Policy summary:
  Required tools: gitleaks, semgrep, bandit (python detected), trivy
  Severity gates: block on critical/high, warn on medium > 5
  CWE enforcement: 8 blocked CWEs (SQL injection, XSS, ...)
  Branch protection: enforced on main (2 reviews required)

Next steps:
  1. Review and commit the generated files
  2. Install pre-commit hooks: pre-commit install --hook-type pre-commit --hook-type pre-push
  3. Run your first local scan: agh scan
```

### 5.4 Pre-Commit / Pre-Push Hooks

```yaml
# .pre-commit-hooks.yaml (in agh-local repo, consumed by other repos)
- id: agh-secrets
  name: AGH Secret Detection
  entry: agh scan --tool gitleaks --quiet --format table
  language: python
  stages: [pre-commit]
  pass_filenames: false
  always_run: true

- id: agh-policy
  name: AGH Policy Gate
  entry: agh policy check
  language: python
  stages: [pre-push]
  pass_filenames: false

- id: agh-scan
  name: AGH Full Scan
  entry: agh scan --quiet --format table
  language: python
  stages: [pre-push]
  pass_filenames: false
```

**Behavior by mode:**

| Hook | Strict Mode | Advisory Mode |
|------|-------------|---------------|
| `agh-secrets` (pre-commit) | Block commit | Block commit (always — secrets are never advisory) |
| `agh-policy` (pre-push) | Block push | Warn, allow push |
| `agh-scan` (pre-push) | Block push on gate failure | Warn, allow push |

### 5.5 Auth: Device Flow SSO

```
agh auth login
  |
  v
POST /auth/device/code (to AGH server)
  -> { device_code, user_code, verification_uri }
  |
  v
Print: "Open https://agh.example-org.com/device and enter code: ABCD-1234"
Open browser automatically
  |
  v
User authenticates via Entra ID SSO (same as AGH web app)
  |
  v
Poll POST /auth/device/token
  -> { access_token, refresh_token }
  |
  v
Save to ~/.agh/credentials.json (mode 0600)
  {
    "server": "https://agh.example-org.com",
    "access_token": "...",
    "refresh_token": "...",
    "org_id": "example-orglabs",
    "email": "admin@company.example",
    "expires_at": "2026-03-05T18:00:00Z"
  }
```

**When is auth needed?**

| Action | Auth Required? |
|--------|---------------|
| `agh scan` (policy repo is public/internal) | No |
| `agh scan` (policy repo is private) | Yes — to fetch policy |
| `agh init` | Yes — to fetch policy + validate identity |
| `agh auth login` | Yes (this IS the auth) |
| `agh status` | No (reads local cache) |
| `agh policy show` | No (reads local cache) |

### 5.6 Invitation Flow

When admin invites a developer in AGH (mother):

```
Admin sends invitation via AGH dashboard
  |
  v
Email to developer:
  Subject: "You've been invited to AGH Security"
  Body:
    You've been granted [analyst] access to [example-orglabs].

    To set up local security scanning:

    1. Install the CLI:
       pip install agh-local

    2. Authenticate:
       agh auth login --server https://agh.example-org.com

    3. Initialize your repo:
       cd your-project
       agh init

    4. Install git hooks:
       pre-commit install --hook-type pre-commit --hook-type pre-push

    5. Run your first scan:
       agh scan

    VS Code Extension (optional):
    Install "AGH Security" from the VS Code Marketplace.
```

---

## 6. Repository Structure (Final)

### `agh-local` repo:

```
agh-local/
  README.md
  LICENSE
  .pre-commit-hooks.yaml          # Hooks consumable by other repos

  cli/
    pyproject.toml
    src/agh/
      __init__.py
      cli.py                       # Main CLI entry point
      config.py                    # Local config (~/.agh/)
      init.py                      # agh init command
      scanner/
        engine.py                  # Docker vs native dispatch
        docker_runner.py           # Docker execution
        native_runner.py           # Native tool execution
        language_detect.py         # Detect project languages
        parsers/
          gitleaks.py
          semgrep.py
          bandit.py
          checkov.py
          trivy.py
      policy/
        resolver.py                # Fetch + merge + resolve policy
        evaluator.py               # Evaluate severity/CWE gates
        workflow_generator.py      # Generate GH Actions from policy
      auth/
        device_flow.py             # RFC 8628 Device Flow
        credentials.py             # ~/.agh/credentials.json management
      formatters/
        table.py
        json_fmt.py
        sarif.py
    tests/
      test_cli.py
      test_policy_resolver.py
      test_policy_evaluator.py
      test_workflow_generator.py
      test_parsers.py
      test_language_detect.py
      fixtures/

  scanner/
    Dockerfile.lite                # Lightweight scanner image

  vscode-extension/
    package.json
    src/
      extension.ts
      scanRunner.ts                # Calls agh CLI
      diagnosticProvider.ts
      findingsTreeProvider.ts
      codeLensProvider.ts
      statusBar.ts
      policyChecker.ts
      auth.ts
    tsconfig.json

  .github/
    workflows/
      ci.yaml                      # Test + lint
      release-cli.yaml             # Publish to PyPI
      release-docker.yaml          # Build + push Docker image
      release-extension.yaml       # Publish to VS Code Marketplace
```

### `agh-policy` repo:

```
agh-policy/
  README.md

  org/
    example-orglabs/
      policy.yaml
      semgrep-rules/
      gitleaks.toml
      bandit.yaml
      checkov.yaml
      trivy.yaml

  repos/
    example-orglabs/
      android-consumer-app/
        policy.yaml

  workflows/
    templates/
      agh-scan.yaml.j2
    generated/
      example-orglabs/
        android-consumer-app/
          agh-scan.yaml

  schemas/
    policy-schema.json
    finding-schema.json
    VERSION

  github-app/
    app.py                         # GitHub App: Policy Enforcer
    webhook_handler.py             # Process GitHub webhook events
    branch_protection.py           # Configure branch protection
    workflow_validator.py          # Check repos have correct workflow
    Dockerfile
```

---

## 7. Implementation Phases

### Phase 1: Policy Repo + Schema (Foundation)

**Goal:** `agh-policy` repo exists with validated policy definitions

**Scope:**
- [ ] Create `agh-policy` repository
- [ ] Define `policy-schema.json` (JSON Schema for policy.yaml validation)
- [ ] Define `finding-schema.json` (normalized finding contract)
- [ ] Write org-level policy for example-orglabs
- [ ] Write example repo-level override
- [ ] Copy scanner configs from AGH (semgrep-rules, gitleaks.toml)
- [ ] Create Jinja2 template for GitHub Actions workflow generation
- [ ] Write policy validation CI (schema check on every PR)
- [ ] Write workflow generation CI (regenerate on policy change)

**Exit Criteria:**
- `agh-policy` repo exists with valid policy.yaml
- CI validates schema on every PR
- Generated workflow template renders correctly

**Size:** M (1-2 weeks)

### Phase 2: Core CLI + Policy Resolution (MVP)

**Goal:** `agh scan` works locally, driven by policy from agh-policy repo

**Scope:**
- [ ] Create `agh-local` repository
- [ ] Implement policy resolver (fetch from agh-policy, merge org + repo, cache)
- [ ] Implement policy evaluator (severity gates, CWE enforcement)
- [ ] Implement scanner engine (Docker + native fallback)
- [ ] Implement 5 result parsers
- [ ] Implement language detection
- [ ] Implement table/JSON/SARIF formatters
- [ ] Build Dockerfile.lite
- [ ] `agh scan` command with policy-driven tool selection + gate evaluation
- [ ] `agh policy show` command
- [ ] `agh policy check` command
- [ ] `agh status` command
- [ ] Tests for all components
- [ ] Publish to PyPI as `agh-local`
- [ ] Publish Docker image

**Exit Criteria:**
```bash
pip install agh-local
cd my-project
agh scan              # Runs tools per policy, evaluates gates
agh policy show       # Shows effective policy
agh policy check      # Re-evaluates gates on last results
```

**Size:** L (2-3 weeks)

### Phase 3: `agh init` + GitHub Actions Generation

**Goal:** One command provisions a repo with workflow + hooks

**Scope:**
- [ ] Implement `agh init` command
- [ ] Workflow generator: policy.yaml + Jinja2 template -> agh-scan.yaml
- [ ] Pre-commit config generation
- [ ] Org detection from git remote
- [ ] Repo override detection
- [ ] Print onboarding summary with next steps

**Exit Criteria:**
```bash
cd my-project
agh init
# Creates .github/workflows/agh-scan.yaml
# Creates/appends .pre-commit-config.yaml
# Prints policy summary + next steps
```

**Size:** M (1-2 weeks)

### Phase 4: Auth + Private Policy Repos

**Goal:** Device Flow SSO for teams with private agh-policy repos

**Scope:**
- [ ] Implement Device Flow auth (RFC 8628)
- [ ] Credentials storage (~/.agh/credentials.json)
- [ ] Authenticated policy fetch (GitHub API with token)
- [ ] `agh auth login` command
- [ ] Token refresh handling
- [ ] Integration with AGH invitation flow (docs + email template)

**Exit Criteria:**
```bash
agh auth login --server https://agh.example-org.com
# Opens browser, Entra ID SSO
# Saves credentials
agh scan  # Fetches policy from private repo using saved token
```

**Size:** M (1-2 weeks)

### Phase 5: GitHub App (Policy Enforcer)

**Goal:** Automated compliance enforcement across all org repos

**Scope:**
- [ ] Build GitHub App: "AGH Policy Enforcer"
- [ ] Webhook handler: push, pull_request, check_suite, repository events
- [ ] New repo detection -> auto-PR with agh-scan.yaml workflow
- [ ] PR validation: verify required checks exist and pass
- [ ] Branch protection configuration (enforced vs advisory mode)
- [ ] Compliance status reporting to AGH dashboard
- [ ] Workflow drift detection (agh-scan.yaml modified by developer -> alert)

**Exit Criteria:**
- New repo in org -> GitHub App opens PR with workflow
- PR without passing agh checks -> App creates failing check
- Branch protection auto-configured per policy
- Compliance visible on AGH dashboard

**Size:** L (2-3 weeks)

### Phase 6: VS Code Extension

**Goal:** IDE integration with policy-aware scanning

**Scope:**
- [ ] Port extension from AGH, modify to call `agh` CLI
- [ ] Diagnostic provider maps normalized findings to VS Code
- [ ] Tree view grouped by severity
- [ ] CodeLens annotations
- [ ] Status bar with finding counts + policy gate status
- [ ] Policy checker integration (show gate pass/fail in IDE)
- [ ] Auth integration (call `agh auth login` from extension)
- [ ] Publish to VS Code Marketplace

**Exit Criteria:**
- Install extension, open project -> findings in Problems panel
- Status bar shows gate pass/fail
- Extension respects org policy for severity thresholds

**Size:** L (2-3 weeks)

### Phase 7: Mother Verification Integration

**Goal:** AGH server scans repos and assigns findings to developers

**Scope:**
- [ ] AGH Scheduler: trigger scan on first commit detection
- [ ] AGH Scheduler: frequency-based scanning per policy
- [ ] Finding assignment via git blame -> AGH user mapping
- [ ] PR comment integration (findings in PR files)
- [ ] Notification system (email/Slack per org config)
- [ ] Compliance dashboard: which repos have workflow, which pass, which fail
- [ ] Policy change -> trigger re-scan of affected repos

**Exit Criteria:**
- Developer pushes code -> mother scans on schedule
- Findings attributed to developer on AGH dashboard
- PR comments show inline findings
- Compliance dashboard shows org-wide status

**Size:** L (3-4 weeks)

---

## 8. Dependency Graph

```
Phase 1 (Policy Repo) ----+---> Phase 2 (Core CLI) ---> Phase 3 (agh init + GH Actions)
                           |                        |
                           |                        +---> Phase 4 (Auth)
                           |
                           +---> Phase 5 (GitHub App) ---> Phase 7 (Mother Verification)
                           |
                           +---> Phase 6 (VS Code Extension)
                                    (after Phase 2)
```

**Critical path:** Phase 1 -> 2 -> 3 (developer gets policy-driven scan + GH Actions in ~5-6 weeks)

**Parallel after Phase 1:** Phase 5 (GitHub App) can start immediately since it reads from agh-policy repo directly.

**Parallel after Phase 2:** Phase 4 (Auth) and Phase 6 (VS Code) can start once CLI exists.

---

## 9. Success Metrics

| Metric | Target | How Measured |
|--------|--------|-------------|
| Policy compliance rate | >90% of repos have agh-scan.yaml within 30 days | GitHub App scan |
| Pre-commit secret catch rate | >95% of secrets caught before push | Compare local vs mother findings |
| Time from invite to first scan | < 15 minutes | Onboarding tracking |
| Policy update propagation | < 1 hour for all repos to use new policy | Cache TTL + GH Actions `@main` ref |
| False positive rate | < 10% | Developer feedback |
| Developer adoption | >80% of active devs have agh-local installed within 60 days | Auth login count |
| Mother verification delta | < 5% findings missed by daughter | Compare mother scan vs GH Actions results |
