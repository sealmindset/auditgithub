# Security Tools Reference

Complete reference for all security scanning tools used in AuditGH, including current tools, their purposes, and recommended future additions.

---

## Current Tool Inventory

### Overview by Category

| Category | Tools | Purpose |
|----------|-------|---------|
| **Secrets Detection** | Gitleaks, TruffleHog | Find hardcoded credentials |
| **Dependency Scanning** | Grype, Trivy, OWASP DC, Syft | CVEs in packages |
| **Static Analysis (SAST)** | Semgrep, CodeQL, Bandit | Code vulnerabilities |
| **Infrastructure (IaC)** | Checkov, Trivy | Cloud misconfigurations |
| **JavaScript Security** | Retire.js, npm/yarn/pnpm audit | Frontend vulnerabilities |
| **API Security** | Custom scanner, Nuclei | API endpoint discovery |
| **Code Metrics** | cloc | Lines of code analysis |

---

## Secrets Detection

### Gitleaks

| Attribute | Value |
|-----------|-------|
| **Purpose** | Detect hardcoded secrets in git history and working tree |
| **Script** | `scan_repos.py` → `run_gitleaks()` |
| **Output** | `{repo}_gitleaks.json`, `{repo}_gitleaks.md` |
| **Install** | `brew install gitleaks` or [GitHub](https://github.com/gitleaks/gitleaks) |

**What it detects:**
- API keys (AWS, GCP, Azure, etc.)
- Private keys (SSH, PGP)
- Database credentials
- OAuth tokens
- Generic passwords and secrets

**Command used:**
```bash
gitleaks detect --source /path/to/repo --report-format json --report-path output.json --verbose
```

---

### TruffleHog

| Attribute | Value |
|-----------|-------|
| **Purpose** | Deep secret scanning with verification |
| **Script** | `scan_repos.py` → `run_trufflehog()` |
| **Output** | `{repo}_trufflehog.json`, `{repo}_trufflehog.md` |
| **Install** | `brew install trufflehog` or [GitHub](https://github.com/trufflesecurity/trufflehog) |

**What it detects:**
- Verified secrets (actually tests if credentials work)
- 700+ credential types
- Git history scanning
- Entropy-based detection

**Command used:**
```bash
trufflehog filesystem /path/to/repo --json --only-verified
```

**Why both Gitleaks AND TruffleHog?**
- Gitleaks: Fast, pattern-based, catches more potential secrets
- TruffleHog: Slower, but verifies if secrets are actually valid

---

## Dependency Scanning (SCA)

### Grype

| Attribute | Value |
|-----------|-------|
| **Purpose** | Vulnerability scanner for container images and filesystems |
| **Script** | `scan_repos.py` → `run_grype()` |
| **Output** | `{repo}_grype_repo.json`, `{repo}_grype_repo.md` |
| **Install** | `brew install grype` or [GitHub](https://github.com/anchore/grype) |

**What it scans:**
- Python (pip, poetry, pipenv)
- JavaScript (npm, yarn, pnpm)
- Java (Maven, Gradle)
- Go modules
- Ruby gems
- Rust crates
- Container images

**Command used:**
```bash
grype dir:/path/to/repo -o json --file output.json
```

---

### Trivy

| Attribute | Value |
|-----------|-------|
| **Purpose** | Comprehensive vulnerability scanner |
| **Script** | `scan_repos.py` → `run_trivy_fs()`, `scan_deps.py` |
| **Output** | `{repo}_trivy_fs.json`, `{repo}_trivy_fs.md` |
| **Install** | `brew install trivy` or [GitHub](https://github.com/aquasecurity/trivy) |

**What it scans:**
- OS packages
- Application dependencies
- IaC misconfigurations
- Secrets (basic)
- License compliance

**Command used:**
```bash
trivy fs -q -f json --scanners vuln,config,secret,license /path/to/repo
```

---

### Syft

| Attribute | Value |
|-----------|-------|
| **Purpose** | Generate Software Bill of Materials (SBOM) |
| **Script** | `scan_repos.py` → `run_syft()` |
| **Output** | `{repo}_syft_repo.json`, `{repo}_syft_repo.md` |
| **Install** | `brew install syft` or [GitHub](https://github.com/anchore/syft) |

**What it generates:**
- CycloneDX SBOM
- SPDX SBOM
- Complete dependency tree
- Package metadata

**Command used:**
```bash
syft dir:/path/to/repo -o cyclonedx-json --file output.json
```

---

### OWASP Dependency-Check

| Attribute | Value |
|-----------|-------|
| **Purpose** | CVE detection in project dependencies |
| **Script** | `scan_repos.py` → `run_dependency_check()` |
| **Output** | `{repo}_dependency_check.json` |
| **Install** | `brew install dependency-check` or [OWASP](https://owasp.org/www-project-dependency-check/) |

**What it scans:**
- Java (Maven, Gradle)
- .NET (NuGet)
- Python (pip)
- Ruby (bundler)
- Node.js (npm)

**Command used:**
```bash
dependency-check --scan /path/to/repo --format JSON --out output.json
```

---

## Static Analysis (SAST)

### Semgrep

| Attribute | Value |
|-----------|-------|
| **Purpose** | Pattern-based static analysis |
| **Script** | `scan_repos.py` → `run_semgrep()`, `scan_sast.py` |
| **Output** | `{repo}_semgrep.json`, `{repo}_semgrep.md` |
| **Install** | `pip install semgrep` or [Semgrep](https://semgrep.dev/) |

**Languages supported:**
- Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C/C++, Kotlin, Swift, and 20+ more

**What it detects:**
- SQL injection
- XSS vulnerabilities
- Command injection
- Insecure deserialization
- Hardcoded secrets
- Security misconfigurations

**Command used:**
```bash
semgrep scan --config=auto --json --output output.json /path/to/repo
```

---

### CodeQL

| Attribute | Value |
|-----------|-------|
| **Purpose** | Deep semantic code analysis |
| **Script** | `scan_repos.py` → `run_codeql()` |
| **Output** | `{repo}_codeql.sarif`, `{repo}_codeql.md` |
| **Install** | [GitHub CodeQL](https://github.com/github/codeql-cli-binaries) |

**Languages supported:**
- Python, JavaScript/TypeScript, Java, Go, C/C++, C#, Ruby

**What it detects:**
- Data flow vulnerabilities
- Taint tracking
- Complex security patterns
- CWE-mapped vulnerabilities

**Command used:**
```bash
codeql database create db --language=python --source-root=/path/to/repo
codeql database analyze db --format=sarif-latest --output=output.sarif
```

---

### Bandit

| Attribute | Value |
|-----------|-------|
| **Purpose** | Python-specific security linter |
| **Script** | `scan_repos.py` → `run_bandit()` |
| **Output** | `{repo}_bandit.json`, `{repo}_bandit.md` |
| **Install** | `pip install bandit` |

**What it detects:**
- Hardcoded passwords
- SQL injection
- Shell injection
- Insecure functions (eval, exec)
- Weak cryptography
- Unsafe YAML loading

**Command used:**
```bash
bandit -r /path/to/repo -f json -o output.json
```

---

## Infrastructure as Code (IaC)

### Checkov

| Attribute | Value |
|-----------|-------|
| **Purpose** | IaC security scanner |
| **Script** | `scan_repos.py` → `run_checkov()`, `scan_iac.py` |
| **Output** | `{repo}_checkov.json`, `{repo}_checkov.md` |
| **Install** | `pip install checkov` or [GitHub](https://github.com/bridgecrewio/checkov) |

**What it scans:**
- Terraform
- CloudFormation
- Kubernetes manifests
- Dockerfiles
- ARM templates
- Helm charts

**What it detects:**
- Publicly exposed resources
- Missing encryption
- Overly permissive IAM
- Insecure defaults
- Compliance violations (CIS, SOC2, HIPAA)

**Command used:**
```bash
checkov -d /path/to/repo -o json
```

---

## JavaScript Security

### Retire.js

| Attribute | Value |
|-----------|-------|
| **Purpose** | Detect vulnerable JavaScript libraries |
| **Script** | `scan_repos.py` → `run_retire_js()` |
| **Output** | `{repo}_retire.json`, `{repo}_retire.md` |
| **Install** | `npm install -g retire` |

**What it detects:**
- Known vulnerabilities in JS libraries
- Outdated frontend dependencies
- Client-side security issues

**Command used:**
```bash
retire --path /path/to/repo --outputformat json --outputpath output.json
```

---

### npm/yarn/pnpm audit

| Attribute | Value |
|-----------|-------|
| **Purpose** | Native package manager security audit |
| **Script** | `scan_repos.py` → `run_npm_audit()` |
| **Output** | `{repo}_npm_audit.json`, `{repo}_npm_audit.md` |
| **Install** | Included with npm/yarn/pnpm |

**What it detects:**
- CVEs in npm packages
- Security advisories
- Dependency vulnerabilities

**Commands used:**
```bash
npm audit --json
yarn audit --json
pnpm audit --json
```

---

## API Security

### Custom API Scanner

| Attribute | Value |
|-----------|-------|
| **Purpose** | API endpoint discovery and analysis |
| **Script** | `execution/scan_api.py` |
| **Output** | API audit reports |

**What it does:**
1. **Discovery Agent**: Framework fingerprinting (FastAPI, Express, Spring, etc.)
2. **Extraction Agent**: Endpoint discovery using Semgrep patterns
3. **Synthesis Agent**: OpenAPI specification generation
4. **Security Agent**: Vulnerability assessment

**Frameworks detected:**
- Python: FastAPI, Flask, Django
- JavaScript: Express, Koa, Fastify
- Java: Spring Boot, JAX-RS
- Kotlin: Ktor, Spring

---

### Nuclei

| Attribute | Value |
|-----------|-------|
| **Purpose** | Template-based vulnerability scanner |
| **Script** | `scan_repos.py` → `run_nuclei()` |
| **Output** | `{repo}_nuclei.json`, `{repo}_nuclei.md` |
| **Install** | `brew install nuclei` or [GitHub](https://github.com/projectdiscovery/nuclei) |

**What it detects:**
- CVEs
- Misconfigurations
- Default credentials
- Exposed panels
- Technology detection

**Command used:**
```bash
nuclei -target /path/to/repo -json -output output.json
```

---

## Code Metrics

### cloc

| Attribute | Value |
|-----------|-------|
| **Purpose** | Count lines of code by language |
| **Script** | `scan_repos.py` → `run_cloc()` |
| **Output** | `{repo}_cloc.json` |
| **Install** | `brew install cloc` |

**What it provides:**
- Lines of code per language
- Comment lines
- Blank lines
- File counts

**Command used:**
```bash
cloc /path/to/repo --json --out output.json
```

---

## Tool Comparison Matrix

| Tool | Speed | Accuracy | Languages | False Positives |
|------|-------|----------|-----------|-----------------|
| **Gitleaks** | ⚡ Fast | Good | All | Medium |
| **TruffleHog** | 🐢 Slow | Excellent | All | Low (verified) |
| **Grype** | ⚡ Fast | Good | Many | Low |
| **Trivy** | ⚡ Fast | Good | Many | Low |
| **Semgrep** | ⚡ Fast | Good | 20+ | Medium |
| **CodeQL** | 🐢 Slow | Excellent | 7 | Low |
| **Bandit** | ⚡ Fast | Good | Python | Medium |
| **Checkov** | ⚡ Fast | Good | IaC | Low |
| **Horusec** | ⚡ Fast | Good | 15+ | Low |
| **Whispers** | ⚡ Fast | Good | Config | Low |
| **Bearer** | ⚡ Fast | Good | Many | Medium |
| **Terrascan** | ⚡ Fast | Good | IaC | Low |

---

## Newly Integrated Tools (Phase 1 - December 2024)

The following 5 tools have been integrated into AuditGH's scanning pipeline:

### ✅ Horusec (Integrated)

| Attribute | Value |
|-----------|-------|
| **Purpose** | Multi-language SAST with low false positives |
| **Status** | ✅ **INTEGRATED** |
| **Script** | `scan_repos.py` → `run_horusec()` |
| **Output** | `{repo}_horusec.json`, `{repo}_horusec.md` |
| **Install** | `curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh \| bash -s latest` |
| **GitHub** | [ZupIT/horusec](https://github.com/ZupIT/horusec) |

**What it detects:**
- Aggregates 15+ security tools into unified output
- Supports: Go, C#, Java, Kotlin, Python, Ruby, JavaScript, TypeScript, Terraform, HCL, Dart, Elixir, Shell, PHP, C, HTML, JSON, Nginx

**Command used:**
```bash
horusec start -p /path/to/repo -o json -O output.json --disable-docker true -e true
```

---

### ✅ Whispers (Integrated)

| Attribute | Value |
|-----------|-------|
| **Purpose** | Hardcoded secrets in config files |
| **Status** | ✅ **INTEGRATED** |
| **Script** | `scan_repos.py` → `run_whispers()` |
| **Output** | `{repo}_whispers.json`, `{repo}_whispers.md` |
| **Install** | `pip install whispers` |
| **GitHub** | [Skyscanner/whispers](https://github.com/Skyscanner/whispers) |

**What it detects:**
- Secrets in YAML, JSON, XML, .npmrc, .pypirc, .htpasswd
- Config files: .properties, pip.conf, Dockerfile
- Shell scripts and Python3 AST analysis

**Command used:**
```bash
whispers -o output.json /path/to/repo
```

---

### ✅ Bearer (Integrated)

| Attribute | Value |
|-----------|-------|
| **Purpose** | Data flow analysis for sensitive data exposure |
| **Status** | ✅ **INTEGRATED** |
| **Script** | `scan_repos.py` → `run_bearer()` |
| **Output** | `{repo}_bearer.json`, `{repo}_bearer.md` |
| **Install** | `brew install bearer/tap/bearer` |
| **GitHub** | [Bearer/bearer](https://github.com/Bearer/bearer) |

**What it detects:**
- PII/PHI data flows
- Data leakage to logs/third parties
- GDPR/CCPA compliance issues
- Security vulnerabilities with data context

**Command used:**
```bash
bearer scan /path/to/repo --format json --output output.json --quiet
```

---

### ✅ Dockle (Integrated)

| Attribute | Value |
|-----------|-------|
| **Purpose** | Container image linter for best practices |
| **Status** | ✅ **INTEGRATED** (Dockerfile detection) |
| **Script** | `scan_repos.py` → `run_dockle()` |
| **Output** | `{repo}_dockle.json`, `{repo}_dockle.md` |
| **Install** | `brew install goodwithtech/r/dockle` |
| **GitHub** | [goodwithtech/dockle](https://github.com/goodwithtech/dockle) |

**What it checks:**
- CIS Docker Benchmark compliance
- Security best practices
- Image efficiency
- Proper user configuration

**Note:** Dockle requires built container images. AuditGH detects Dockerfiles and provides scan instructions.

---

### ✅ Terrascan (Integrated)

| Attribute | Value |
|-----------|-------|
| **Purpose** | IaC security scanner with 500+ policies |
| **Status** | ✅ **INTEGRATED** |
| **Script** | `scan_repos.py` → `run_terrascan()` |
| **Output** | `{repo}_terrascan.json`, `{repo}_terrascan.md` |
| **Install** | `brew install terrascan` |
| **GitHub** | [tenable/terrascan](https://github.com/tenable/terrascan) |

**What it scans:**
- Terraform
- Kubernetes (YAML, Helm)
- Dockerfiles
- CloudFormation
- Azure ARM
- Kustomize

**Command used:**
```bash
terrascan scan -d /path/to/repo -o json
```

---

## ⚠️ Skipped Tools (Require Registration/API Key)

### ❌ Snyk CLI (Skipped)

| Attribute | Value |
|-----------|-------|
| **Purpose** | Comprehensive vulnerability scanning with fix suggestions |
| **Status** | ❌ **SKIPPED** - Requires free registration and API key |
| **Why skipped** | `snyk auth` required before use, even for free tier |
| **Install** | `npm install -g snyk` |
| **Registration** | https://snyk.io/signup |

**Alternative:** Use **Grype** + **Trivy** for similar coverage without registration.

---

## Future Tools (Recommended Additions)

### Phase 2 - Planned

#### 1. **Kubesec**
| Attribute | Value |
|-----------|-------|
| **Purpose** | Kubernetes manifest security analysis |
| **Why add** | Deep K8s security checks |
| **Install** | `brew install kubesec` |
| **GitHub** | [controlplaneio/kubesec](https://github.com/controlplaneio/kubesec) |

---

### Low Priority (Nice to Have)

#### 8. **GitLeaks + git-secrets**
| Attribute | Value |
|-----------|-------|
| **Purpose** | Pre-commit secret prevention |
| **Why add** | Prevent secrets from being committed |
| **Install** | `brew install git-secrets` |

---

#### 9. **Prowler**
| Attribute | Value |
|-----------|-------|
| **Purpose** | AWS/Azure/GCP security assessment |
| **Why add** | Cloud security posture management |
| **Install** | `pip install prowler` |
| **GitHub** | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) |

---

#### 10. **Scorecard**
| Attribute | Value |
|-----------|-------|
| **Purpose** | OpenSSF security health metrics |
| **Why add** | Supply chain security scoring |
| **Install** | `brew install scorecard` |
| **GitHub** | [ossf/scorecard](https://github.com/ossf/scorecard) |

---

### Mobile & Language-Specific

#### 11. **MobSF (Mobile Security Framework)**
| Attribute | Value |
|-----------|-------|
| **Purpose** | Mobile app security (Android/iOS) - SAST + DAST |
| **Why add** | Comprehensive mobile security analysis including APK/IPA scanning, dynamic analysis, and API testing |
| **Languages** | Java, Kotlin, Swift, Objective-C |
| **Install** | Docker: `docker pull opensecurity/mobile-security-framework-mobsf` |
| **GitHub** | [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) |
| **Features** | Static analysis, dynamic analysis, malware analysis, API fuzzing |

---

#### 12. **gosec**
| Attribute | Value |
|-----------|-------|
| **Purpose** | Go source code security analyzer |
| **Why add** | Go-specific security rules (SQL injection, hardcoded creds, crypto issues) |
| **Languages** | Go |
| **Install** | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| **GitHub** | [securego/gosec](https://github.com/securego/gosec) |
| **Integration** | Works standalone or as GolangCI-Lint plugin |

---

#### 13. **GolangCI-Lint**
| Attribute | Value |
|-----------|-------|
| **Purpose** | Go linter aggregator (includes gosec) |
| **Why add** | Single tool for all Go linting including security via gosec integration |
| **Languages** | Go |
| **Install** | `brew install golangci-lint` or `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |
| **GitHub** | [golangci/golangci-lint](https://github.com/golangci/golangci-lint) |
| **Config** | Enable gosec in `.golangci.yml`: `linters: { enable: [gosec] }` |

> **Tip:** Use GolangCI-Lint with gosec enabled for comprehensive Go security scanning in a single pass.

---

## Implementation Roadmap

### ✅ Phase 1: Complete (December 2024)
1. ~~**Snyk CLI**~~ - ❌ Skipped (requires API key)
2. ✅ **Horusec** - Multi-tool aggregation
3. ✅ **Whispers** - Additional secret patterns
4. ✅ **Bearer** - Data flow analysis
5. ✅ **Dockle** - Container best practices
6. ✅ **Terrascan** - Additional IaC coverage

### Phase 2: Planned (Q1 2025)
7. **Kubesec** - Kubernetes deep analysis
8. **Prowler** - Cloud security posture
9. **Scorecard** - Supply chain security

### ✅ Phase 3: Complete (December 2024)
10. ✅ **gosec + GolangCI-Lint** - Go security (combined for efficiency)
11. ✅ **MobSF** - Mobile app security (Android/iOS source code analysis)

---

## Tool Installation

> **⚠️ IMPORTANT: All security tools run inside the `auditgh` Docker container.**
> 
> You do NOT need to install these tools on your host machine. The Dockerfile installs all required tools automatically.

### Docker Container (Recommended)

All tools are pre-installed in the `auditgh` container. Just run:

```bash
# Build the container with all tools
docker-compose build auditgh

# Run scans (tools execute inside container)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target myorg'
```

### Dockerfile Tool Installation

The following is installed in the `auditgh` container's Dockerfile:

```dockerfile
# ===========================================
# SECRETS DETECTION
# ===========================================
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar xz -C /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
RUN pip install whispers

# ===========================================
# DEPENDENCY SCANNING (SCA)
# ===========================================
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# ===========================================
# STATIC ANALYSIS (SAST)
# ===========================================
RUN pip install semgrep bandit
RUN curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash -s latest

# ===========================================
# DATA FLOW ANALYSIS
# ===========================================
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ===========================================
# INFRASTRUCTURE AS CODE (IaC)
# ===========================================
RUN pip install checkov
RUN curl -L "https://github.com/tenable/terrascan/releases/latest/download/terrascan_$(uname -s)_$(uname -m).tar.gz" | tar xz -C /usr/local/bin

# ===========================================
# CONTAINER SECURITY
# ===========================================
RUN curl -L "https://github.com/goodwithtech/dockle/releases/latest/download/dockle_$(uname -s)_$(uname -m).tar.gz" | tar xz -C /usr/local/bin

# ===========================================
# JAVASCRIPT SECURITY
# ===========================================
RUN npm install -g retire

# ===========================================
# API/NETWORK SCANNING
# ===========================================
RUN curl -L "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip" -o nuclei.zip && unzip nuclei.zip -d /usr/local/bin && rm nuclei.zip

# ===========================================
# CODE METRICS
# ===========================================
RUN apt-get install -y cloc
```

### Local Development (Optional)

If you need to run tools locally for testing:

```bash
#!/bin/bash
# Local installation (NOT recommended for production)

# Horusec (correct install method)
curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash -s latest

# Whispers
pip install whispers

# Bearer
curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh

# Terrascan
brew install terrascan  # macOS
# or: curl -L "https://github.com/tenable/terrascan/releases/latest/download/terrascan_Darwin_arm64.tar.gz" | tar xz

# Dockle
brew install goodwithtech/r/dockle  # macOS

# Verify
horusec version
whispers --version
bearer version
terrascan version
```

---

[← Back to README](../README.md) | [AI Agents →](AI_AGENTS.md)
