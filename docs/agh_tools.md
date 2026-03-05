 Secrets Detection (3 tools)                                                                                                                                             
                                                                                                                                                                          
  ┌────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬──────────────────────┐   
  │    Tool    │                                                            Purpose                                                            │      Invocation      │   
  ├────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────┤   
  │ Gitleaks   │ Detects API keys, passwords, tokens, and hardcoded credentials in the working tree and full Git history. Findings classified  │ CLI (gitleaks        │   
  │            │ as CWE-798.                                                                                                                   │ detect)              │   
  ├────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────┤
  │ TruffleHog │ Scans repository history and current state for high-entropy strings and known secret patterns (AWS keys, Slack tokens, etc.). │ CLI                  │
  ├────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────┤
  │ Whispers   │ Specialized for secrets embedded in configuration files (YAML, JSON, XML, .env, .properties). Runs in an isolated Python      │ CLI (isolated venv)  │
  │            │ venv.                                                                                                                         │                      │
  └────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴──────────────────────┘

  SAST - Static Application Security Testing (3 tools)

  ┌─────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬──────────────────────────┐
  │  Tool   │                                                           Purpose                                                            │        Invocation        │
  ├─────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤
  │ Semgrep │ Pattern-based code analysis using 10+ rule packs (security-audit, OWASP Top 10, command-injection, SQL-injection, XSS, JWT,  │ CLI (semgrep scan)       │
  │         │ Docker, etc.) plus custom rules in semgrep-rules/. Supports taint-mode data flow analysis.                                   │                          │
  ├─────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤
  │ Bandit  │ Python-specific SAST. Detects hardcoded passwords, insecure function calls, SQL injection risks, and unsafe deserialization. │ CLI (bandit -r)          │
  │         │  Only runs when .py files are present.                                                                                       │                          │
  ├─────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤
  │ CodeQL  │ Semantic code analysis with database-driven data flow tracking. Supports Python, JavaScript/TypeScript, Go, and Java. Finds  │ CLI (codeql database     │
  │         │ deeper vulnerabilities that pattern matching misses.                                                                         │ create + analyze)        │
  └─────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴──────────────────────────┘

  SCA - Software Composition Analysis / Dependency Scanning (8 tools)

  ┌─────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬───────────────────────────┐
  │        Tool         │                                                    Purpose                                                     │        Invocation         │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┤
  │ Grype               │ Scans repository filesystem or Docker images for known vulnerabilities in packages. Supports VEX               │ CLI (grype)               │
  │                     │ (Vulnerability Exploitability eXchange) for false-positive suppression.                                        │                           │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┤
  │ Trivy               │ Multi-scanner covering vulnerabilities, misconfigurations, secrets, and license issues across filesystem and   │ CLI (trivy fs)            │
  │                     │ container images.                                                                                              │                           │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┤
  │ Syft                │ Generates Software Bill of Materials (SBOM) in CycloneDX and SPDX formats. Inventories all                     │ CLI                       │
  │                     │ packages/dependencies for compliance and auditing.                                                             │                           │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┤
  │ OWASP               │ Cross-language dependency scanner (Java, .NET, Python, Ruby, Node.js) using the National Vulnerability         │ CLI (dependency-check.sh) │
  │ Dependency-Check    │ Database (NVD).                                                                                                │                           │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┤
  │ pip-audit           │ Python-specific. Audits requirements.txt, Pipfile, pyproject.toml, and setup.py against the PyPI advisory      │ CLI (pip-audit --format   │
  │                     │ database.                                                                                                      │ json)                     │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┤
  │ Safety              │ Python-specific. Checks installed packages against the Safety vulnerability database.                          │ CLI (safety check --json) │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┤
  │ npm audit           │ Node.js/JavaScript. Scans package-lock.json for known vulnerabilities in npm dependencies.                     │ CLI (npm audit --json)    │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────┤
  │ retire.js           │ JavaScript-specific. Identifies JavaScript libraries with known CVEs, including client-side libraries.         │ CLI                       │
  └─────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴───────────────────────────┘

  Infrastructure as Code Security (2 tools)

  ┌───────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬──────────────────┐
  │   Tool    │                                                          Purpose                                                           │    Invocation    │
  ├───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────┤
  │ Checkov   │ Scans Terraform, CloudFormation, Docker, Kubernetes, and Helm charts for security misconfigurations and policy violations. │ CLI (checkov -d) │
  ├───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────────────┤
  │ Terrascan │ Policy-as-code engine for Terraform, Kubernetes, Docker, and CloudFormation. Validates against 500+ security policies.     │ CLI              │
  └───────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴──────────────────┘

  Container Security (1 tool)

  ┌────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────┐
  │  Tool  │                                                               Purpose                                                               │ Invocation │
  ├────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ Dockle │ Audits Docker images and Dockerfiles against CIS benchmarks and best practices (no root user, minimal layers, no secrets in image). │ CLI        │
  └────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────┘

  Go Security (3 tools)

  ┌───────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────┐
  │     Tool      │                                                                Purpose                                                                │ Invocation │
  ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ gosec         │ Go-specific SAST. Detects SQL injection, hardcoded credentials, weak crypto, file path traversal, and unsafe exec calls in Go source. │ CLI        │
  ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ govulncheck   │ Go-specific SCA. Checks Go modules against the Go vulnerability database with call graph analysis (only flags vulns in reachable      │ CLI        │
  │               │ code).                                                                                                                                │            │
  ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ GolangCI-Lint │ Go linter aggregator that includes security-focused linters (gosec, staticcheck, etc.) for comprehensive Go code quality and          │ CLI        │
  │               │ security.                                                                                                                             │            │
  └───────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────┘

  Multi-Language SAST (2 tools)

  ┌─────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────┐
  │  Tool   │                                                                   Purpose                                                                   │ Invocation │
  ├─────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ Horusec │ Multi-language SAST covering 15+ languages. Orchestrates multiple internal engines for broad vulnerability detection.                       │ CLI        │
  ├─────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ Bearer  │ Data flow analysis tool. Tracks sensitive data (PII, credentials) through application code and flags exposure risks and compliance          │ CLI        │
  │         │ violations.                                                                                                                                 │            │
  └─────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────┘

  Ruby Security (1 tool)

  ┌──────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────┬────────────────┐
  │     Tool     │                                             Purpose                                             │   Invocation   │
  ├──────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤
  │ bundle-audit │ Ruby-specific. Audits Gemfile.lock for gems with known CVEs against the Ruby Advisory Database. │ CLI (Ruby gem) │
  └──────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────┘

  Dynamic / Template-Based Scanning (1 tool)

  ┌────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────┐
  │  Tool  │                                                                   Purpose                                                                    │ Invocation │
  ├────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ Nuclei │ Template-based vulnerability scanner. Uses a community-maintained library of detection templates for known CVEs, misconfigurations, and      │ CLI        │
  │        │ exposures.                                                                                                                                   │            │
  └────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────┘

  .NET Security (1 tool)

  ┌───────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬─────────────────┐
  │   Tool    │                                                          Purpose                                                           │   Invocation    │
  ├───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼─────────────────┤
  │ OSSGadget │ .NET/C# tool for detecting malware, backdoors, and suspicious code patterns in open-source packages. Outputs SARIF format. │ dotnet tool CLI │
  └───────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴─────────────────┘

  API Security (2 custom tools)

  ┌──────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────────┐
  │       Tool       │                                                           Purpose                                                            │   Invocation   │
  ├──────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤
  │ API Scanner      │ AI-powered 4-phase API discovery and security assessment: Discovery, Extraction, Synthesis, Security. Fingerprints           │ Python         │
  │ (custom)         │ frameworks (FastAPI, Flask, Django, Express, Spring, etc.) and builds threat matrices.                                       │ (built-in)     │
  ├──────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤
  │ OpenAPI Spider   │ Crawls OpenAPI/Swagger specifications to discover and document API endpoints, authentication schemes, and data models.       │ Python         │
  │ (custom)         │                                                                                                                              │ (built-in)     │
  └──────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────────┘

  Code Metrics (1 tool)

  ┌──────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────┐
  │ Tool │                                                           Purpose                                                           │ Invocation │
  ├──────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ cloc │ Counts lines of code by language. Provides codebase composition metrics used for risk-weighting and scan coverage analysis. │ CLI        │
  └──────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────┘

  ---
  Total: 28 tools across 10 categories, orchestrated from scripts/scanning/scan_repos.py with category-specific execution modules in execution/. All tools output JSON for
   programmatic ingestion and Markdown for human review, with findings persisted to PostgreSQL for trending and aggregation.    