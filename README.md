# AuditGH: GitHub Repository Security Scanner

A modular and extensible security scanning tool that checks GitHub repositories for security vulnerabilities across multiple programming languages.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Docker (Recommended)](#docker-recommended)
  - [CLI (Manual)](#cli-manual)
- [Scanners](#scanners)
- [Architecture](#architecture)
- [License](#license)

## Features

- **Modular Architecture**: Scanners are isolated scripts in `execution/`.
- **Multi-language Support**: Python, JavaScript/TypeScript, Java, Go, Terraform, and more.
- **Comprehensive Scanning**:
  - **Secrets**: Gitleaks, TruffleHog, GenAI tokens.
  - **Vulnerabilities**: OSV, Safety, Pip-audit, Trivy, Grype.
  - **Static Analysis**: CodeQL, Semgrep.
  - **Infrastructure**: Terraform (Checkov, Trivy).
  - **Metrics**: Line counts, binary file inventory.
- **Orchestration**: Run multiple scanners in parallel with profiles (fast, balanced, deep).
- **Reporting**: Markdown, JSON, and HTML reports.
- **Self-Annealing Scanner**: DOE (Design of Experiments) recovery system that automatically handles stuck scans:
  - **Per-repository timeout**: Default 30 minutes (configurable)
  - **Automatic recovery**: Skips stuck repos, generates partial reports, continues scanning
  - **Immediate Ctrl-C response**: Properly cancels all pending scans and exits cleanly
  - **Comprehensive logging**: Tracks stuck repositories with detailed diagnostics
  - **Backward compatible**: All existing commands work unchanged

## Prerequisites

- **Docker**: Docker Desktop with Compose v2 (recommended).
- **Python 3.11+**: If running locally without Docker.
- **GitHub Token**: A Personal Access Token (classic) with `repo` and `read:org` scopes.

## Quick Start

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/auditgh.git
    cd auditgh
    ```

2.  **Run Setup Script (macOS):**
    For a fresh macOS installation, run the setup script to install all dependencies (Homebrew, Docker, Python, etc.) and configure the environment.
    ```bash
    chmod +x setup_mac.sh
    ./setup_mac.sh
    ```
    *Follow the on-screen prompts to configure your GitHub token.*

3.  **Manual Configuration (Linux/Windows/Existing Mac):**
    If not using the setup script:
    Copy `.env.sample` to `.env` and add your GitHub token and organization.
    ```bash
    cp .env.sample .env
    # Edit .env:
    # GITHUB_ORG=your-org
    # GITHUB_TOKEN=ghp_...
    ```

4.  **Run a Scan (Docker):**
    Use the helper script to run a balanced scan against your configured organization.
    ```bash
    ./run_scan.sh
    ```

## Usage

### Docker (Recommended)
```
docker-compose run --rm auditgh \
  --org sealmindset \
  --include-forks \
  --include-archived \
  --max-workers 4 \
  --loglevel INFO
```

### Environment Variables

You can pass environment variables to `docker-compose run` to control the behavior of the scanner.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SKIP_SCAN` | `false` | Set to `true` to start the container without running the scan automatically. Useful for debugging or manual execution. |
| `GITHUB_ORG` | (Required) | The GitHub organization to scan. |
| `GITHUB_TOKEN` | (Required) | Your GitHub Personal Access Token. |
| `GITHUB_API` | `https://api.github.com` | Base URL for GitHub API (useful for GHE). |

**Example: Start the full stack without scanning**
Use `up` to start all services (API, UI, Database) in the background.
```bash
SKIP_SCAN=true docker-compose up -d
```

**Example: Run a single container shell**
Use `run` to start just the scanner container interactively.
```bash
docker-compose run --rm -e SKIP_SCAN=true auditgh /bin/bash
```

### Or

The easiest way to run scans is via the provided shell scripts. **You do NOT need to manually run `docker compose up` first.** The `run_scan.sh` script handles spinning up the scanning container, running the job, and cleaning up afterwards.

**1. Run a standard scan:**
This command will build the image (if needed), start the container, run the orchestrator, and then remove the container.
```bash
./run_scan.sh
```

**2. Customizing the scan:**
You can pass arguments to `run_scan.sh` which are forwarded to the orchestrator inside the container:
```bash
# Scan a specific repository
./run_scan.sh --repo owner/repo-name

# Set repository timeout (default: 30 minutes)
./run_scan.sh --repo-timeout 15

# Disable repository timeout
./run_scan.sh --repo-timeout 0

# Increase verbosity
./run_scan.sh -v
```

**3. Timeout and Self-Annealing:**
The scanner includes automatic timeout and recovery features to prevent stuck scans:

```bash
# Default: 30-minute timeout per repository
docker-compose run --rm auditgh --org your-org

# Custom timeout: 15 minutes per repository
docker-compose run --rm auditgh --org your-org --repo-timeout 15
```

**4. AI-Enhanced Scanning (Optional):**
Enable AI-powered reasoning to diagnose stuck scans and suggest fixes using OpenAI or Claude.

**Prerequisites:**
1. Get an API key from OpenAI or Anthropic.
2. Add it to your `.env` file:
   ```bash
   AI_AGENT_ENABLED=true
   AI_PROVIDER=openai  # or claude
   OPENAI_API_KEY=sk-...
   # ANTHROPIC_API_KEY=sk-ant-...
   ```

**Usage:**
```bash
# Enable AI agent via CLI
docker-compose run --rm auditgh --org your-org --ai-agent

# Enable auto-remediation (AI can apply safe fixes)
docker-compose run --rm auditgh --org your-org --ai-agent --ai-auto-remediate

# Use a specific provider
docker-compose run --rm auditgh --org your-org --ai-agent --ai-provider claude
```

**Key Features:**
- **Root Cause Analysis:** AI diagnoses why a scan got stuck (e.g., "Too many generated files").
- **Smart Remediation:** Suggests specific fixes like increasing timeouts or excluding paths.
- **Auto-Remediation:** Can automatically apply safe fixes if enabled.
- **Cost Control:** Budget limits per scan (default $0.50) to prevent runaway costs.

**5. Manual Docker Compose (Advanced):**
If you prefer to run `docker compose` directly without the helper script:
```bash
# Build the image
docker compose build

# Run the scan (this is what run_scan.sh does internally)
docker compose run --rm auditgh \
  --org <YOUR_ORG> \
  --profile balanced
```

**Seeding the Portal:**
If you are using the AuditGH Portal (web UI), use `seed_org.sh` to populate the database. This script also manages its own Docker containers.
```bash
./seed_org.sh --mode=container
```

### CLI (Manual)

If you prefer to run python scripts directly (requires all dependencies installed locally):

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    # You may need to install external tools (trivy, gitleaks, etc.) manually.
    ```

2.  **Run the Orchestrator:**
    ```bash
    python execution/orchestrate_scans.py --org <ORG> --token <TOKEN> --profile balanced
    ```

3.  **Run Individual Scanners:**
    Each scanner is a standalone script in `execution/`.
    ```bash
    # Scan for secrets
    python execution/scan_gitleaks.py --org <ORG> --token <TOKEN>

    # Scan OSS dependencies
    python execution/scan_oss.py --org <ORG> --token <TOKEN>
    ```

## Scanners

| Scanner | Description | Script |
| :--- | :--- | :--- |
| **CICD** | Analyzes GitHub Actions workflows. | `execution/scan_cicd.py` |
| **Gitleaks** | Detects hardcoded secrets. | `execution/scan_gitleaks.py` |
| **TruffleHog** | Deep secret scanning. | `execution/scan_trufflehog.py` |
| **OSS** | Checks dependencies (pip, npm, maven, etc.) for CVEs. | `execution/scan_oss.py` |
| **CodeQL** | Static application security testing (SAST). | `execution/scan_codeql.py` |
| **Terraform** | IaC scanning with Checkov and Trivy. | `execution/scan_terraform.py` |
| **Binaries** | Inventories binary files. | `execution/scan_binaries.py` |
| **Linecount** | Counts lines of code by language. | `execution/scan_linecount.py` |
| **GenAI Tokens** | Detects AI provider tokens (OpenAI, etc.). | `execution/scan_genai_tokens.py` |

## Architecture

This project follows a 3-Layer Architecture:

1.  **Directives (`directives/`)**: SOPs and instructions for running scans.
2.  **Orchestration**: The `execution/orchestrate_scans.py` script manages the workflow.
3.  **Execution (`execution/`)**: Deterministic Python scripts that perform the actual scanning.

## License

MIT
