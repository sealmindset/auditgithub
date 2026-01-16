# Scan Repository Directive

## Goal
Perform a comprehensive security scan on a target GitHub repository using a suite of security tools.

## Inputs
- `repo_url`: URL of the repository to scan.
- `repo_name`: Name of the repository.
- `output_dir`: Directory to save reports.

## Tools / Execution Scripts
The following deterministic scripts in `execution/` should be used. If a script does not exist, it must be created from the logic in `scan_repos.py`.

1.  `execution/clone_repo.py`: Clones the repository.
2.  `execution/detect_tech.py`: Detects languages and frameworks.
3.  `execution/scan_secrets.py`: Runs Gitleaks/TruffleHog.
4.  `execution/scan_sast.py`: Runs Semgrep/CodeQL.
5.  `execution/scan_deps.py`: Runs Trivy/OWASP Dependency Check.
6.  `execution/scan_iac.py`: Runs Checkov/Trivy IaC.
7.  `execution/generate_report.py`: Aggregates results into a Markdown report.

## Workflow
1.  **Clone**: Clone the target repository to a temporary directory.
2.  **Detect**: Identify languages to select appropriate scanners.
3.  **Scan**: Run the relevant scanners in parallel where possible.
4.  **Report**: Generate a summary report and detailed findings.
5.  **Cleanup**: Remove temporary files.

## Edge Cases
- **Authentication**: Ensure GitHub tokens are valid.
- **Timeouts**: Handle large repositories gracefully.
- **Failures**: If a single scanner fails, the overall scan should continue.
