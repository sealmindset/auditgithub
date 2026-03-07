# Changelog

All notable changes to the AuditGitHub project will be documented in this file.

## [Unreleased]

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
# Quick start (uses defaults: rob.vance@sleepnumber.com, sn-openai-dev-01)
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
6. `az account set --subscription "sn-openai-dev-01"`
7. `az account show` verification with formatted output
