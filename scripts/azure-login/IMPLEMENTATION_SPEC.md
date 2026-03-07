# Azure Device-Code Login Automation — Implementation Spec

## Overview

Automate the Azure CLI device-code login flow using Playwright to handle the browser-based authentication steps. The script orchestrates the CLI `az login --use-device-code` command, extracts the device code, opens a Playwright-driven browser to `https://login.microsoft.com/device`, enters the code, selects the user account, pauses for MFA, and finally sets the target Azure subscription.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  az_login.py  (Orchestrator)                         │
│                                                       │
│  1. Spawn `az login --use-device-code` as subprocess │
│  2. Parse device code from stdout via regex           │
│  3. Launch Playwright Chromium (headed)               │
│  4. Navigate to https://login.microsoft.com/device   │
│  5. Fill device code → Click Next                    │
│  6. Click target account tile                         │
│  7. PAUSE for user MFA input (manual step)           │
│  8. Wait for auth-complete signal                     │
│  9. Close browser                                     │
│ 10. Run `az account set --subscription <SUB>`        │
│ 11. Verify with `az account show`                    │
└─────────────────────────────────────────────────────┘
```

## Components

### 1. `az_login.py` — Main Orchestrator (Python)
- **Subprocess management**: Spawns `az login --use-device-code` in a background thread, captures stdout line-by-line.
- **Code extraction**: Regex `r'enter the code\s+([A-Z0-9]+)\s+to authenticate'` to pull the device code.
- **Playwright automation**: Headed Chromium browser with slow_mo for reliability.
- **Account selection**: Configurable email via CLI arg or env var `AZURE_LOGIN_EMAIL`.
- **MFA pause**: Uses `page.pause()` or a polling loop waiting for the auth-complete page.
- **Subscription switch**: After successful auth, runs `az account set --subscription <name>`.
- **Logging**: Every step logged with timestamps to stdout and optionally to file.

### 2. `config.py` — Configuration
- `AZURE_LOGIN_EMAIL`: Target account email (default: `rob.vance@sleepnumber.com`)
- `AZURE_SUBSCRIPTION`: Target subscription (default: `sn-openai-dev-01`)
- `BROWSER_HEADLESS`: Whether to run headless (default: `False` — must be headed for MFA)
- `BROWSER_SLOW_MO`: Milliseconds between actions (default: `500`)
- `LOGIN_TIMEOUT`: Max wait for login completion in seconds (default: `300`)
- `DEVICE_CODE_URL`: `https://login.microsoft.com/device`

### 3. `requirements.txt` — Dependencies
- `playwright` (with chromium browser installed)
- Standard lib only otherwise (subprocess, re, threading, time, argparse, logging)

## Detailed Flow

### Step 1: Pre-flight checks
- Verify `az` CLI is installed and on PATH
- Verify Playwright browsers are installed (auto-install if missing)
- Load configuration from env vars / CLI args

### Step 2: Launch `az login --use-device-code`
- Spawn as subprocess with `stdout=PIPE, stderr=STDOUT`
- Read output in a background thread
- Extract the device code via regex
- Timeout after 30s if no code received

### Step 3: Browser automation
- Launch Chromium in headed mode (MFA requires user interaction)
- Navigate to `https://login.microsoft.com/device`
- Wait for the code input field
- Type the extracted device code
- Click "Next"

### Step 4: Account selection
- Wait for the account picker page
- Look for the target email in the account tiles
- Click the matching account
- If not found, log available accounts and prompt user

### Step 5: MFA (Manual)
- Detect if MFA is required (authenticator app, SMS, etc.)
- Print clear instructions to terminal: "Please complete MFA on your device"
- Poll the page for navigation away from the MFA page
- Timeout after configurable duration (default 5 minutes)

### Step 6: Post-auth
- Detect successful authentication ("You have signed in" or similar)
- Close the browser
- Wait for the `az login` subprocess to complete
- Parse and display the account info

### Step 7: Set subscription
- Run `az account set --subscription "sn-openai-dev-01"`
- Verify with `az account show`
- Display final confirmation

## Error Handling
- **az CLI not found**: Exit with install instructions
- **Device code timeout**: Kill subprocess, exit with retry instructions
- **Browser launch failure**: Attempt Playwright install, retry once
- **Account not found**: List available accounts, prompt for selection
- **MFA timeout**: Close browser, kill subprocess, exit with instructions
- **Subscription not found**: List available subscriptions

## CLI Interface
```
python scripts/azure-login/az_login.py [OPTIONS]

Options:
  --email TEXT          Azure account email (default: env AZURE_LOGIN_EMAIL)
  --subscription TEXT   Azure subscription name (default: env AZURE_SUBSCRIPTION)
  --timeout INT         MFA timeout in seconds (default: 300)
  --slow-mo INT         Browser slow_mo in ms (default: 500)
  --headless            Run browser headless (not recommended for MFA)
  --debug               Enable debug logging
  --help                Show help
```

## Security Considerations
- No credentials stored or logged
- Device code is ephemeral and single-use
- MFA is performed manually by the user
- Browser session is closed immediately after auth
- No cookies or tokens are persisted by the script
