#!/bin/bash

# Azure Device-Code Login Automation — Shell Wrapper
# Ensures dependencies are installed, then runs the Python orchestrator.
#
# Usage:
#   ./scripts/azure-login/az-login.sh
#   ./scripts/azure-login/az-login.sh --email user@company.com
#   ./scripts/azure-login/az-login.sh --subscription "my-sub"
#   ./scripts/azure-login/az-login.sh --debug

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

log_info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Pre-flight: az CLI ──────────────────────────────────────────────────────
check_az() {
    if ! command -v az &>/dev/null; then
        log_error "Azure CLI (az) not found."
        echo "  Install: brew install azure-cli   (macOS)"
        echo "           curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash  (Linux)"
        exit 1
    fi
    log_success "Azure CLI found: $(az version --output tsv 2>/dev/null | head -1)"
}

# ── Pre-flight: Python ──────────────────────────────────────────────────────
check_python() {
    local py=""
    for candidate in python3 python; do
        if command -v "$candidate" &>/dev/null; then
            py="$candidate"
            break
        fi
    done
    if [ -z "$py" ]; then
        log_error "Python 3 not found on PATH."
        exit 1
    fi
    PYTHON="$py"
    log_success "Python found: $($PYTHON --version)"
}

# ── Pre-flight: Playwright ──────────────────────────────────────────────────
ensure_playwright() {
    if ! $PYTHON -c "import playwright" &>/dev/null; then
        log_warn "Playwright not installed. Installing..."
        $PYTHON -m pip install --quiet playwright
    fi
    log_success "Playwright Python package ready"

    # Ensure Chromium browser is installed
    if ! $PYTHON -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    b.close()
" &>/dev/null 2>&1; then
        log_warn "Chromium browser not installed. Installing..."
        $PYTHON -m playwright install chromium
    fi
    log_success "Playwright Chromium browser ready"
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo "========================================"
    echo "  Azure Device-Code Login Automation"
    echo "========================================"
    echo ""

    check_az
    check_python
    ensure_playwright

    echo ""
    log_info "Starting login automation..."
    echo ""

    $PYTHON "${SCRIPT_DIR}/az_login.py" "$@"
    exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo ""
        log_success "Azure login automation completed successfully."
    else
        echo ""
        log_error "Azure login automation failed (exit code: $exit_code)."
        echo ""
        echo "Troubleshooting:"
        echo "  1. Ensure you can run 'az login --use-device-code' manually"
        echo "  2. Check screenshots in: ${SCRIPT_DIR}/screenshots/"
        echo "  3. Run with --debug for verbose logging"
        echo "  4. Run with --log-file /tmp/az-login.log to capture logs"
    fi

    exit $exit_code
}

main "$@"
