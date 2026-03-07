#!/bin/bash
################################################################################
# Claude CLI Setup - Single Script Automation
#
# This script handles the complete Claude CLI setup in one file:
# - Creates ~/.claude directory if it doesn't exist
# - Creates get-claude-token.sh if it doesn't exist
# - Creates/updates settings.json (with backup if exists)
# - Generates token and saves to claudekey.txt
# - Tests the setup
#
# On failure, a diagnostic log is automatically saved to the user's Desktop
# so they can send it to IT support.
#
# Usage:
#   ./setup_claude_single.sh
#   ./setup_claude_single.sh --skip-token
#   ./setup_claude_single.sh --debug
#   ./setup_claude_single.sh --base-url "https://custom.url.com"
################################################################################

# ============================================================================
# Configuration (can be overridden by command-line args)
# ============================================================================

CLAUDE_DIR="${HOME}/.claude"
TOKEN_SCRIPT="${CLAUDE_DIR}/get-claude-token.sh"
SETTINGS_FILE="${CLAUDE_DIR}/settings.json"
TOKEN_FILE="${CLAUDE_DIR}/claudekey.txt"

# Default configuration
BASE_URL="${ANTHROPIC_FOUNDRY_BASE_URL:-https://snapistg-scus.azure.sleepnumber.com/anthropic}"
SONNET_MODEL="${ANTHROPIC_DEFAULT_SONNET_MODEL:-cogdep-aifoundry-dev-eus2-claude-sonnet-4-5}"
HAIKU_MODEL="${ANTHROPIC_DEFAULT_HAIKU_MODEL:-cogdep-aifoundry-dev-eus2-claude-haiku-4-5}"
OPUS_MODEL="${ANTHROPIC_DEFAULT_OPUS_MODEL:-cogdep-aifoundry-dev-eus2-claude-opus-4-6}"

SKIP_TOKEN=false
DEBUG=false

# Track issues during setup
HAS_ERRORS=false
HAS_WARNINGS=false

# Diagnostic log — collects technical details for IT support
DIAG_LOG=""
DIAG_LOG_FILE=""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ============================================================================
# Diagnostic Log Functions
# ============================================================================

# Append a line to the diagnostic log (plain text, no colors)
diag() {
    DIAG_LOG="${DIAG_LOG}$1
"
}

# Collect system and environment info for the diagnostic log
collect_diagnostics() {
    diag "==============================================================================="
    diag "CLAUDE CLI SETUP — DIAGNOSTIC LOG"
    diag "==============================================================================="
    diag ""
    diag "Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    diag "Script:    $0"
    diag "Arguments: $ORIGINAL_ARGS"
    diag ""
    diag "--- SYSTEM INFO ---"
    diag "Hostname:  $(hostname 2>/dev/null || echo 'unknown')"
    diag "OS:        $(uname -s 2>/dev/null || echo 'unknown') $(uname -r 2>/dev/null || echo '')"
    diag "Arch:      $(uname -m 2>/dev/null || echo 'unknown')"
    diag "User:      $(whoami 2>/dev/null || echo 'unknown')"
    diag "Home:      $HOME"
    diag "Shell:     $SHELL"
    diag "PATH:      $PATH"
    diag ""
    diag "--- AZURE CLI ---"
    if command -v az &> /dev/null; then
        diag "Installed: YES"
        diag "Location:  $(command -v az)"
        diag "Version:   $(az --version 2>&1 | head -n5)"
        diag ""
        if az account show &> /dev/null 2>&1; then
            diag "Logged in: YES"
            diag "Account:   $(az account show 2>&1)"
        else
            diag "Logged in: NO"
            diag "az account show output: $(az account show 2>&1)"
        fi
    else
        diag "Installed: NO"
        diag "Searched:  $(echo "$PATH" | tr ':' '\n')"
    fi
    diag ""
    diag "--- CLAUDE CLI ---"
    if command -v claude &> /dev/null; then
        diag "Installed: YES"
        diag "Location:  $(command -v claude)"
        diag "Version:   $(claude --version 2>&1)"
    else
        diag "Installed: NO"
    fi
    diag ""
    diag "--- NODE/NPM ---"
    if command -v node &> /dev/null; then
        diag "Node:      $(node --version 2>&1)"
    else
        diag "Node:      NOT INSTALLED"
    fi
    if command -v npm &> /dev/null; then
        diag "npm:       $(npm --version 2>&1)"
    else
        diag "npm:       NOT INSTALLED"
    fi
    diag ""
    diag "--- CONFIGURATION ---"
    diag "Base URL:      $BASE_URL"
    diag "Sonnet Model:  $SONNET_MODEL"
    diag "Haiku Model:   $HAIKU_MODEL"
    diag "Opus Model:    $OPUS_MODEL"
    diag "Skip Token:    $SKIP_TOKEN"
    diag ""
    diag "--- FILE STATE ---"
    diag "~/.claude/ exists:          $([ -d "$CLAUDE_DIR" ] && echo 'YES' || echo 'NO')"
    if [ -d "$CLAUDE_DIR" ]; then
        diag "~/.claude/ permissions:     $(stat -f '%A %Sp' "$CLAUDE_DIR" 2>/dev/null || stat -c '%a %A' "$CLAUDE_DIR" 2>/dev/null)"
        diag "~/.claude/ contents:"
        diag "$(ls -la "$CLAUDE_DIR" 2>&1 | sed 's/^/    /')"
    fi
    diag ""
    diag "settings.json exists:       $([ -f "$SETTINGS_FILE" ] && echo 'YES' || echo 'NO')"
    if [ -f "$SETTINGS_FILE" ]; then
        diag "settings.json content:"
        diag "$(sed 's/^/    /' "$SETTINGS_FILE" 2>&1)"
    fi
    diag ""
    diag "get-claude-token.sh exists: $([ -f "$TOKEN_SCRIPT" ] && echo 'YES' || echo 'NO')"
    if [ -f "$TOKEN_SCRIPT" ]; then
        diag "get-claude-token.sh permissions: $(stat -f '%A %Sp' "$TOKEN_SCRIPT" 2>/dev/null || stat -c '%a %A' "$TOKEN_SCRIPT" 2>/dev/null)"
    fi
    diag ""
    diag "claudekey.txt exists:       $([ -f "$TOKEN_FILE" ] && echo 'YES' || echo 'NO')"
    if [ -f "$TOKEN_FILE" ]; then
        local token_len
        token_len=$(wc -c < "$TOKEN_FILE" 2>/dev/null | tr -d ' ')
        diag "claudekey.txt size:         ${token_len} bytes"
    fi
    diag ""
    diag "--- ENVIRONMENT VARIABLES ---"
    diag "ANTHROPIC_FOUNDRY_BASE_URL:     ${ANTHROPIC_FOUNDRY_BASE_URL:-(not set)}"
    diag "ANTHROPIC_DEFAULT_SONNET_MODEL: ${ANTHROPIC_DEFAULT_SONNET_MODEL:-(not set)}"
    diag "ANTHROPIC_DEFAULT_HAIKU_MODEL:  ${ANTHROPIC_DEFAULT_HAIKU_MODEL:-(not set)}"
    diag "ANTHROPIC_DEFAULT_OPUS_MODEL:   ${ANTHROPIC_DEFAULT_OPUS_MODEL:-(not set)}"
    diag "CLAUDE_CODE_USE_FOUNDRY:        ${CLAUDE_CODE_USE_FOUNDRY:-(not set)}"
    diag ""
}

# Write the diagnostic log to a file and tell the user where it is
save_diagnostic_log() {
    # Pick a location the user can easily find
    local desktop="${HOME}/Desktop"
    local log_dir
    if [ -d "$desktop" ]; then
        log_dir="$desktop"
    else
        log_dir="$HOME"
    fi

    DIAG_LOG_FILE="${log_dir}/claude-setup-log-$(date +%Y%m%d-%H%M%S).txt"

    # Append the step-by-step output log
    diag "--- SETUP STEP LOG ---"
    diag "$STEP_LOG"
    diag ""
    diag "==============================================================================="
    diag "END OF DIAGNOSTIC LOG"
    diag "==============================================================================="

    echo "$DIAG_LOG" > "$DIAG_LOG_FILE" 2>/dev/null

    if [ -f "$DIAG_LOG_FILE" ]; then
        return 0
    else
        # Fallback to /tmp if Desktop/Home is not writable
        DIAG_LOG_FILE="/tmp/claude-setup-log-$(date +%Y%m%d-%H%M%S).txt"
        echo "$DIAG_LOG" > "$DIAG_LOG_FILE" 2>/dev/null
        return 0
    fi
}

# ============================================================================
# Helper Functions
# ============================================================================

# Captured step output for the diagnostic log
STEP_LOG=""

step_log() {
    STEP_LOG="${STEP_LOG}$1
"
}

log_info() {
    echo -e "${GREEN}✓${NC} $1"
    step_log "[OK]      $1"
}

log_warn() {
    local message="$1"
    echo -e "${YELLOW}⚠${NC} $message"
    step_log "[WARNING] $message"
    HAS_WARNINGS=true
}

log_error() {
    local message="$1"
    echo -e "${RED}✗${NC} $message"
    step_log "[ERROR]   $message"
    HAS_ERRORS=true
}

log_debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
    step_log "[DEBUG]   $1"
}

print_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              CLAUDE CLI SETUP AUTOMATION                   ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  Base URL:     %-44s║\n" "$BASE_URL"
    printf "║  Sonnet Model: %-44s║\n" "$SONNET_MODEL"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

print_success() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║   SETUP COMPLETE — You're all set!                         ║"
    echo "║                                                            ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  Directory:    %-44s║\n" "$CLAUDE_DIR"
    printf "║  Token Script: %-44s║\n" "get-claude-token.sh"
    printf "║  Settings:     %-44s║\n" "settings.json"
    printf "║  Token File:   %-44s║\n" "claudekey.txt"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Next Steps:                                               ║"
    echo "║  1. Test your setup: claude --version                      ║"
    echo "║  2. Generate fresh token: ~/.claude/get-claude-token.sh    ║"
    echo "║  3. Start coding: claude                                   ║"
    echo "║                                                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

print_failure() {
    # Generate and save the diagnostic log
    collect_diagnostics
    save_diagnostic_log

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    if [ "$HAS_ERRORS" = true ]; then
        echo "║   SETUP DID NOT COMPLETE SUCCESSFULLY                      ║"
    else
        echo "║   SETUP COMPLETED WITH WARNINGS                            ║"
    fi
    echo "║                                                            ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                            ║"
    echo "║   A diagnostic log has been saved to your Desktop.         ║"
    echo "║                                                            ║"
    echo "║   Please send this file to IT support:                     ║"
    echo "║                                                            ║"
    printf "║     %-56s║\n" "$(basename "$DIAG_LOG_FILE")"
    echo "║                                                            ║"
    printf "║   Location: %-48s║\n" "$DIAG_LOG_FILE"
    echo "║                                                            ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                            ║"
    echo "║   What to do:                                              ║"
    echo "║                                                            ║"
    echo "║   1. Find the file on your Desktop                         ║"
    echo "║      (or the location shown above)                         ║"
    echo "║                                                            ║"
    echo "║   2. Email it to your IT support team, or attach           ║"
    echo "║      it to a support ticket                                ║"
    echo "║                                                            ║"
    echo "║   3. IT will have everything they need to help you         ║"
    echo "║                                                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

check_azure_cli() {
    echo ""
    echo "─── Pre-flight Checks ───"

    if ! command -v az &> /dev/null; then
        log_error "Azure CLI (az) is not installed on this computer."
        return 1
    fi

    local version
    version=$(az --version 2>&1 | head -n1)
    log_info "Found: $version"
}

check_azure_login() {
    if az account show &> /dev/null; then
        local user
        user=$(az account show --query user.name -o tsv 2>/dev/null)
        log_info "Logged in as: $user"
    else
        log_warn "Not logged into Azure. You may be prompted to sign in."
    fi
}

check_claude_cli() {
    if command -v claude &> /dev/null; then
        local version
        version=$(claude --version 2>&1)
        log_info "Claude CLI found: $version"
    else
        log_warn "Claude CLI is not installed yet."
    fi
}

# ============================================================================
# Setup Functions
# ============================================================================

create_claude_directory() {
    echo ""
    echo "─── Step 1: Create ~/.claude Directory ───"

    if [ -d "$CLAUDE_DIR" ]; then
        log_debug "Directory already exists: $CLAUDE_DIR"
    else
        if ! mkdir -p "$CLAUDE_DIR"; then
            log_error "Could not create the configuration folder: $CLAUDE_DIR"
            return 1
        fi
        log_debug "Created directory: $CLAUDE_DIR"
    fi

    log_info "Directory ready: $CLAUDE_DIR"
}

create_token_script() {
    echo ""
    echo "─── Step 2: Create Token Script ───"

    # Check if script already exists
    if [ -f "$TOKEN_SCRIPT" ]; then
        log_debug "Token script already exists, will overwrite"
        cp "$TOKEN_SCRIPT" "${TOKEN_SCRIPT}.backup.$(date +%Y%m%d_%H%M%S)"
        log_debug "Backed up existing script"
    fi

    # Create the token script
    if ! cat > "$TOKEN_SCRIPT" << 'EOF'
#!/bin/bash
if ! az account get-access-token > /dev/null 2>&1; then
    az login > /dev/null 2>&1
fi
az account get-access-token --resource "https://cognitiveservices.azure.com" --query accessToken -o tsv
EOF
    then
        log_error "Could not create the token script: $TOKEN_SCRIPT"
        return 1
    fi

    # Make it executable
    chmod +x "$TOKEN_SCRIPT"

    log_info "Token script created: $TOKEN_SCRIPT"
    log_debug "Script permissions: $(stat -f '%A' "$TOKEN_SCRIPT" 2>/dev/null || stat -c '%a' "$TOKEN_SCRIPT" 2>/dev/null)"
}

create_settings_json() {
    echo ""
    echo "─── Step 3: Create Settings File ───"

    # Backup existing settings if they exist
    if [ -f "$SETTINGS_FILE" ]; then
        cp "$SETTINGS_FILE" "${SETTINGS_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "Backed up existing settings"
    fi

    # Create the settings JSON
    if ! cat > "$SETTINGS_FILE" << EOF
{
  "apiKeyHelper": "~/.claude/get-claude-token.sh",
  "env": {
    "CLAUDE_CODE_USE_FOUNDRY": "1",
    "ANTHROPIC_FOUNDRY_BASE_URL": "$BASE_URL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "$SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "$HAIKU_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "$OPUS_MODEL"
  }
}
EOF
    then
        log_error "Could not create the settings file: $SETTINGS_FILE"
        return 1
    fi

    log_info "Settings file created: $SETTINGS_FILE"

    if [ "$DEBUG" = true ]; then
        log_debug "Settings content:"
        sed 's/^/  /' "$SETTINGS_FILE"
    fi
}

generate_token() {
    echo ""
    echo "─── Step 4: Generate Token ───"

    if [ "$SKIP_TOKEN" = true ]; then
        log_info "Token generation skipped (--skip-token flag)"
        return 0
    fi

    log_debug "Executing token script..."

    # Generate token — capture stdout and stderr separately
    local token_stderr
    local token_err_file="/tmp/claude_setup_token_err$$"
    if TOKEN=$("$TOKEN_SCRIPT" 2>"$token_err_file"); then
        token_stderr=$(cat "$token_err_file" 2>/dev/null)
        rm -f "$token_err_file"

        # Check if token is not empty
        if [ -z "$TOKEN" ]; then
            log_warn "Token generation returned an empty result."
            echo "  You can generate it manually later with: $TOKEN_SCRIPT"
            return 0
        fi

        # Save token to file with restricted permissions
        (umask 077 && echo "$TOKEN" > "$TOKEN_FILE")

        local token_length=${#TOKEN}
        local token_preview="${TOKEN:0:20}...${TOKEN: -20}"

        log_info "Token generated and saved to: $TOKEN_FILE"
        log_debug "Token length: $token_length characters"
        log_debug "Token preview: $token_preview"
    else
        token_stderr=$(cat "$token_err_file" 2>/dev/null)
        rm -f "$token_err_file"
        log_warn "Token generation failed."
        if [ -n "$token_stderr" ]; then
            step_log "[DETAIL]  Azure error output: $token_stderr"
        fi
        echo "  You can generate it manually later with: $TOKEN_SCRIPT"
    fi

    return 0
}

test_setup() {
    echo ""
    echo "─── Step 5: Test Setup ───"

    if command -v claude &> /dev/null; then
        local version
        version=$(claude --version 2>&1)
        log_info "Claude CLI test passed: $version"
    else
        log_debug "Claude CLI not found (already reported in pre-flight)"
    fi
}

# ============================================================================
# Argument Parsing
# ============================================================================

show_help() {
    cat << EOF
Claude CLI Setup - Single Script Automation

Usage:
    $0 [OPTIONS]

Options:
    --base-url URL       Anthropic Foundry base URL
                         Default: $BASE_URL

    --sonnet-model NAME  Sonnet model name
                         Default: $SONNET_MODEL

    --haiku-model NAME   Haiku model name
                         Default: $HAIKU_MODEL

    --opus-model NAME    Opus model name
                         Default: $OPUS_MODEL

    --skip-token         Skip token generation (setup configuration only)

    --debug              Enable debug logging

    --help               Show this help message

Examples:
    $0
    $0 --skip-token
    $0 --base-url "https://custom.url.com"
    $0 --debug

Environment Variables:
    ANTHROPIC_FOUNDRY_BASE_URL
    ANTHROPIC_DEFAULT_SONNET_MODEL
    ANTHROPIC_DEFAULT_HAIKU_MODEL
    ANTHROPIC_DEFAULT_OPUS_MODEL

Files Created:
    ~/.claude/get-claude-token.sh    Token generation script
    ~/.claude/settings.json          Claude CLI configuration
    ~/.claude/claudekey.txt          Generated token

Troubleshooting:
    If setup fails, a diagnostic log file is automatically saved
    to your Desktop. Send that file to IT support for help.
EOF
}

# Save original args for the diagnostic log
ORIGINAL_ARGS="$*"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --base-url)
            if [[ -z "${2:-}" || "$2" == --* ]]; then
                echo "Error: --base-url requires a value"
                exit 1
            fi
            BASE_URL="$2"
            shift 2
            ;;
        --sonnet-model)
            if [[ -z "${2:-}" || "$2" == --* ]]; then
                echo "Error: --sonnet-model requires a value"
                exit 1
            fi
            SONNET_MODEL="$2"
            shift 2
            ;;
        --haiku-model)
            if [[ -z "${2:-}" || "$2" == --* ]]; then
                echo "Error: --haiku-model requires a value"
                exit 1
            fi
            HAIKU_MODEL="$2"
            shift 2
            ;;
        --opus-model)
            if [[ -z "${2:-}" || "$2" == --* ]]; then
                echo "Error: --opus-model requires a value"
                exit 1
            fi
            OPUS_MODEL="$2"
            shift 2
            ;;
        --skip-token)
            SKIP_TOKEN=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================================
# Main Execution
# ============================================================================

main() {
    print_header

    # Pre-flight checks — Azure CLI is required, the rest are warnings
    if ! check_azure_cli; then
        print_failure
        exit 1
    fi
    check_azure_login
    check_claude_cli

    # Setup steps — directory and file writes are required
    if ! create_claude_directory; then
        print_failure
        exit 1
    fi

    if ! create_token_script; then
        print_failure
        exit 1
    fi

    if ! create_settings_json; then
        print_failure
        exit 1
    fi

    generate_token
    test_setup

    # Final result
    if [ "$HAS_ERRORS" = true ] || [ "$HAS_WARNINGS" = true ]; then
        print_failure
        if [ "$HAS_ERRORS" = true ]; then
            exit 1
        fi
    else
        print_success
    fi
}

main
