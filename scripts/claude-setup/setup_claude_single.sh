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
# Usage:
#   ./setup_claude_single.sh
#   ./setup_claude_single.sh --skip-token
#   ./setup_claude_single.sh --debug
#   ./setup_claude_single.sh --base-url "https://custom.url.com"
################################################################################

set -e  # Exit on error

# ============================================================================
# Configuration (can be overridden by command-line args)
# ============================================================================

CLAUDE_DIR="${HOME}/.claude"
TOKEN_SCRIPT="${CLAUDE_DIR}/get-claude-token.sh"
SETTINGS_FILE="${CLAUDE_DIR}/settings.json"
TOKEN_FILE="${CLAUDE_DIR}/claudekey.txt"

# Default configuration
BASE_URL="${ANTHROPIC_FOUNDRY_BASE_URL:-https://snapistg.sleepnumber.com/anthropic}"
SONNET_MODEL="${ANTHROPIC_DEFAULT_SONNET_MODEL:-cogdep-aifoundry-dev-eus2-claude-sonnet-4-5}"
HAIKU_MODEL="${ANTHROPIC_DEFAULT_HAIKU_MODEL:-cogdep-aifoundry-dev-eus2-claude-haiku-4-5}"
OPUS_MODEL="${ANTHROPIC_DEFAULT_OPUS_MODEL:-cogdep-aifoundry-dev-eus2-claude-opus-4-5}"

SKIP_TOKEN=false
DEBUG=false

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
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

print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║   CLAUDE CLI SETUP COMPLETE                                ║"
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

# ============================================================================
# Pre-flight Checks
# ============================================================================

check_azure_cli() {
    echo ""
    echo "─── Pre-flight Checks ───"

    if ! command -v az &> /dev/null; then
        log_error "Azure CLI (az) not found. Install it:"
        echo "  macOS:   brew install azure-cli"
        echo "  Linux:   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
        echo "  Windows: winget install Microsoft.AzureCLI"
        exit 1
    fi

    local version=$(az --version 2>&1 | head -n1)
    log_info "Found: $version"
}

check_azure_login() {
    if az account show &> /dev/null; then
        local user=$(az account show --query user.name -o tsv 2>/dev/null)
        log_info "Logged in as: $user"
        return 0
    else
        log_warn "Not logged into Azure. You'll need to login when generating the token."
        return 1
    fi
}

check_claude_cli() {
    if command -v claude &> /dev/null; then
        local version=$(claude --version 2>&1)
        log_info "Claude CLI found: $version"
        return 0
    else
        log_warn "Claude CLI not found. Install from: https://github.com/anthropics/claude-code"
        return 1
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
        mkdir -p "$CLAUDE_DIR"
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
        # Backup existing script
        cp "$TOKEN_SCRIPT" "${TOKEN_SCRIPT}.backup"
        log_debug "Backed up existing script to: ${TOKEN_SCRIPT}.backup"
    fi

    # Create the token script
    cat > "$TOKEN_SCRIPT" << 'EOF'
#!/bin/bash
if ! az account get-access-token > /dev/null 2>&1; then
    az login > /dev/null 2>&1
fi
az account get-access-token --resource "https://cognitiveservices.azure.com" --query accessToken -o tsv
EOF

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
        cp "$SETTINGS_FILE" "${SETTINGS_FILE}.backup"
        log_info "Backed up existing settings to: ${SETTINGS_FILE}.backup"
    fi

    # Create the settings JSON
    cat > "$SETTINGS_FILE" << EOF
{
  "apiKeyHelper": "$TOKEN_SCRIPT",
  "env": {
    "CLAUDE_CODE_USE_FOUNDRY": "1",
    "ANTHROPIC_FOUNDRY_BASE_URL": "$BASE_URL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "$SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "$HAIKU_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "$OPUS_MODEL"
  }
}
EOF

    log_info "Settings file created: $SETTINGS_FILE"

    if [ "$DEBUG" = true ]; then
        log_debug "Settings content:"
        cat "$SETTINGS_FILE" | sed 's/^/  /'
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

    # Generate token
    if TOKEN=$("$TOKEN_SCRIPT" 2>&1); then
        # Check if token is not empty
        if [ -z "$TOKEN" ]; then
            log_error "Token generation returned empty result"
            log_warn "You can generate it manually later with: $TOKEN_SCRIPT"
            return 1
        fi

        # Save token to file
        echo "$TOKEN" > "$TOKEN_FILE"

        # Get token info
        local token_length=${#TOKEN}
        local token_preview="${TOKEN:0:20}...${TOKEN: -20}"

        log_info "Token generated and saved to: $TOKEN_FILE"
        log_debug "Token length: $token_length characters"
        log_debug "Token preview: $token_preview"

        return 0
    else
        log_error "Token generation failed: $TOKEN"
        log_warn "You can generate it manually later with: $TOKEN_SCRIPT"
        return 1
    fi
}

test_setup() {
    echo ""
    echo "─── Step 5: Test Setup ───"

    if command -v claude &> /dev/null; then
        local version=$(claude --version 2>&1)
        log_info "Claude CLI test passed: $version"
        return 0
    else
        log_warn "Claude CLI not found. Install it to use this configuration:"
        echo "  https://github.com/anthropics/claude-code"
        return 1
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
EOF
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --base-url)
            BASE_URL="$2"
            shift 2
            ;;
        --sonnet-model)
            SONNET_MODEL="$2"
            shift 2
            ;;
        --haiku-model)
            HAIKU_MODEL="$2"
            shift 2
            ;;
        --opus-model)
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

    # Pre-flight checks
    check_azure_cli
    check_azure_login
    check_claude_cli

    # Setup steps
    create_claude_directory
    create_token_script
    create_settings_json
    generate_token
    test_setup

    # Summary
    print_summary
}

# Run main function
main

exit 0
