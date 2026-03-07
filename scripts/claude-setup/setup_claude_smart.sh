#!/bin/bash
################################################################################
# Claude CLI Setup - Smart Settings Merge
#
# This version intelligently handles settings.json changes:
# - Preserves custom settings not managed by this script
# - Only updates Claude-specific configuration
# - Merges environment variables instead of replacing
# - Offers interactive mode to confirm changes
#
# Usage:
#   ./setup_claude_smart.sh
#   ./setup_claude_smart.sh --force        # Skip confirmation
#   ./setup_claude_smart.sh --update-only  # Only update settings, don't regenerate token
################################################################################

set -e  # Exit on error

# ============================================================================
# Configuration
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
UPDATE_ONLY=false
FORCE=false
DEBUG=false
INTERACTIVE=true

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Keys managed by this script
MANAGED_ENV_KEYS=(
    "CLAUDE_CODE_USE_FOUNDRY"
    "ANTHROPIC_FOUNDRY_BASE_URL"
    "ANTHROPIC_DEFAULT_SONNET_MODEL"
    "ANTHROPIC_DEFAULT_HAIKU_MODEL"
    "ANTHROPIC_DEFAULT_OPUS_MODEL"
)

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

log_change() {
    echo -e "${CYAN}  →${NC} $1"
}

print_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CLAUDE CLI SMART SETUP & UPDATE                  ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  Base URL:     %-44s║\n" "$BASE_URL"
    printf "║  Sonnet Model: %-44s║\n" "$SONNET_MODEL"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# ============================================================================
# JSON Helper Functions (using Python for reliable JSON parsing)
# ============================================================================

has_jq() {
    command -v jq &> /dev/null
}

has_python() {
    command -v python3 &> /dev/null
}

# Check if we can parse JSON
check_json_parser() {
    if has_jq; then
        log_debug "Using jq for JSON parsing"
        return 0
    elif has_python; then
        log_debug "Using Python for JSON parsing"
        return 0
    else
        log_error "Neither jq nor python3 found. Install one of them:"
        echo "  brew install jq"
        echo "  or ensure python3 is installed"
        exit 1
    fi
}

# Get value from JSON using path
json_get() {
    local file="$1"
    local path="$2"

    if has_jq; then
        jq -r "$path // empty" "$file" 2>/dev/null || echo ""
    else
        python3 -c "
import json, sys
try:
    with open('$file') as f:
        data = json.load(f)
    keys = '$path'.strip('.').split('.')
    value = data
    for key in keys:
        if key and key in value:
            value = value[key]
        else:
            sys.exit(1)
    print(value)
except:
    sys.exit(1)
" 2>/dev/null || echo ""
    fi
}

# Merge settings JSON files
merge_settings() {
    local old_file="$1"
    local new_file="$2"

    log_debug "Merging settings from $old_file into $new_file"

    if has_jq; then
        # Use jq for smart merge
        jq -s '.[0] * .[1] | .env = (.[0].env // {}) * (.[1].env // {})' \
            "$old_file" "$new_file" > "${new_file}.tmp"
        mv "${new_file}.tmp" "$new_file"
    else
        # Use Python for merge
        python3 << 'PYTHON_EOF'
import json
import sys

try:
    # Read both files
    with open(''"$old_file"'') as f:
        old = json.load(f)
    with open(''"$new_file"'') as f:
        new = json.load(f)

    # Merge top-level keys (new overwrites old for managed keys)
    merged = old.copy()

    # Update with new values (but preserve other top-level keys)
    for key in ['apiKeyHelper']:
        if key in new:
            merged[key] = new[key]

    # Merge env variables (preserve custom ones, update managed ones)
    if 'env' in merged:
        old_env = merged['env']
        new_env = new.get('env', {})

        # Preserve all old env vars
        merged_env = old_env.copy()

        # Update with new managed vars
        for key in new_env:
            merged_env[key] = new_env[key]

        merged['env'] = merged_env
    else:
        merged['env'] = new.get('env', {})

    # Write merged result
    with open(''"$new_file"'', 'w') as f:
        json.dump(merged, f, indent=2)
        f.write('\n')

    sys.exit(0)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
PYTHON_EOF
    fi
}

# Show differences between old and new settings
show_settings_diff() {
    local old_file="$1"
    local new_file="$2"

    echo ""
    echo "Settings changes:"
    echo "────────────────────────────────────────────────"

    # Check apiKeyHelper
    local old_helper=$(json_get "$old_file" ".apiKeyHelper")
    local new_helper=$(json_get "$new_file" ".apiKeyHelper")

    if [ "$old_helper" != "$new_helper" ]; then
        echo "  apiKeyHelper:"
        log_change "Old: $old_helper"
        log_change "New: $new_helper"
    fi

    # Check each managed env variable
    for key in "${MANAGED_ENV_KEYS[@]}"; do
        local old_val=$(json_get "$old_file" ".env.$key")
        local new_val=$(json_get "$new_file" ".env.$key")

        if [ "$old_val" != "$new_val" ]; then
            echo "  env.$key:"
            if [ -z "$old_val" ]; then
                log_change "Adding: $new_val"
            else
                log_change "Old: $old_val"
                log_change "New: $new_val"
            fi
        fi
    done

    echo "────────────────────────────────────────────────"
    echo ""
}

confirm_changes() {
    if [ "$FORCE" = true ] || [ "$INTERACTIVE" = false ]; then
        return 0
    fi

    echo -n "Apply these changes? [Y/n] "
    read -r response
    case "$response" in
        [nN][oO]|[nN])
            log_warn "Changes cancelled by user"
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

# ============================================================================
# Setup Functions
# ============================================================================

check_prerequisites() {
    echo "─── Pre-flight Checks ───"

    # Check Azure CLI
    if ! command -v az &> /dev/null; then
        log_error "Azure CLI not found"
        exit 1
    fi
    log_info "Azure CLI found"

    # Check JSON parser
    check_json_parser

    # Check Azure login
    if az account show &> /dev/null; then
        local user=$(az account show --query user.name -o tsv 2>/dev/null)
        log_info "Logged in as: $user"
    else
        log_warn "Not logged into Azure"
    fi
}

create_claude_directory() {
    echo ""
    echo "─── Step 1: Create Directory ───"

    mkdir -p "$CLAUDE_DIR"
    log_info "Directory ready: $CLAUDE_DIR"
}

create_token_script() {
    echo ""
    echo "─── Step 2: Token Script ───"

    if [ -f "$TOKEN_SCRIPT" ]; then
        log_info "Token script exists (keeping existing)"
        return 0
    fi

    cat > "$TOKEN_SCRIPT" << 'EOF'
#!/bin/bash
if ! az account get-access-token > /dev/null 2>&1; then
    az login > /dev/null 2>&1
fi
az account get-access-token --resource "https://cognitiveservices.azure.com" --query accessToken -o tsv
EOF

    chmod +x "$TOKEN_SCRIPT"
    log_info "Token script created: $TOKEN_SCRIPT"
}

update_settings() {
    echo ""
    echo "─── Step 3: Update Settings ───"

    # Create new settings template
    local temp_new="${SETTINGS_FILE}.new"
    cat > "$temp_new" << EOF
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

    if [ -f "$SETTINGS_FILE" ]; then
        # Existing settings - show diff and merge
        log_info "Existing settings found"

        # Backup
        cp "$SETTINGS_FILE" "${SETTINGS_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        log_debug "Created timestamped backup"

        # Show what will change
        show_settings_diff "$SETTINGS_FILE" "$temp_new"

        # Confirm changes
        if confirm_changes; then
            # Merge settings (preserves custom keys)
            merge_settings "$SETTINGS_FILE" "$temp_new"
            log_info "Settings updated (custom settings preserved)"
        else
            rm "$temp_new"
            return 1
        fi
    else
        # New settings - just create
        mv "$temp_new" "$SETTINGS_FILE"
        log_info "Settings created: $SETTINGS_FILE"
    fi

    rm -f "$temp_new"
}

generate_token() {
    echo ""
    echo "─── Step 4: Generate Token ───"

    if [ "$SKIP_TOKEN" = true ]; then
        log_info "Token generation skipped"
        return 0
    fi

    if [ "$UPDATE_ONLY" = true ]; then
        log_info "Update-only mode: keeping existing token"
        return 0
    fi

    if TOKEN=$("$TOKEN_SCRIPT" 2>&1); then
        if [ -n "$TOKEN" ]; then
            echo "$TOKEN" > "$TOKEN_FILE"
            log_info "Token generated: $TOKEN_FILE"
            return 0
        fi
    fi

    log_warn "Token generation failed (run manually: $TOKEN_SCRIPT)"
    return 1
}

test_setup() {
    echo ""
    echo "─── Step 5: Test Setup ───"

    if command -v claude &> /dev/null; then
        local version=$(claude --version 2>&1)
        log_info "Claude CLI ready: $version"
    else
        log_warn "Claude CLI not found"
    fi
}

show_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    SETUP COMPLETE                          ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  ✓ Settings updated with merge strategy                   ║"
    echo "║  ✓ Custom settings preserved                               ║"
    echo "║  ✓ Environment variables merged                            ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  View your settings:                                       ║"
    echo "║    cat ~/.claude/settings.json                             ║"
    echo "║                                                            ║"
    echo "║  Restore from backup if needed:                            ║"
    echo "║    cp ~/.claude/settings.json.backup.* ~/.claude/settings.json ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

# ============================================================================
# Argument Parsing
# ============================================================================

show_help() {
    cat << EOF
Claude CLI Smart Setup - Preserves Custom Settings

Usage:
    $0 [OPTIONS]

Options:
    --base-url URL       Update base URL
    --sonnet-model NAME  Update Sonnet model
    --haiku-model NAME   Update Haiku model
    --opus-model NAME    Update Opus model

    --update-only        Only update settings (don't regenerate token)
    --skip-token         Same as --update-only
    --force              Skip confirmation prompts
    --debug              Enable debug logging
    --help               Show this help

Examples:
    # Update settings with confirmation
    $0

    # Update base URL only, keep existing token
    $0 --update-only --base-url "https://new-url.com"

    # Force update without prompts
    $0 --force

    # Just update settings, don't touch token
    $0 --skip-token

Merge Strategy:
    This script uses intelligent merging:
    - Preserves custom top-level settings
    - Merges environment variables (keeps custom ones)
    - Only updates Claude-specific configuration
    - Creates timestamped backups before changes

Example:
    Your settings before:
        {
          "customKey": "my-value",
          "env": {
            "CUSTOM_VAR": "important",
            "ANTHROPIC_FOUNDRY_BASE_URL": "old-url"
          }
        }

    After running script:
        {
          "customKey": "my-value",              ← Preserved
          "apiKeyHelper": "~/.claude/...",      ← Updated
          "env": {
            "CUSTOM_VAR": "important",          ← Preserved
            "ANTHROPIC_FOUNDRY_BASE_URL": "new-url",  ← Updated
            "ANTHROPIC_DEFAULT_SONNET_MODEL": "..."   ← Added
          }
        }
EOF
}

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
        --update-only|--skip-token)
            UPDATE_ONLY=true
            SKIP_TOKEN=true
            shift
            ;;
        --force)
            FORCE=true
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
            echo "Use --help for usage"
            exit 1
            ;;
    esac
done

# ============================================================================
# Main
# ============================================================================

main() {
    print_header
    check_prerequisites
    create_claude_directory
    create_token_script

    if update_settings; then
        generate_token
        test_setup
        show_summary
    else
        log_warn "Setup cancelled or failed"
        exit 1
    fi
}

main

exit 0
