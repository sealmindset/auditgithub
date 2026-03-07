# Claude CLI Setup Automation

Automates the complete setup of Claude CLI configuration with Azure token integration.

## What It Does

This script automates the manual setup process by:

1. ✅ Creating `~/.claude` directory
2. ✅ Generating `get-claude-token.sh` script
3. ✅ Creating/updating `settings.json` with API configuration
4. ✅ Generating and saving Claude token
5. ✅ Testing the setup

## Prerequisites

- **Azure CLI** - Install with: `brew install azure-cli`
- **Azure Account** - Must be logged in: `az login`
- **Claude CLI** (optional for setup, required for usage) - Get from: https://github.com/anthropics/claude-code

## Quick Start

### Basic Usage

```bash
# Run with defaults
python3 setup_claude.py

# Or use the shell wrapper
./setup_claude.sh
```

### With Custom Configuration

```bash
# Custom base URL
python3 setup_claude.py --base-url "https://custom.anthropic.url"

# Skip token generation (setup only)
python3 setup_claude.py --skip-token

# Debug mode
python3 setup_claude.py --debug
```

## What Gets Created

```
~/.claude/
├── get-claude-token.sh    # Token generation script
├── settings.json          # Claude CLI configuration
└── claudekey.txt          # Generated token
```

### get-claude-token.sh

Bash script that:
- Checks Azure login status
- Prompts for login if needed
- Generates access token for Cognitive Services

### settings.json

Configuration with:
- API key helper script path
- Foundry base URL
- Default model names (Sonnet, Haiku, Opus)

### claudekey.txt

The generated Azure access token (refreshed by the script).

## Command-Line Options

```
--base-url URL       Anthropic Foundry base URL
                     Default: https://snapistg-scus.azure.sleepnumber.com/anthropic

--sonnet-model NAME  Sonnet model name
                     Default: cogdep-aifoundry-dev-eus2-claude-sonnet-4-5

--haiku-model NAME   Haiku model name
                     Default: cogdep-aifoundry-dev-eus2-claude-haiku-4-5

--opus-model NAME    Opus model name
                     Default: cogdep-aifoundry-dev-eus2-claude-opus-4-6

--skip-token         Skip token generation (setup configuration only)

--debug              Enable debug logging
```

## Environment Variables

You can set defaults via environment variables:

```bash
export ANTHROPIC_FOUNDRY_BASE_URL="https://custom.url.com"
export ANTHROPIC_DEFAULT_SONNET_MODEL="custom-sonnet-model"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="custom-haiku-model"
export ANTHROPIC_DEFAULT_OPUS_MODEL="custom-opus-model"
```

## Manual Setup Equivalent

This script automates the following manual commands:

```bash
# 1. Create directory
mkdir -p ~/.claude

# 2. Create token script
cat > ~/.claude/get-claude-token.sh << 'EOF'
#!/bin/bash
if ! az account get-access-token > /dev/null 2>&1; then
    az login > /dev/null 2>&1
fi
az account get-access-token --resource "https://cognitiveservices.azure.com" --query accessToken -o tsv
EOF
chmod +x ~/.claude/get-claude-token.sh

# 3. Create settings.json
cat > ~/.claude/settings.json << 'EOF'
{
  "apiKeyHelper": "~/.claude/get-claude-token.sh",
  "env": {
    "CLAUDE_CODE_USE_FOUNDRY": "1",
    "ANTHROPIC_FOUNDRY_BASE_URL": "https://snapistg-scus.azure.sleepnumber.com/anthropic",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "cogdep-aifoundry-dev-eus2-claude-sonnet-4-5",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "cogdep-aifoundry-dev-eus2-claude-haiku-4-5",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "cogdep-aifoundry-dev-eus2-claude-opus-4-6"
  }
}
EOF

# 4. Generate token
~/.claude/get-claude-token.sh > ~/.claude/claudekey.txt

# 5. Test
claude --version
```

## Troubleshooting

### "Azure CLI (az) not found"
Install Azure CLI:
```bash
brew install azure-cli
```

### "Not logged into Azure"
Login to Azure:
```bash
az login
```

### "Token generation failed"
Manually generate token:
```bash
~/.claude/get-claude-token.sh
```

### "Claude CLI not found"
Install Claude CLI from: https://github.com/anthropics/claude-code

The script will still complete setup successfully even if Claude CLI is not installed.

## Testing the Setup

After running the script:

```bash
# Test Claude CLI
claude --version

# Generate a fresh token
~/.claude/get-claude-token.sh

# View your configuration
cat ~/.claude/settings.json

# Check token
cat ~/.claude/claudekey.txt
```

## Security Notes

- ✅ Token script uses secure Azure authentication
- ✅ Tokens are generated on-demand
- ✅ No hardcoded credentials
- ✅ Existing settings are backed up before modification
- ✅ Token file permissions should be restricted (600)

## Files Created

| File | Purpose | Executable |
|------|---------|------------|
| `get-claude-token.sh` | Generate Azure token | ✅ Yes |
| `settings.json` | Claude CLI config | ❌ No |
| `claudekey.txt` | Stored token | ❌ No |
| `settings.json.backup` | Backup of old settings | ❌ No |

## Integration with Azure Login Script

This script works alongside the Azure login automation:

```bash
# 1. Login to Azure (if needed)
cd ../azure-login
source venv/bin/activate
python az_login.py

# 2. Setup Claude CLI
cd ../claude-setup
python3 setup_claude.py

# 3. Start using Claude
claude
```

## Examples

### Complete Fresh Setup
```bash
python3 setup_claude.py
```

### Update Configuration Only
```bash
python3 setup_claude.py --skip-token
```

### Custom Environment
```bash
python3 setup_claude.py \
  --base-url "https://production.url.com" \
  --sonnet-model "production-sonnet" \
  --debug
```

## Support

For issues:
- Check Azure login: `az account show`
- Check token script: `~/.claude/get-claude-token.sh`
- Run with debug: `python3 setup_claude.py --debug`
- Review logs in the terminal output
