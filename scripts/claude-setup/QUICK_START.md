# Claude Setup - Quick Start Guide

## One-Command Setup

```bash
cd /Users/rob.vance@sleepnumber.com/Documents/GitHub/auditgithub/scripts/claude-setup
python3 setup_claude.py
```

That's it! The script will:
1. ✅ Check prerequisites (Azure CLI, Azure login)
2. ✅ Create `~/.claude/` directory
3. ✅ Generate `get-claude-token.sh` script
4. ✅ Create `settings.json` with your configuration
5. ✅ Generate and save your Claude token
6. ✅ Test the setup

## What Gets Created

```
~/.claude/
├── get-claude-token.sh          # Token generation script (executable)
├── settings.json                # Claude CLI configuration
├── claudekey.txt                # Your Azure token
└── settings.json.backup         # Backup of previous settings
```

## Verify Setup

```bash
# Check files were created
ls -la ~/.claude/

# Test token generation
~/.claude/get-claude-token.sh

# Test Claude CLI
claude --version
```

## Common Usage

### Standard Setup
```bash
python3 setup_claude.py
```

### Setup Without Token Generation
```bash
python3 setup_claude.py --skip-token
```

### Custom Configuration
```bash
python3 setup_claude.py \
  --base-url "https://custom.url.com" \
  --sonnet-model "custom-sonnet-model"
```

### Debug Mode
```bash
python3 setup_claude.py --debug
```

## Manual Token Generation

If token generation fails or you need to refresh:

```bash
# Generate new token
~/.claude/get-claude-token.sh > ~/.claude/claudekey.txt

# Or copy to clipboard (macOS)
~/.claude/get-claude-token.sh | pbcopy
```

## Troubleshooting

### "Azure CLI (az) not found"
```bash
brew install azure-cli
```

### "Not logged into Azure"
```bash
# Use the azure-login automation
cd ../azure-login
source venv/bin/activate
python az_login.py
```

### "Token generation failed"
```bash
# Check Azure login
az account show

# Try manual token generation
~/.claude/get-claude-token.sh
```

### Settings Not Working
```bash
# Restore backup
cp ~/.claude/settings.json.backup ~/.claude/settings.json

# Re-run setup
python3 setup_claude.py
```

## Integration with Azure Login

Complete workflow for fresh setup:

```bash
# 1. Login to Azure
cd scripts/azure-login
source venv/bin/activate
python az_login.py

# 2. Setup Claude CLI
cd ../claude-setup
python3 setup_claude.py

# 3. Start using Claude
claude
```

## Configuration Options

| Flag | Description | Default |
|------|-------------|---------|
| `--base-url` | Foundry base URL | `https://snapistg-scus.azure.sleepnumber.com/anthropic` |
| `--sonnet-model` | Sonnet model name | `cogdep-aifoundry-dev-eus2-claude-sonnet-4-5` |
| `--haiku-model` | Haiku model name | `cogdep-aifoundry-dev-eus2-claude-haiku-4-5` |
| `--opus-model` | Opus model name | `cogdep-aifoundry-dev-eus2-claude-opus-4-6` |
| `--skip-token` | Skip token generation | `false` |
| `--debug` | Enable debug logging | `false` |

## Environment Variables

Set defaults via environment:

```bash
export ANTHROPIC_FOUNDRY_BASE_URL="https://custom.url.com"
export ANTHROPIC_DEFAULT_SONNET_MODEL="custom-model"

python3 setup_claude.py
```

## File Permissions

After setup, secure your token file:

```bash
chmod 600 ~/.claude/claudekey.txt
```

## Comparison: Manual vs Automated

| Task | Manual | Automated |
|------|--------|-----------|
| Commands | 8+ separate commands | 1 command |
| Clipboard ops | 3 copy/paste cycles | 0 |
| Time | ~5 minutes | ~5 seconds |
| Validation | None | Complete |
| Backup | Manual | Automatic |
| Error handling | None | Comprehensive |

## Success Indicators

After running the script, you should see:

```
✓ Found: azure-cli 2.82.0
✓ Logged in as: your.email@company.com
✓ Claude CLI found: 2.1.71
✓ Directory ready
✓ Token script created
✓ Settings file created
✓ Token generated and saved
✓ Claude CLI test passed
```

## Next Steps

1. **Verify setup**: `claude --version`
2. **Test token**: `~/.claude/get-claude-token.sh`
3. **Start coding**: `claude`

For detailed documentation, see:
- `README.md` - Complete usage guide
- `IMPLEMENTATION_SPEC.md` - Technical details
- `--help` - Command-line reference

## Support

Issues? Run with debug mode:
```bash
python3 setup_claude.py --debug
```

Check the output for specific error messages and troubleshooting guidance.
