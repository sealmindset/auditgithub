#!/usr/bin/env python3
"""
Claude CLI Setup Automation

Automates the setup of Claude CLI configuration:
1. Creates ~/.claude directory
2. Generates get-claude-token.sh script
3. Creates/updates settings.json with API configuration
4. Tests the setup

Usage:
    python setup_claude.py
    python setup_claude.py --debug
    python setup_claude.py --base-url "https://custom.url.com"
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLAUDE_DIR = Path.home() / ".claude"
TOKEN_SCRIPT = CLAUDE_DIR / "get-claude-token.sh"
SETTINGS_FILE = CLAUDE_DIR / "settings.json"
TOKEN_FILE = CLAUDE_DIR / "claudekey.txt"

DEFAULT_BASE_URL = "https://snapistg.sleepnumber.com/anthropic"
DEFAULT_SONNET_MODEL = "cogdep-aifoundry-dev-eus2-claude-sonnet-4-5"
DEFAULT_HAIKU_MODEL = "cogdep-aifoundry-dev-eus2-claude-haiku-4-5"
DEFAULT_OPUS_MODEL = "cogdep-aifoundry-dev-eus2-claude-opus-4-5"

TOKEN_SCRIPT_CONTENT = """#!/bin/bash
if ! az account get-access-token > /dev/null 2>&1; then
    az login > /dev/null 2>&1
fi
az account get-access-token --resource "https://cognitiveservices.azure.com" --query accessToken -o tsv
"""

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("claude_setup")


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=[logging.StreamHandler(sys.stdout)],
    )


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------


def check_az_cli() -> bool:
    """Verify Azure CLI is installed."""
    logger.info("Checking for Azure CLI (az)...")
    try:
        result = subprocess.run(
            ["az", "--version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            version_line = result.stdout.strip().split("\n")[0]
            logger.info(f"✓ Found: {version_line}")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    logger.error(
        "✗ Azure CLI (az) not found. Install it:\n"
        "  macOS:   brew install azure-cli\n"
        "  Linux:   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash\n"
        "  Windows: winget install Microsoft.AzureCLI"
    )
    return False


def check_azure_login() -> bool:
    """Check if user is logged into Azure."""
    logger.info("Checking Azure login status...")
    try:
        result = subprocess.run(
            ["az", "account", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            account_info = json.loads(result.stdout)
            logger.info(f"✓ Logged in as: {account_info.get('user', {}).get('name', 'Unknown')}")
            return True
    except Exception:
        pass

    logger.warning(
        "✗ Not logged into Azure. You'll need to login when generating the token."
    )
    return False


def check_claude_cli() -> bool:
    """Check if Claude CLI is installed."""
    logger.info("Checking for Claude CLI...")
    try:
        result = subprocess.run(
            ["claude", "--version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logger.info(f"✓ Claude CLI found: {result.stdout.strip()}")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    logger.warning(
        "✗ Claude CLI not found. Install it from:\n"
        "  https://github.com/anthropics/claude-code"
    )
    return False


# ---------------------------------------------------------------------------
# Setup functions
# ---------------------------------------------------------------------------


def create_claude_directory() -> bool:
    """Create the ~/.claude directory if it doesn't exist."""
    logger.info(f"Creating directory: {CLAUDE_DIR}")
    try:
        CLAUDE_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"✓ Directory ready: {CLAUDE_DIR}")
        return True
    except Exception as exc:
        logger.error(f"✗ Failed to create directory: {exc}")
        return False


def create_token_script() -> bool:
    """Create the get-claude-token.sh script."""
    logger.info(f"Creating token script: {TOKEN_SCRIPT}")
    try:
        # Write the script
        TOKEN_SCRIPT.write_text(TOKEN_SCRIPT_CONTENT)

        # Make it executable
        TOKEN_SCRIPT.chmod(0o755)

        logger.info(f"✓ Token script created: {TOKEN_SCRIPT}")
        logger.debug(f"Script permissions: {oct(TOKEN_SCRIPT.stat().st_mode)[-3:]}")
        return True
    except Exception as exc:
        logger.error(f"✗ Failed to create token script: {exc}")
        return False


def create_settings_json(
    base_url: str,
    sonnet_model: str,
    haiku_model: str,
    opus_model: str,
) -> bool:
    """Create or update the settings.json file."""
    logger.info(f"Creating settings file: {SETTINGS_FILE}")

    settings: dict[str, Any] = {
        "apiKeyHelper": str(TOKEN_SCRIPT),
        "env": {
            "CLAUDE_CODE_USE_FOUNDRY": "1",
            "ANTHROPIC_FOUNDRY_BASE_URL": base_url,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": sonnet_model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": haiku_model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": opus_model,
        },
    }

    try:
        # Backup existing settings if they exist
        if SETTINGS_FILE.exists():
            backup_file = SETTINGS_FILE.with_suffix(".json.backup")
            SETTINGS_FILE.rename(backup_file)
            logger.info(f"✓ Backed up existing settings to: {backup_file}")

        # Write new settings
        SETTINGS_FILE.write_text(json.dumps(settings, indent=2) + "\n")
        logger.info(f"✓ Settings file created: {SETTINGS_FILE}")
        logger.debug(f"Settings content:\n{json.dumps(settings, indent=2)}")
        return True
    except Exception as exc:
        logger.error(f"✗ Failed to create settings file: {exc}")
        return False


def generate_token() -> bool:
    """Generate and save the Claude token."""
    logger.info("Generating Claude token...")
    try:
        # Run the token script
        result = subprocess.run(
            [str(TOKEN_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            logger.error(f"✗ Token generation failed: {result.stderr}")
            return False

        token = result.stdout.strip()
        if not token:
            logger.error("✗ Token generation returned empty result")
            return False

        # Save token to file
        TOKEN_FILE.write_text(token + "\n")
        logger.info(f"✓ Token generated and saved to: {TOKEN_FILE}")
        logger.debug(f"Token length: {len(token)} characters")
        logger.debug(f"Token preview: {token[:20]}...{token[-20:]}")
        return True
    except subprocess.TimeoutExpired:
        logger.error("✗ Token generation timed out")
        return False
    except Exception as exc:
        logger.error(f"✗ Failed to generate token: {exc}")
        return False


def test_setup() -> bool:
    """Test the Claude CLI setup."""
    logger.info("Testing Claude CLI setup...")

    # Check if claude command exists
    try:
        result = subprocess.run(
            ["claude", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            logger.info(f"✓ Claude CLI test passed: {result.stdout.strip()}")
            return True
        else:
            logger.warning(f"⚠ Claude CLI test returned code {result.returncode}")
            return False
    except FileNotFoundError:
        logger.warning(
            "⚠ Claude CLI not found. Install it to use this configuration:\n"
            "  https://github.com/anthropics/claude-code"
        )
        return False
    except Exception as exc:
        logger.error(f"✗ Claude CLI test failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------


def run(
    base_url: str = DEFAULT_BASE_URL,
    sonnet_model: str = DEFAULT_SONNET_MODEL,
    haiku_model: str = DEFAULT_HAIKU_MODEL,
    opus_model: str = DEFAULT_OPUS_MODEL,
    skip_token: bool = False,
    debug: bool = False,
) -> bool:
    """
    Execute the Claude CLI setup process.

    Args:
        base_url: Anthropic Foundry base URL
        sonnet_model: Sonnet model name
        haiku_model: Haiku model name
        opus_model: Opus model name
        skip_token: Skip token generation step
        debug: Enable debug logging

    Returns True if setup completed successfully.
    """
    logger.info(
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║              CLAUDE CLI SETUP AUTOMATION                   ║\n"
        "╠══════════════════════════════════════════════════════════════╣\n"
        f"║  Base URL:     {base_url[:44]:<44}║\n"
        f"║  Sonnet Model: {sonnet_model[:44]:<44}║\n"
        "╚══════════════════════════════════════════════════════════════╝"
    )

    # ── Pre-flight checks ──
    logger.info("\n─── Pre-flight Checks ───")
    az_ok = check_az_cli()
    if not az_ok:
        return False

    azure_login_ok = check_azure_login()
    claude_cli_ok = check_claude_cli()

    # ── Step 1: Create directory ──
    logger.info("\n─── Step 1: Create ~/.claude Directory ───")
    if not create_claude_directory():
        return False

    # ── Step 2: Create token script ──
    logger.info("\n─── Step 2: Create Token Script ───")
    if not create_token_script():
        return False

    # ── Step 3: Create settings.json ──
    logger.info("\n─── Step 3: Create Settings File ───")
    if not create_settings_json(base_url, sonnet_model, haiku_model, opus_model):
        return False

    # ── Step 4: Generate token ──
    if not skip_token:
        logger.info("\n─── Step 4: Generate Token ───")
        if not azure_login_ok:
            logger.warning(
                "You may need to login to Azure. The script will prompt you if needed."
            )
        if not generate_token():
            logger.error(
                "Token generation failed. You can generate it manually later with:\n"
                f"  {TOKEN_SCRIPT} | tee {TOKEN_FILE}"
            )
            # Don't fail the setup, token can be generated later
    else:
        logger.info("\n─── Step 4: Generate Token (SKIPPED) ───")

    # ── Step 5: Test setup ──
    logger.info("\n─── Step 5: Test Setup ───")
    test_ok = test_setup()

    # ── Summary ──
    logger.info(
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║                                                            ║\n"
        "║   CLAUDE CLI SETUP COMPLETE                                ║\n"
        "║                                                            ║\n"
        "╠══════════════════════════════════════════════════════════════╣\n"
        f"║  Directory:    {str(CLAUDE_DIR)[:44]:<44}║\n"
        f"║  Token Script: {TOKEN_SCRIPT.name:<44}║\n"
        f"║  Settings:     {SETTINGS_FILE.name:<44}║\n"
        f"║  Token File:   {TOKEN_FILE.name:<44}║\n"
        "╠══════════════════════════════════════════════════════════════╣\n"
        "║  Next Steps:                                               ║\n"
    )

    if not claude_cli_ok:
        logger.info(
            "║  1. Install Claude CLI from:                               ║\n"
            "║     https://github.com/anthropics/claude-code              ║\n"
        )

    if not skip_token and TOKEN_FILE.exists():
        logger.info(
            "║  2. Test your setup:                                       ║\n"
            "║     claude                                                 ║\n"
        )
    else:
        logger.info(
            "║  2. Generate token manually:                               ║\n"
            f"║     {str(TOKEN_SCRIPT)[:58]:<58}║\n"
        )

    logger.info(
        "║                                                            ║\n"
        "╚══════════════════════════════════════════════════════════════╝"
    )

    return True


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Claude CLI Setup Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s\n"
            "  %(prog)s --base-url https://custom.url.com\n"
            "  %(prog)s --skip-token --debug\n"
        ),
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("ANTHROPIC_FOUNDRY_BASE_URL", DEFAULT_BASE_URL),
        help=f"Anthropic Foundry base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--sonnet-model",
        default=os.environ.get("ANTHROPIC_DEFAULT_SONNET_MODEL", DEFAULT_SONNET_MODEL),
        help=f"Sonnet model name (default: {DEFAULT_SONNET_MODEL})",
    )
    parser.add_argument(
        "--haiku-model",
        default=os.environ.get("ANTHROPIC_DEFAULT_HAIKU_MODEL", DEFAULT_HAIKU_MODEL),
        help=f"Haiku model name (default: {DEFAULT_HAIKU_MODEL})",
    )
    parser.add_argument(
        "--opus-model",
        default=os.environ.get("ANTHROPIC_DEFAULT_OPUS_MODEL", DEFAULT_OPUS_MODEL),
        help=f"Opus model name (default: {DEFAULT_OPUS_MODEL})",
    )
    parser.add_argument(
        "--skip-token",
        action="store_true",
        default=False,
        help="Skip token generation (useful for testing setup)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug logging",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(debug=args.debug)

    success = run(
        base_url=args.base_url,
        sonnet_model=args.sonnet_model,
        haiku_model=args.haiku_model,
        opus_model=args.opus_model,
        skip_token=args.skip_token,
        debug=args.debug,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
