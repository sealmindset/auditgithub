#!/usr/bin/env python3
"""
Azure Device-Code Login Automation with Playwright

Orchestrates the full Azure CLI device-code login flow:
1. Spawns `az login --use-device-code` as a subprocess
2. Extracts the device code from CLI output
3. Opens a Playwright-driven browser to enter the code
4. Selects the target account
5. Pauses for user MFA input
6. Sets the target Azure subscription
7. Verifies the login

Usage:
    python scripts/azure-login/az_login.py
    python scripts/azure-login/az_login.py --email user@company.com --subscription "my-sub"
    python scripts/azure-login/az_login.py --debug
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEVICE_CODE_URL = "https://login.microsoft.com/device"
DEVICE_CODE_REGEX = re.compile(
    r"enter the code\s+([A-Z0-9]+)\s+to authenticate", re.IGNORECASE
)
DEFAULT_EMAIL = "rob.vance@sleepnumber.com"
DEFAULT_SUBSCRIPTION = "sn-openai-dev-01"
DEFAULT_TIMEOUT = 300  # 5 minutes for MFA
DEFAULT_SLOW_MO = 500
DEVICE_CODE_WAIT = 30  # seconds to wait for device code from az CLI

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Microsoft login page selectors (data-driven for easy maintenance)
SELECTORS = {
    "code_input": 'input[name="otc"]',
    "next_button": 'input[type="submit"][value="Next"], button[type="submit"]',
    "account_tile": '[data-test-id="{email}"], [data-bind*="currentUsername"]',
    "account_by_email": 'text="{email}"',
    "continue_button": 'input[type="submit"], button[type="submit"]',
    "auth_complete_text": "You have signed in",
    "error_text": ".alert-error, #error_description",
    "mfa_page_indicator": (
        "#idDiv_SAOTCAS_Description, "  # Authenticator app
        "#idDiv_SAOTCC_Description, "   # SMS code
        ".table.mfa-container, "        # MFA container
        "#idRichContext_DisplaySign, "   # Number matching
        "#idDiv_SAASDS_Description"     # FIDO key
    ),
    "stay_signed_in_no": 'input[type="submit"][value="No"], #idBtn_Back',
    "stay_signed_in_yes": 'input[type="submit"][value="Yes"], #idSIButton9',
    "device_code_page_title": "Enter code",
}

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("az_login")


def setup_logging(debug: bool = False, log_file: str | None = None) -> None:
    level = logging.DEBUG if debug else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, handlers=handlers)


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def check_az_cli() -> bool:
    """Verify Azure CLI is installed and on PATH."""
    logger.info("Checking for Azure CLI (az)...")
    try:
        result = subprocess.run(
            ["az", "--version"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            version_line = result.stdout.strip().split("\n")[0]
            logger.info(f"Found: {version_line}")
            return True
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass

    logger.error(
        "Azure CLI (az) not found. Install it:\n"
        "  macOS:   brew install azure-cli\n"
        "  Linux:   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash\n"
        "  Windows: winget install Microsoft.AzureCLI"
    )
    return False


def check_playwright() -> bool:
    """Verify Playwright is installed; auto-install browsers if missing."""
    logger.info("Checking Playwright installation...")
    try:
        import playwright  # noqa: F401
        logger.info("Playwright package found")
    except ImportError:
        logger.error(
            "Playwright not installed. Run:\n"
            "  pip install playwright\n"
            "  playwright install chromium"
        )
        return False

    # Check if browsers are installed by trying to get the executable path
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        logger.info("Playwright Chromium browser is ready")
        return True
    except Exception as exc:
        logger.warning(f"Browser not ready: {exc}")
        logger.info("Attempting to install Chromium browser...")
        try:
            subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                check=True, capture_output=True, text=True
            )
            logger.info("Chromium browser installed successfully")
            return True
        except subprocess.CalledProcessError as install_err:
            logger.error(f"Failed to install Chromium: {install_err.stderr}")
            return False


# ---------------------------------------------------------------------------
# Device code extraction (subprocess + threading)
# ---------------------------------------------------------------------------

class DeviceCodeCapture:
    """Manages the `az login --use-device-code` subprocess and captures the device code."""

    def __init__(self):
        self.device_code: str | None = None
        self.process: subprocess.Popen | None = None
        self.output_lines: list[str] = []
        self.auth_complete = threading.Event()
        self.code_ready = threading.Event()
        self._reader_thread: threading.Thread | None = None

    def start(self) -> None:
        """Spawn `az login --use-device-code` and begin reading output."""
        logger.info("Launching: az login --use-device-code")
        self.process = subprocess.Popen(
            ["az", "login", "--use-device-code"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()

    def _read_output(self) -> None:
        """Background thread: read subprocess output line by line."""
        if not self.process or not self.process.stdout:
            return
        for line in self.process.stdout:
            line = line.strip()
            if not line:
                continue
            self.output_lines.append(line)
            logger.debug(f"[az CLI] {line}")

            # Try to extract device code
            match = DEVICE_CODE_REGEX.search(line)
            if match:
                self.device_code = match.group(1)
                logger.info(f"Device code captured: {self.device_code}")
                self.code_ready.set()

        # Process finished
        self.auth_complete.set()

    def wait_for_code(self, timeout: int = DEVICE_CODE_WAIT) -> str | None:
        """Block until the device code is captured or timeout."""
        logger.info(f"Waiting up to {timeout}s for device code from az CLI...")
        self.code_ready.wait(timeout=timeout)
        if not self.device_code:
            logger.error(
                "Timed out waiting for device code. az CLI output:\n"
                + "\n".join(self.output_lines)
            )
        return self.device_code

    def wait_for_auth(self, timeout: int = DEFAULT_TIMEOUT) -> bool:
        """Block until az login completes."""
        logger.info(f"Waiting up to {timeout}s for az login to complete...")
        self.auth_complete.wait(timeout=timeout)
        if self.process:
            retcode = self.process.poll()
            if retcode == 0:
                logger.info("az login completed successfully")
                return True
            logger.warning(f"az login exited with code {retcode}")
        return False

    def kill(self) -> None:
        """Terminate the subprocess if still running."""
        if self.process and self.process.poll() is None:
            logger.warning("Terminating az login subprocess...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()


# ---------------------------------------------------------------------------
# Playwright browser automation
# ---------------------------------------------------------------------------

def automate_device_login(
    device_code: str,
    email: str,
    headless: bool = False,
    slow_mo: int = DEFAULT_SLOW_MO,
    mfa_timeout: int = DEFAULT_TIMEOUT,
) -> bool:
    """
    Drive the browser through the device-code login flow.

    Returns True if authentication completed successfully.
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

    logger.info(f"Launching browser (headless={headless}, slow_mo={slow_mo}ms)")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=headless,
            slow_mo=slow_mo,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
            ],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        page = context.new_page()

        try:
            # ── Step 1: Navigate to device login page ──
            logger.info(f"Navigating to {DEVICE_CODE_URL}")
            page.goto(DEVICE_CODE_URL, wait_until="domcontentloaded", timeout=30000)
            logger.info(f"Page title: {page.title()}")

            # ── Step 2: Enter the device code ──
            logger.info(f"Entering device code: {device_code}")
            code_input = page.wait_for_selector(
                SELECTORS["code_input"], state="visible", timeout=15000
            )
            if not code_input:
                logger.error("Could not find code input field")
                _save_screenshot(page, "error_no_code_input")
                return False

            code_input.fill(device_code)
            logger.info("Device code entered")

            # ── Step 3: Click Next ──
            logger.info("Clicking Next button")
            next_btn = page.wait_for_selector(
                SELECTORS["next_button"], state="visible", timeout=10000
            )
            if next_btn:
                next_btn.click()
            else:
                logger.warning("Next button not found, pressing Enter instead")
                code_input.press("Enter")

            # Small wait for page transition
            page.wait_for_load_state("domcontentloaded", timeout=15000)
            time.sleep(2)
            logger.info(f"After code entry — page title: {page.title()}")

            # ── Step 4: Account selection ──
            success = _select_account(page, email)
            if not success:
                logger.error("Account selection failed")
                _save_screenshot(page, "error_account_selection")
                return False

            # Small wait for page transition
            page.wait_for_load_state("domcontentloaded", timeout=15000)
            time.sleep(2)

            # ── Step 5: Handle MFA ──
            logger.info("Checking if MFA is required...")
            mfa_result = _handle_mfa(page, mfa_timeout)
            if not mfa_result:
                logger.error("MFA flow did not complete successfully")
                _save_screenshot(page, "error_mfa")
                return False

            # ── Step 6: Handle "Stay signed in?" prompt ──
            _handle_stay_signed_in(page)

            # ── Step 7: Verify authentication complete ──
            auth_ok = _verify_auth_complete(page)
            if auth_ok:
                logger.info("Browser authentication flow completed successfully")
            else:
                logger.warning("Could not confirm auth completion in browser, but az CLI may still succeed")

            return True

        except PlaywrightTimeout as exc:
            logger.error(f"Playwright timeout: {exc}")
            _save_screenshot(page, "error_timeout")
            return False
        except Exception as exc:
            logger.error(f"Unexpected error during browser automation: {exc}", exc_info=True)
            _save_screenshot(page, "error_unexpected")
            return False
        finally:
            logger.info("Closing browser")
            context.close()
            browser.close()


def _select_account(page, email: str) -> bool:
    """Select the target account from the account picker."""
    from playwright.sync_api import TimeoutError as PlaywrightTimeout

    logger.info(f"Looking for account: {email}")

    # Strategy 1: Click on an element containing the email text
    try:
        email_element = page.wait_for_selector(
            f'text="{email}"', state="visible", timeout=10000
        )
        if email_element:
            logger.info(f"Found account tile for {email}, clicking...")
            email_element.click()
            return True
    except PlaywrightTimeout:
        logger.debug(f"No element with text '{email}' found via Strategy 1")

    # Strategy 2: Look for data-test-id attribute
    try:
        tile = page.wait_for_selector(
            f'[data-test-id="{email}"]', state="visible", timeout=5000
        )
        if tile:
            logger.info(f"Found account tile by data-test-id, clicking...")
            tile.click()
            return True
    except PlaywrightTimeout:
        logger.debug("No element with data-test-id found via Strategy 2")

    # Strategy 3: Look for any account list item containing the email
    try:
        tiles = page.query_selector_all(".table[role='listbox'] .table-row, .row.tile")
        for tile in tiles:
            text = tile.inner_text()
            if email.lower() in text.lower():
                logger.info(f"Found account in tile list: {text.strip()[:60]}...")
                tile.click()
                return True
    except Exception:
        logger.debug("Strategy 3 failed")

    # Strategy 4: Use "Use another account" if available, then enter email
    try:
        other_account = page.query_selector('text="Use another account"')
        if other_account:
            logger.info("Clicking 'Use another account'")
            other_account.click()
            page.wait_for_load_state("domcontentloaded", timeout=10000)
            time.sleep(1)

            email_input = page.wait_for_selector(
                'input[type="email"], input[name="loginfmt"]',
                state="visible", timeout=10000
            )
            if email_input:
                logger.info(f"Typing email: {email}")
                email_input.fill(email)
                next_btn = page.wait_for_selector(
                    SELECTORS["next_button"], state="visible", timeout=5000
                )
                if next_btn:
                    next_btn.click()
                else:
                    email_input.press("Enter")
                return True
    except PlaywrightTimeout:
        logger.debug("Strategy 4 failed — no 'Use another account' option")

    # Strategy 5: If we're already on a password page or MFA page, account was auto-selected
    try:
        password_input = page.query_selector('input[type="password"]')
        mfa_indicator = page.query_selector(SELECTORS["mfa_page_indicator"])
        if password_input or mfa_indicator:
            logger.info("Account appears to be auto-selected (password/MFA page detected)")
            return True
    except Exception:
        pass

    # Log what we see for debugging
    logger.warning("Could not find the target account. Current page content:")
    try:
        visible_text = page.inner_text("body")
        logger.warning(f"Page text (first 500 chars): {visible_text[:500]}")
    except Exception:
        pass
    _save_screenshot(page, "debug_account_picker")

    return False


def _handle_mfa(page, timeout: int) -> bool:
    """
    Handle the MFA step. This requires manual user interaction.
    The script polls the page waiting for navigation past the MFA screen.
    """
    from playwright.sync_api import TimeoutError as PlaywrightTimeout

    # Check if MFA is actually required
    time.sleep(2)

    # Check for various MFA indicators
    mfa_detected = False
    try:
        mfa_element = page.query_selector(SELECTORS["mfa_page_indicator"])
        if mfa_element:
            mfa_detected = True
    except Exception:
        pass

    # Also check for password page (some orgs require password + MFA)
    password_input = page.query_selector('input[type="password"]')
    if password_input:
        logger.info(
            "\n"
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║  PASSWORD REQUIRED — Please enter your password in the     ║\n"
            "║  browser window.                                           ║\n"
            "╚══════════════════════════════════════════════════════════════╝"
        )
        # Wait for navigation away from password page
        try:
            page.wait_for_selector(
                'input[type="password"]', state="detached", timeout=timeout * 1000
            )
        except PlaywrightTimeout:
            logger.error("Password entry timed out")
            return False
        time.sleep(2)
        # Re-check for MFA after password
        try:
            mfa_element = page.query_selector(SELECTORS["mfa_page_indicator"])
            if mfa_element:
                mfa_detected = True
        except Exception:
            pass

    if not mfa_detected:
        # Check if we already passed auth
        try:
            body_text = page.inner_text("body")
            if SELECTORS["auth_complete_text"].lower() in body_text.lower():
                logger.info("Authentication already complete — no MFA needed")
                return True
        except Exception:
            pass

        # Check for number matching display
        number_display = page.query_selector("#idRichContext_DisplaySign")
        if number_display:
            mfa_detected = True

    if mfa_detected:
        # Extract the MFA number if it's number-matching
        mfa_number = None
        try:
            number_el = page.query_selector("#idRichContext_DisplaySign")
            if number_el:
                mfa_number = number_el.inner_text().strip()
        except Exception:
            pass

        mfa_msg = (
            "\n"
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║                                                            ║\n"
            "║   MFA REQUIRED — Complete verification on your device      ║\n"
        )
        if mfa_number:
            mfa_msg += (
                f"║                                                            ║\n"
                f"║   >>> Enter number:  {mfa_number:<38}║\n"
            )
        mfa_msg += (
            "║                                                            ║\n"
            f"║   Timeout: {timeout} seconds                                  ║\n"
            "║                                                            ║\n"
            "╚══════════════════════════════════════════════════════════════╝"
        )
        logger.info(mfa_msg)

        # Poll for navigation away from MFA page
        start_time = time.time()
        poll_interval = 2  # seconds
        while (time.time() - start_time) < timeout:
            elapsed = int(time.time() - start_time)
            try:
                body_text = page.inner_text("body")
                # Check if we've moved past MFA
                if SELECTORS["auth_complete_text"].lower() in body_text.lower():
                    logger.info("MFA completed — authentication successful")
                    return True
                # Check for "Stay signed in" prompt (means auth succeeded)
                stay_signed = page.query_selector(SELECTORS["stay_signed_in_no"])
                if stay_signed and stay_signed.is_visible():
                    logger.info("MFA completed — 'Stay signed in' prompt detected")
                    return True
                # Check if MFA element is gone
                mfa_still = page.query_selector(SELECTORS["mfa_page_indicator"])
                if not mfa_still:
                    logger.info("MFA indicator gone — authentication likely completed")
                    return True
            except Exception:
                pass

            if elapsed % 30 == 0 and elapsed > 0:
                logger.info(f"Still waiting for MFA... ({elapsed}s / {timeout}s)")
            time.sleep(poll_interval)

        logger.error(f"MFA timeout after {timeout}s")
        return False

    # No MFA detected and no auth complete — check if page transitioned
    logger.info("No MFA detected, checking authentication status...")
    time.sleep(3)
    try:
        body_text = page.inner_text("body")
        if SELECTORS["auth_complete_text"].lower() in body_text.lower():
            return True
        # Check for stay signed in prompt
        stay_signed = page.query_selector(SELECTORS["stay_signed_in_no"])
        if stay_signed and stay_signed.is_visible():
            return True
    except Exception:
        pass

    # Give it a bit more time
    logger.info("Waiting briefly for page transition...")
    time.sleep(5)
    return True  # Assume success; the az CLI will confirm


def _handle_stay_signed_in(page) -> None:
    """Handle the 'Stay signed in?' prompt by clicking No."""
    from playwright.sync_api import TimeoutError as PlaywrightTimeout

    try:
        time.sleep(2)
        no_btn = page.query_selector(SELECTORS["stay_signed_in_no"])
        if no_btn and no_btn.is_visible():
            logger.info("'Stay signed in?' prompt — clicking No")
            no_btn.click()
            time.sleep(2)
            return

        yes_btn = page.query_selector(SELECTORS["stay_signed_in_yes"])
        if yes_btn and yes_btn.is_visible():
            logger.info("'Stay signed in?' prompt — clicking Yes")
            yes_btn.click()
            time.sleep(2)
            return

        logger.debug("No 'Stay signed in' prompt detected")
    except Exception as exc:
        logger.debug(f"Stay signed in handler: {exc}")


def _verify_auth_complete(page) -> bool:
    """Check if the browser shows authentication success."""
    try:
        time.sleep(2)
        body_text = page.inner_text("body")
        success_indicators = [
            "you have signed in",
            "you're signed in",
            "you are signed in",
            "authentication complete",
            "you can close this window",
            "you have successfully",
        ]
        for indicator in success_indicators:
            if indicator in body_text.lower():
                logger.info(f"Auth complete indicator found: '{indicator}'")
                return True
        logger.debug(f"Page text (first 300 chars): {body_text[:300]}")
    except Exception as exc:
        logger.debug(f"Auth verification error: {exc}")
    return False


def _save_screenshot(page, name: str) -> None:
    """Save a debug screenshot."""
    try:
        screenshots_dir = Path(__file__).parent / "screenshots"
        screenshots_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = screenshots_dir / f"{name}_{timestamp}.png"
        page.screenshot(path=str(filepath))
        logger.info(f"Screenshot saved: {filepath}")
    except Exception as exc:
        logger.debug(f"Could not save screenshot: {exc}")


# ---------------------------------------------------------------------------
# Subscription management
# ---------------------------------------------------------------------------

def set_subscription(subscription_name: str) -> bool:
    """Set the active Azure subscription."""
    logger.info(f"Setting subscription: {subscription_name}")
    try:
        result = subprocess.run(
            ["az", "account", "set", "--subscription", subscription_name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            logger.info(f"Subscription set to: {subscription_name}")
            return True

        logger.error(f"Failed to set subscription: {result.stderr.strip()}")
        _list_subscriptions()
        return False
    except subprocess.TimeoutExpired:
        logger.error("Timed out setting subscription")
        return False


def verify_login() -> bool:
    """Verify the current Azure login and display account info."""
    logger.info("Verifying Azure login...")
    try:
        result = subprocess.run(
            ["az", "account", "show", "--output", "json"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            account = json.loads(result.stdout)
            logger.info(
                "\n"
                "╔══════════════════════════════════════════════════════════════╗\n"
                "║  AZURE LOGIN VERIFIED                                      ║\n"
                "╠══════════════════════════════════════════════════════════════╣\n"
                f"║  User:         {account.get('user', {}).get('name', 'N/A'):<44}║\n"
                f"║  Subscription: {account.get('name', 'N/A'):<44}║\n"
                f"║  Tenant:       {account.get('tenantId', 'N/A'):<44}║\n"
                f"║  State:        {account.get('state', 'N/A'):<44}║\n"
                "╚══════════════════════════════════════════════════════════════╝"
            )
            return True

        logger.error(f"Login verification failed: {result.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        logger.error("Timed out verifying login")
        return False
    except json.JSONDecodeError:
        logger.error("Could not parse account info")
        return False


def _list_subscriptions() -> None:
    """List available subscriptions for troubleshooting."""
    logger.info("Available subscriptions:")
    try:
        result = subprocess.run(
            ["az", "account", "list", "--output", "table"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            logger.info(f"\n{result.stdout}")
    except Exception:
        logger.warning("Could not list subscriptions")


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run(
    email: str = DEFAULT_EMAIL,
    subscription: str = DEFAULT_SUBSCRIPTION,
    headless: bool = False,
    slow_mo: int = DEFAULT_SLOW_MO,
    mfa_timeout: int = DEFAULT_TIMEOUT,
    debug: bool = False,
) -> bool:
    """
    Execute the full Azure device-code login flow.

    Returns True if all steps completed successfully.
    """
    start_time = time.time()
    logger.info(
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║          AZURE DEVICE-CODE LOGIN AUTOMATION                 ║\n"
        "╠══════════════════════════════════════════════════════════════╣\n"
        f"║  Email:        {email:<44}║\n"
        f"║  Subscription: {subscription:<44}║\n"
        f"║  MFA Timeout:  {mfa_timeout}s{' ' * (42 - len(str(mfa_timeout)))}║\n"
        "╚══════════════════════════════════════════════════════════════╝"
    )

    # ── Pre-flight ──
    logger.info("─── Pre-flight Checks ───")
    if not check_az_cli():
        return False
    if not check_playwright():
        return False

    # ── Step 1: Launch az login ──
    logger.info("─── Step 1: Launch az login --use-device-code ───")
    capture = DeviceCodeCapture()
    capture.start()

    # ── Step 2: Get device code ──
    logger.info("─── Step 2: Extract Device Code ───")
    device_code = capture.wait_for_code()
    if not device_code:
        capture.kill()
        return False

    # ── Step 3-5: Browser automation ──
    logger.info("─── Step 3: Browser Automation ───")
    browser_ok = automate_device_login(
        device_code=device_code,
        email=email,
        headless=headless,
        slow_mo=slow_mo,
        mfa_timeout=mfa_timeout,
    )

    if not browser_ok:
        logger.error("Browser automation failed")
        capture.kill()
        return False

    # ── Step 6: Wait for az login to complete ──
    logger.info("─── Step 4: Waiting for az CLI to Confirm Auth ───")
    auth_ok = capture.wait_for_auth(timeout=30)
    if not auth_ok:
        logger.warning("az login did not confirm completion, checking manually...")
        # It might have already completed; try verify
        if not verify_login():
            capture.kill()
            return False

    # ── Step 7: Set subscription ──
    logger.info("─── Step 5: Set Azure Subscription ───")
    if not set_subscription(subscription):
        return False

    # ── Step 8: Verify ──
    logger.info("─── Step 6: Final Verification ───")
    if not verify_login():
        return False

    elapsed = int(time.time() - start_time)
    logger.info(
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║                                                            ║\n"
        "║   AZURE LOGIN COMPLETE                                     ║\n"
        f"║   Total time: {elapsed}s{' ' * (44 - len(str(elapsed)))}║\n"
        "║                                                            ║\n"
        "╚══════════════════════════════════════════════════════════════╝"
    )
    return True


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Azure Device-Code Login Automation with Playwright",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s\n"
            "  %(prog)s --email user@company.com --subscription my-sub\n"
            "  %(prog)s --debug --timeout 600\n"
        ),
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("AZURE_LOGIN_EMAIL", DEFAULT_EMAIL),
        help=f"Azure account email (env: AZURE_LOGIN_EMAIL, default: {DEFAULT_EMAIL})",
    )
    parser.add_argument(
        "--subscription",
        default=os.environ.get("AZURE_SUBSCRIPTION", DEFAULT_SUBSCRIPTION),
        help=f"Azure subscription name (env: AZURE_SUBSCRIPTION, default: {DEFAULT_SUBSCRIPTION})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("AZURE_MFA_TIMEOUT", DEFAULT_TIMEOUT)),
        help=f"MFA timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--slow-mo",
        type=int,
        default=int(os.environ.get("AZURE_SLOW_MO", DEFAULT_SLOW_MO)),
        help=f"Browser action delay in ms (default: {DEFAULT_SLOW_MO})",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Run browser headless (NOT recommended — MFA requires visibility)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug logging",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Write logs to file in addition to stdout",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(debug=args.debug, log_file=args.log_file)

    success = run(
        email=args.email,
        subscription=args.subscription,
        headless=args.headless,
        slow_mo=args.slow_mo,
        mfa_timeout=args.timeout,
        debug=args.debug,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
