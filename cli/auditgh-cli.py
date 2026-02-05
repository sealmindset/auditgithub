#!/usr/bin/env python3
"""
AuditGitHub CLI - Device Flow Authentication Example

Demonstrates OAuth 2.0 Device Authorization Grant Flow for CLI authentication.
Provides commands for login, user info, API operations, and token management.

Usage:
    ./cli/auditgh-cli.py login              # Authenticate via browser
    ./cli/auditgh-cli.py whoami             # Show current user info
    ./cli/auditgh-cli.py scan <org> <repo>  # Trigger security scan
    ./cli/auditgh-cli.py logout             # Clear saved tokens
"""
import requests
import time
import json
import webbrowser
import sys
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000"
CLIENT_ID = "auditgh-cli"
CLIENT_NAME = "AuditGitHub CLI"
TOKEN_FILE = Path.home() / ".auditgh" / "tokens.json"
CONFIG_FILE = Path.home() / ".auditgh" / "config.json"


class AuditGHCLI:
    """AuditGitHub CLI client with device flow authentication."""

    def __init__(self, api_url: str = API_URL):
        self.api_url = api_url.rstrip('/')
        self.session = requests.Session()
        self.tokens = self._load_tokens()
        self.config = self._load_config()

    def _load_tokens(self) -> Dict:
        """Load tokens from file if exists."""
        if TOKEN_FILE.exists():
            try:
                return json.loads(TOKEN_FILE.read_text())
            except json.JSONDecodeError:
                print("⚠️  Warning: Invalid token file, ignoring")
                return {}
        return {}

    def _save_tokens(self, tokens: Dict):
        """Save tokens to file with secure permissions."""
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(json.dumps(tokens, indent=2))
        TOKEN_FILE.chmod(0o600)  # User read/write only

    def _load_config(self) -> Dict:
        """Load config from file if exists."""
        if CONFIG_FILE.exists():
            try:
                return json.loads(CONFIG_FILE.read_text())
            except json.JSONDecodeError:
                return {}
        return {}

    def _save_config(self, config: Dict):
        """Save config to file."""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(config, indent=2))
        CONFIG_FILE.chmod(0o600)

    def login(self, open_browser: bool = True, no_browser: bool = False):
        """
        Authenticate using OAuth 2.0 Device Flow.

        Steps:
        1. Request device code from API
        2. Display user code and verification URL
        3. Open browser (unless --no-browser)
        4. Poll for token until approved
        """
        print("🔐 AuditGitHub CLI Login\n")

        # Step 1: Request device code
        try:
            response = self.session.post(
                f"{self.api_url}/auth/device/code",
                json={
                    "client_id": CLIENT_ID,
                    "client_name": CLIENT_NAME,
                    "scopes": ["repo:read", "scan:trigger", "findings:read"]
                },
                timeout=10
            )

            if response.status_code != 200:
                print(f"❌ Failed to initiate device flow: {response.text}")
                return False

            data = response.json()
            device_code = data["device_code"]
            user_code = data["user_code"]
            verification_uri_complete = data["verification_uri_complete"]
            verification_uri = data["verification_uri"]
            interval = data["interval"]

        except requests.exceptions.RequestException as e:
            print(f"❌ Connection error: {e}")
            print(f"   Make sure API is running at {self.api_url}")
            return False

        # Step 2: Display instructions
        print(f"To sign in, use a web browser to open:")
        print(f"  {verification_uri_complete}\n")
        print(f"And enter the code: {user_code}")
        print(f"\nWaiting for authentication", end="", flush=True)

        # Open browser if enabled
        if open_browser and not no_browser:
            try:
                webbrowser.open(verification_uri_complete)
            except Exception as e:
                print(f"\n⚠️  Could not open browser automatically: {e}")

        # Step 3: Poll for token
        max_poll_time = 600  # 10 minutes
        start_time = time.time()

        while time.time() - start_time < max_poll_time:
            time.sleep(interval)
            print(".", end="", flush=True)

            try:
                token_response = self.session.post(
                    f"{self.api_url}/auth/device/token",
                    json={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": device_code,
                        "client_id": CLIENT_ID
                    },
                    timeout=10
                )

                if token_response.status_code == 200:
                    # Success!
                    tokens = token_response.json()
                    self._save_tokens(tokens)
                    self.tokens = tokens
                    print("\n\n✅ Login successful!")
                    print(f"   Token saved to {TOKEN_FILE}")
                    return True

                # Handle error responses
                error_data = token_response.json() if token_response.headers.get('content-type', '').startswith('application/json') else {}
                error = error_data.get("detail", "unknown")

                if error == "authorization_pending":
                    # Still waiting for user approval
                    continue
                elif error == "slow_down":
                    # Server requested slower polling
                    interval += 5
                    continue
                elif error == "expired_token":
                    print("\n\n❌ Login timeout. Please try again.")
                    return False
                elif error == "access_denied":
                    print("\n\n❌ Authorization denied by user.")
                    return False
                else:
                    print(f"\n\n❌ Error: {error}")
                    return False

            except requests.exceptions.RequestException as e:
                print(f"\n❌ Connection error during polling: {e}")
                return False

        print("\n\n❌ Login timeout. Please try again.")
        return False

    def logout(self):
        """Clear saved tokens and config."""
        if TOKEN_FILE.exists():
            TOKEN_FILE.unlink()
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
        self.tokens = {}
        self.config = {}
        print("✅ Logged out successfully")
        print(f"   Tokens cleared from {TOKEN_FILE}")

    def whoami(self):
        """Show current user information."""
        if not self.tokens:
            print("❌ Not authenticated. Run: auditgh-cli.py login")
            return

        try:
            response = self._api_request("GET", "/auth/me")

            if response.status_code == 200:
                user = response.json()
                print(f"Logged in as: {user.get('email', 'Unknown')}")
                print(f"Name: {user.get('name', 'N/A')}")
                print(f"Provider: {user.get('provider', 'N/A')}")
                print(f"Subject: {user.get('sub', 'N/A')}")
            else:
                print(f"❌ Failed to get user info: {response.text}")
                print("   Token may be expired. Run: auditgh-cli.py login")

        except Exception as e:
            print(f"❌ Error: {e}")

    def list_repos(self, org: Optional[str] = None):
        """List repositories."""
        if not self.tokens:
            print("❌ Not authenticated. Run: auditgh-cli.py login")
            return

        try:
            url = "/api/repositories"
            if org:
                url += f"?org={org}"

            response = self._api_request("GET", url)

            if response.status_code == 200:
                repos = response.json().get("data", [])
                if not repos:
                    print("No repositories found")
                    return

                print(f"\nFound {len(repos)} repositories:\n")
                for repo in repos:
                    print(f"  • {repo['name']}")
                    if repo.get('description'):
                        print(f"    {repo['description']}")
                    print()
            else:
                print(f"❌ Failed to list repositories: {response.text}")

        except Exception as e:
            print(f"❌ Error: {e}")

    def scan_repository(self, org: str, repo: str):
        """Trigger security scan for a repository."""
        if not self.tokens:
            print("❌ Not authenticated. Run: auditgh-cli.py login")
            return

        print(f"🔍 Triggering scan for {org}/{repo}...")

        try:
            # Get repository ID
            repos_response = self._api_request(
                "GET",
                f"/api/repositories?name={repo}&org={org}"
            )

            if repos_response.status_code != 200:
                print(f"❌ Failed to find repository: {repos_response.text}")
                return

            repos = repos_response.json().get("data", [])
            if not repos:
                print(f"❌ Repository {org}/{repo} not found")
                return

            repo_id = repos[0]["id"]

            # Trigger scan
            scan_response = self._api_request(
                "POST",
                "/api/scans",
                json={"repository_id": repo_id, "force_rescan": True}
            )

            if scan_response.status_code == 202:
                scan_data = scan_response.json()
                scan_id = scan_data.get("scan_run_id")
                print(f"✅ Scan initiated: {scan_id}")
                print("\nPolling for results (press Ctrl+C to stop)...")

                # Poll for completion
                try:
                    while True:
                        time.sleep(30)
                        status_response = self._api_request(
                            "GET",
                            f"/api/scans/{scan_id}/status"
                        )

                        if status_response.status_code == 200:
                            status_data = status_response.json()
                            status = status_data.get("status")

                            if status == "completed":
                                print(f"\n✅ Scan complete!")
                                print(f"   Security Score: {status_data.get('security_score', 'N/A')}/100")
                                print(f"   Findings: {status_data.get('findings_count', 'N/A')}")
                                break
                            elif status == "failed":
                                print(f"\n❌ Scan failed: {status_data.get('error')}")
                                break
                            else:
                                print(".", end="", flush=True)
                        else:
                            print(f"\n⚠️  Failed to get status: {status_response.text}")
                            break

                except KeyboardInterrupt:
                    print("\n\nScan is still running in background")
                    print(f"Check status at: {self.api_url}/projects/{repo}")

            else:
                print(f"❌ Failed to trigger scan: {scan_response.text}")

        except Exception as e:
            print(f"❌ Error: {e}")

    def _api_request(self, method: str, endpoint: str, **kwargs):
        """
        Make authenticated API request with automatic token refresh.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        if not self.tokens:
            raise Exception("Not authenticated")

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.tokens['access_token']}"

        response = self.session.request(
            method,
            f"{self.api_url}{endpoint}",
            headers=headers,
            **kwargs
        )

        # Try to refresh if unauthorized
        if response.status_code == 401 and self.tokens.get("refresh_token"):
            print("\n🔄 Token expired, refreshing...", end="", flush=True)

            refresh_response = self.session.post(
                f"{self.api_url}/auth/refresh",
                json={"refresh_token": self.tokens["refresh_token"]},
                timeout=10
            )

            if refresh_response.status_code == 200:
                self.tokens = refresh_response.json()
                self._save_tokens(self.tokens)
                print(" done!")

                # Retry original request with new token
                headers["Authorization"] = f"Bearer {self.tokens['access_token']}"
                response = self.session.request(
                    method,
                    f"{self.api_url}{endpoint}",
                    headers=headers,
                    **kwargs
                )
            else:
                print(" failed!")
                print("\n❌ Token refresh failed. Please login again.")

        return response


def print_usage():
    """Print CLI usage information."""
    print("""
AuditGitHub CLI - Security Scanning & Analysis Tool

Usage:
    auditgh-cli.py <command> [options]

Commands:
    login               Authenticate via browser (OAuth 2.0 Device Flow)
    login --no-browser  Authenticate without opening browser
    logout              Clear saved credentials
    whoami              Show current user information
    repos [org]         List repositories (optionally filter by org)
    scan <org> <repo>   Trigger security scan for repository

Examples:
    auditgh-cli.py login
    auditgh-cli.py whoami
    auditgh-cli.py repos sleepnumberinc
    auditgh-cli.py scan sleepnumberinc my-api-service
    auditgh-cli.py logout

Config:
    Tokens: ~/.auditgh/tokens.json
    API URL: {API_URL}
    """)


def main():
    """Main CLI entry point."""
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()
    cli = AuditGHCLI()

    if command == "login":
        no_browser = "--no-browser" in sys.argv
        cli.login(open_browser=True, no_browser=no_browser)

    elif command == "logout":
        cli.logout()

    elif command == "whoami":
        cli.whoami()

    elif command == "repos":
        org = sys.argv[2] if len(sys.argv) > 2 else None
        cli.list_repos(org)

    elif command == "scan":
        if len(sys.argv) < 4:
            print("Usage: auditgh-cli.py scan <org> <repo>")
            sys.exit(1)
        cli.scan_repository(sys.argv[2], sys.argv[3])

    elif command in ["help", "--help", "-h"]:
        print_usage()

    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
