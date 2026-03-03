"""AGH CLI configuration loader.

Reads credentials from ~/.agh/credentials.json and environment variables.
Environment variables take precedence over file config.

Config file format (~/.agh/credentials.json):
{
    "api_key": "agh_...",
    "api_url": "https://agh.example.com",
    "org_id": "uuid-string"
}
"""

import json
import os
import stat
from pathlib import Path

CONFIG_DIR = Path.home() / ".agh"
CREDENTIALS_FILE = CONFIG_DIR / "credentials.json"

ENV_API_KEY = "AGH_API_KEY"
ENV_API_URL = "AGH_API_URL"
ENV_ORG_ID = "AGH_ORG_ID"

DEFAULT_API_URL = "http://localhost:8000"


class AghConfig:
    """Resolved AGH configuration."""

    def __init__(self, api_key=None, api_url=None, org_id=None):
        self.api_key = api_key
        self.api_url = api_url or DEFAULT_API_URL
        self.org_id = org_id

    @property
    def is_authenticated(self):
        return self.api_key is not None

    @property
    def headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        if self.org_id:
            h["X-Organization-ID"] = self.org_id
        return h


def load_config() -> AghConfig:
    """Load config from file, then overlay environment variables."""
    file_cfg = _load_file_config()
    return AghConfig(
        api_key=os.environ.get(ENV_API_KEY, file_cfg.get("api_key")),
        api_url=os.environ.get(ENV_API_URL, file_cfg.get("api_url")),
        org_id=os.environ.get(ENV_ORG_ID, file_cfg.get("org_id")),
    )


def save_credentials(api_key=None, api_url=None, org_id=None):
    """Write credentials to ~/.agh/credentials.json with mode 0600."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    existing = _load_file_config()
    if api_key is not None:
        existing["api_key"] = api_key
    if api_url is not None:
        existing["api_url"] = api_url
    if org_id is not None:
        existing["org_id"] = org_id

    CREDENTIALS_FILE.write_text(json.dumps(existing, indent=2) + "\n")
    CREDENTIALS_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600


def _load_file_config() -> dict:
    """Read credentials file, returning empty dict if missing."""
    if not CREDENTIALS_FILE.exists():
        return {}
    try:
        return json.loads(CREDENTIALS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def detect_repo_name() -> str:
    """Attempt to detect the current repository name from git remote or directory."""
    # Try git remote
    try:
        import subprocess

        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            # Handle SSH and HTTPS URLs
            name = url.rstrip("/").rsplit("/", 1)[-1]
            if name.endswith(".git"):
                name = name[:-4]
            return name
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fall back to current directory name
    return Path.cwd().name
