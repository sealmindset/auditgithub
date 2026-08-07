"""
Fetch-and-cache layer for threat-intel sources.

Mirrors the pattern already used for .cache/kev.json and .cache/epss.json in
scripts/scanning/scan_repos.py: attempt a live fetch, write the result to disk on
success, and fall back to the cached copy on any failure.

Cached-with-manual-refresh is deliberate. Reports must be reproducible, and a hunt
should not acquire a mid-analysis dependency on vendor site availability or on TLS
interception behaving itself.
"""

import json
import logging
import os
import time
from typing import Any, Callable, Dict, Optional

import requests

logger = logging.getLogger(__name__)

# Vendor advisory pages change during a live incident; registry data is definitive
# but also mutates as versions are unpublished. Neither is safe to cache forever.
DEFAULT_TTL_SECONDS = 6 * 60 * 60  # 6 hours

_DEFAULT_TIMEOUT = 20

# Honor the platform-wide TLS setting. Corporate TLS interception (Zscaler) means
# SSL_VERIFY may legitimately point at a custom CA bundle rather than being disabled.
_SSL_VERIFY_RAW = os.environ.get("SSL_VERIFY", "true").strip()


def _ssl_verify():
    """Return a value suitable for requests' verify= parameter."""
    lowered = _SSL_VERIFY_RAW.lower()
    if lowered in ("0", "false", "no"):
        return False
    if lowered in ("1", "true", "yes", ""):
        return True
    # Treat anything else as a path to a CA bundle.
    return _SSL_VERIFY_RAW


def cache_dir() -> str:
    """
    Resolve the on-disk cache directory, creating it if absent.

    Honors THREAT_INTEL_CACHE_DIR, then falls back to <repo-root>/.cache so the
    existing kev.json / epss.json live alongside.
    """
    override = os.environ.get("THREAT_INTEL_CACHE_DIR")
    if override:
        path = override
    else:
        # src/threat_intel/cache.py -> repo root
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        path = os.path.join(repo_root, ".cache")
    os.makedirs(path, exist_ok=True)
    return path


def _cache_path(key: str) -> str:
    safe = key.replace("/", "_").replace("@", "at_").replace(":", "_")
    return os.path.join(cache_dir(), f"{safe}.json")


def cache_age_seconds(key: str) -> Optional[float]:
    """Age of a cache entry, or None if it does not exist."""
    path = _cache_path(key)
    if not os.path.exists(path):
        return None
    return time.time() - os.path.getmtime(path)


def read_cache(key: str) -> Optional[Any]:
    path = _cache_path(key)
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except Exception:
        return None


def write_cache(key: str, payload: Any) -> None:
    path = _cache_path(key)
    try:
        # Write to a temp file then rename, so an interrupted write cannot leave a
        # truncated cache entry behind. (A truncated mid-write state file is exactly
        # what made .scan_resume_state.pkl unparseable.)
        tmp = f"{path}.tmp"
        with open(tmp, "w") as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)
    except Exception as exc:
        logger.warning(f"Failed to write threat-intel cache {key}: {exc}")


def cached_fetch(
    key: str,
    url: str,
    *,
    ttl: int = DEFAULT_TTL_SECONDS,
    force_refresh: bool = False,
    parser: Optional[Callable[[requests.Response], Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    allow_404: bool = False,
) -> Dict[str, Any]:
    """
    Fetch a URL through the cache.

    Returns a dict with:
        ok        - whether usable data was obtained (live or cached)
        data      - the parsed payload, or None
        source    - "live", "cache", or "none"
        url       - the URL attempted, so reports can cite it
        error     - failure detail when the live fetch failed
        age       - cache age in seconds when served from cache

    A 404 is meaningful for registry lookups (a fully unpublished package), so
    allow_404 returns ok=True with data=None rather than falling back to cache.
    """
    result: Dict[str, Any] = {"ok": False, "data": None, "source": "none", "url": url, "error": None}

    age = cache_age_seconds(key)
    if not force_refresh and age is not None and age < ttl:
        cached = read_cache(key)
        if cached is not None:
            return {**result, "ok": True, "data": cached, "source": "cache", "age": age}

    try:
        response = requests.get(
            url,
            timeout=_DEFAULT_TIMEOUT,
            headers=headers or {},
            verify=_ssl_verify(),
        )
        if response.status_code == 404 and allow_404:
            return {**result, "ok": True, "data": None, "source": "live", "error": "404"}
        response.raise_for_status()
        data = parser(response) if parser else response.json()
        write_cache(key, data)
        return {**result, "ok": True, "data": data, "source": "live"}
    except Exception as exc:
        result["error"] = str(exc)
        logger.warning(f"Live fetch failed for {url}: {exc}; falling back to cache")

    cached = read_cache(key)
    if cached is not None:
        return {**result, "ok": True, "data": cached, "source": "cache", "age": cache_age_seconds(key)}

    return result


def refresh_all(keys_and_urls: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    """Force-refresh a set of cache entries. Used by the manual-refresh endpoint."""
    out: Dict[str, Dict[str, Any]] = {}
    for key, url in keys_and_urls.items():
        out[key] = cached_fetch(key, url, force_refresh=True)
    return out
