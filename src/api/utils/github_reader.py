"""
Shared read-only GitHub HTTP layer for the deployment-topology phases.

Extracted from the P1 topology service so every phase (P1 reusable-workflow
propagation, P2 deployment observation, later static/IaC phases) shares one set
of behaviours that took real incidents to get right:

* **A 403 is not automatically a permission denial.** GitHub returns 403 for
  primary and secondary throttling too. Throttling is reported as the internal
  ``RATE_LIMITED`` status so a throttled run is never filed as a rights gap -
  that would raise a false access request.
* **HTTP status is data, not an exception.** ``_get`` returns
  ``(payload, status)`` so a 403/404 becomes recorded coverage instead of a lost
  repository.
* **Every response feeds the shared budget governor.** One PAT, one 5000/hr
  limit, many consumers - see ``github_budget``.
* **The /rate_limit endpoint is only a cross-check.** It has been observed
  reporting 4990 remaining while the very next real request 403'd with
  ``X-RateLimit-Used: 5019``, so the smaller of endpoint and real response
  headers wins.
"""
import logging
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import requests

from . import github_budget

logger = logging.getLogger(__name__)

# Internal sentinel status: throttled by GitHub, NOT denied by permissions.
# Kept out of the 4xx range so it can never be mistaken for an HTTP status.
RATE_LIMITED = 1429


class GitHubReader:
    """Authenticated, read-only GitHub client with budget and rights accounting."""

    def __init__(
        self,
        github_token: str,
        base_url: str = "https://api.github.com",
        max_rate_limit_wait: int = 0,
    ):
        """
        Args:
            github_token: Classic PAT with `repo` scope, or a GitHub App token
                with the equivalent read permissions.
            base_url: GitHub API base, overridable for GHES.
            max_rate_limit_wait: Seconds this reader may block waiting for a
                primary rate-limit reset. 0 aborts instead of waiting.
        """
        self.github_token = github_token
        self.base_url = base_url.rstrip("/")
        self.max_rate_limit_wait = max_rate_limit_wait
        self.rate_limited = False
        self.rate_limit_reset_at: Optional[int] = None
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        # Rights gaps discovered during a run, surfaced in the sync stats so an
        # access request can be raised with concrete evidence.
        self.rights_gaps: Dict[str, Dict[str, Any]] = {}

    # -- HTTP -------------------------------------------------------------

    def _get(
        self, path: str, params: Optional[Dict[str, Any]] = None, raw: bool = False
    ) -> Tuple[Optional[Any], int]:
        """GET a GitHub endpoint, returning (payload_or_None, status_code).

        Never raises for HTTP status - callers branch on the code so a 403 or
        404 becomes recorded coverage rather than a lost repository.
        """
        url = f"{self.base_url}{path}"
        headers = {"Accept": "application/vnd.github.raw"} if raw else {}

        for attempt in range(2):
            try:
                resp = self.session.get(url, params=params, headers=headers, timeout=30)
            except requests.RequestException as exc:
                logger.warning("GitHub request failed for %s: %s", path, exc)
                return None, 0
            self.request_count += 1
            # Publish the authoritative budget so scheduled scans back off before
            # they starve operator-triggered work.
            github_budget.observe_headers(resp.headers)

            if self._is_rate_limited(resp):
                self.rate_limited = True
                self.rate_limit_reset_at = _int_header(resp, "X-RateLimit-Reset")
                wait = self._seconds_until_reset()
                if attempt == 0 and wait is not None and 0 < wait <= self.max_rate_limit_wait:
                    logger.warning(
                        "GitHub rate limit exhausted; sleeping %ss until reset", wait
                    )
                    time.sleep(wait + 2)
                    continue
                # RATE_LIMITED is distinct from a permission denial. Returning it
                # as its own status keeps a throttled run from being reported as
                # a rights gap, which would send a false access request.
                return None, RATE_LIMITED

            if resp.status_code >= 400:
                return None, resp.status_code
            return (resp.text if raw else resp.json()), resp.status_code

        return None, RATE_LIMITED

    @staticmethod
    def _is_rate_limited(resp: requests.Response) -> bool:
        """True when a 403/429 is throttling rather than a permission denial."""
        if resp.status_code == 429:
            return True
        if resp.status_code != 403:
            return False
        if _int_header(resp, "X-RateLimit-Remaining") == 0:
            return True
        body = (resp.text or "").lower()
        return "rate limit" in body or "secondary rate limit" in body

    def _seconds_until_reset(self) -> Optional[int]:
        if not self.rate_limit_reset_at:
            return None
        return max(0, int(self.rate_limit_reset_at - time.time()))

    def _reset_utc(self) -> str:
        if not self.rate_limit_reset_at:
            return "the next rate-limit window"
        return datetime.utcfromtimestamp(self.rate_limit_reset_at).isoformat() + "Z"

    def rate_limit_status(self) -> Dict[str, Any]:
        """Current primary rate-limit budget, for run reports.

        /rate_limit is not always truthful: it has been observed reporting
        ~4990 remaining while the very next real request returned 403 with
        X-RateLimit-Used: 5019. So the budget is cross-checked against the
        headers of a real request, and the smaller of the two wins.
        """
        payload, status = self._get("/rate_limit")
        if status != 200 or not isinstance(payload, dict):
            return {"available": False, "status": status}
        core = (payload.get("resources") or {}).get("core") or {}
        result = {
            "available": True,
            "limit": core.get("limit"),
            "remaining": core.get("remaining"),
            "reset_epoch": core.get("reset"),
            "reset_utc": (
                datetime.utcfromtimestamp(core["reset"]).isoformat() + "Z"
                if core.get("reset")
                else None
            ),
            "source": "rate_limit_endpoint",
        }

        probe = self.observe_rate_limit_headers()
        if probe.get("remaining") is not None and (
            result.get("remaining") is None
            or probe["remaining"] < result["remaining"]
        ):
            result["reported_by_endpoint"] = result["remaining"]
            result["remaining"] = probe["remaining"]
            result["reset_epoch"] = probe.get("reset_epoch") or result["reset_epoch"]
            result["reset_utc"] = probe.get("reset_utc") or result["reset_utc"]
            result["source"] = "response_headers"
        return result

    def observe_rate_limit_headers(self) -> Dict[str, Any]:
        """Read the real remaining budget from a cheap authenticated request.

        GET /user costs one call and returns the authoritative rate-limit
        headers even when it 403s because the budget is gone.
        """
        url = f"{self.base_url}/user"
        try:
            resp = self.session.get(url, timeout=30)
        except requests.RequestException:
            return {}
        self.request_count += 1
        github_budget.observe_headers(resp.headers)
        remaining = _int_header(resp, "X-RateLimit-Remaining")
        reset = _int_header(resp, "X-RateLimit-Reset")
        if reset:
            self.rate_limit_reset_at = reset
        if remaining is None:
            return {}
        return {
            "remaining": remaining,
            "used": _int_header(resp, "X-RateLimit-Used"),
            "reset_epoch": reset,
            "reset_utc": (
                datetime.utcfromtimestamp(reset).isoformat() + "Z" if reset else None
            ),
        }

    def _record_gap(self, key: str, endpoint: str, status: int, detail: str) -> None:
        """Record a real permission denial (never a throttle) for the run report."""
        gap = self.rights_gaps.setdefault(
            key,
            {"endpoint": endpoint, "status": status, "detail": detail, "occurrences": 0,
             "examples": []},
        )
        gap["occurrences"] += 1
        if len(gap["examples"]) < 5:
            gap["examples"].append(endpoint)


def _int_header(resp: requests.Response, name: str) -> Optional[int]:
    raw = resp.headers.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None
