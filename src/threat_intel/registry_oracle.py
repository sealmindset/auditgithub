"""
Registry ground truth — the malicious-version oracle.

Implements the rule from docs/playbooks/supply-chain-hunt-ttp.md section 0.2:

    A name@version is malicious only if it was published inside the attack window
    AND subsequently unpublished / withdrawn. Both conditions.

Anything a vendor asserts without both conditions is an allegation pending
verification. This module is what arbitration escalates to when sources disagree.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .cache import cached_fetch

logger = logging.getLogger(__name__)

# npm records metadata alongside version timestamps in the same map.
_NPM_TIME_META_KEYS = {"created", "modified"}


def _parse_ts(value: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""
    if not value:
        return None
    try:
        text = value.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _in_window(ts: Optional[datetime], start: datetime, end: datetime) -> bool:
    return ts is not None and start <= ts <= end


class RegistryOracle:
    """
    Queries a package registry to establish which versions are genuinely malicious.

    Confidence differs by ecosystem and is reported honestly rather than flattened:

    npm       - strongest. The packument 'time' map retains every version ever
                published, while 'versions' holds only what is currently published.
                The set difference is exactly the unpublished set.
    crates.io - strong. Per-version 'yanked' flag plus 'created_at'.
    rubygems  - moderate. Yanked versions disappear from the versions endpoint, so
                withdrawal is inferred from absence rather than observed directly.
    pypi      - weakest. PyPI deletion removes a release outright with no tombstone,
                so an unpublished version is indistinguishable from one that never
                existed. Only 'yanked' is directly observable.
    """

    def __init__(self, force_refresh: bool = False):
        self.force_refresh = force_refresh

    # -------------------------------------------------------------------------
    # npm
    # -------------------------------------------------------------------------

    def npm_packument(self, package: str) -> Dict[str, Any]:
        """
        Fetch the full npm packument.

        The abbreviated (application/vnd.npm.install-v1+json) form omits the full
        'time' map, which is the entire basis of unpublish detection, so the full
        document is required despite being larger.
        """
        return cached_fetch(
            key=f"npm_{package}",
            url=f"https://registry.npmjs.org/{package}",
            force_refresh=self.force_refresh,
            headers={"Accept": "application/json"},
            allow_404=True,
        )

    def npm_analyze(
        self,
        package: str,
        window_start: datetime,
        window_end: datetime,
    ) -> Dict[str, Any]:
        """
        Classify every version of an npm package against the attack window.

        Returns published_in_window, unpublished, and malicious (the intersection).
        """
        fetched = self.npm_packument(package)
        out: Dict[str, Any] = {
            "package": package,
            "ecosystem": "npm",
            "ok": fetched["ok"],
            "source": fetched["source"],
            "url": fetched["url"],
            "error": fetched.get("error"),
            "confidence": "high",
            "published_in_window": [],
            "unpublished": [],
            "malicious": [],
            "current_versions": [],
            "notes": [],
        }

        if not fetched["ok"]:
            out["notes"].append("Registry unreachable and no cached copy; result is unknown, not clean.")
            return out

        doc = fetched["data"]
        if doc is None:
            # 404 on the whole packument: every version was unpublished, or the
            # package never existed. Both are notable; neither is "clean".
            out["notes"].append(
                "Packument returned 404 — the entire package is absent from the registry. "
                "Either fully unpublished or never published. Requires manual confirmation."
            )
            out["confidence"] = "indeterminate"
            return out

        time_map: Dict[str, str] = doc.get("time", {}) or {}
        current = set((doc.get("versions", {}) or {}).keys())
        out["current_versions"] = sorted(current)

        for version, raw_ts in time_map.items():
            if version in _NPM_TIME_META_KEYS:
                continue
            ts = _parse_ts(raw_ts)
            in_window = _in_window(ts, window_start, window_end)
            withdrawn = version not in current

            if in_window:
                out["published_in_window"].append(
                    {"version": version, "published": raw_ts, "unpublished": withdrawn}
                )
            if withdrawn:
                out["unpublished"].append({"version": version, "published": raw_ts})
            if in_window and withdrawn:
                # Both conditions satisfied. This is a confirmed malicious version.
                out["malicious"].append(
                    {
                        "name": package,
                        "version": version,
                        "published": raw_ts,
                        "spec": f"{package}@{version}",
                    }
                )

        for bucket in ("published_in_window", "unpublished", "malicious"):
            out[bucket].sort(key=lambda item: item.get("published") or "")

        if out["published_in_window"] and not out["malicious"]:
            out["notes"].append(
                "Versions were published inside the window but remain available. Published-in-window "
                "alone does not establish maliciousness."
            )
        return out

    # -------------------------------------------------------------------------
    # Other ecosystems
    # -------------------------------------------------------------------------

    def crates_analyze(
        self, package: str, window_start: datetime, window_end: datetime
    ) -> Dict[str, Any]:
        fetched = cached_fetch(
            key=f"crates_{package}",
            url=f"https://crates.io/api/v1/crates/{package}",
            force_refresh=self.force_refresh,
            allow_404=True,
        )
        out = {
            "package": package, "ecosystem": "cargo", "ok": fetched["ok"],
            "source": fetched["source"], "url": fetched["url"], "confidence": "high",
            "published_in_window": [], "unpublished": [], "malicious": [], "notes": [],
        }
        if not fetched["ok"] or fetched["data"] is None:
            out["confidence"] = "indeterminate"
            return out

        for ver in fetched["data"].get("versions", []) or []:
            num = ver.get("num")
            ts = _parse_ts(ver.get("created_at", ""))
            in_window = _in_window(ts, window_start, window_end)
            yanked = bool(ver.get("yanked"))
            if in_window:
                out["published_in_window"].append(
                    {"version": num, "published": ver.get("created_at"), "unpublished": yanked}
                )
            if yanked:
                out["unpublished"].append({"version": num, "published": ver.get("created_at")})
            if in_window and yanked:
                out["malicious"].append(
                    {"name": package, "version": num, "published": ver.get("created_at"),
                     "spec": f"{package}@{num}"}
                )
        return out

    def pypi_analyze(
        self, package: str, window_start: datetime, window_end: datetime
    ) -> Dict[str, Any]:
        fetched = cached_fetch(
            key=f"pypi_{package}",
            url=f"https://pypi.org/pypi/{package}/json",
            force_refresh=self.force_refresh,
            allow_404=True,
        )
        out = {
            "package": package, "ecosystem": "pypi", "ok": fetched["ok"],
            "source": fetched["source"], "url": fetched["url"],
            # Deliberately lower. See the class docstring.
            "confidence": "low",
            "published_in_window": [], "unpublished": [], "malicious": [],
            "notes": [
                "PyPI deletion leaves no tombstone, so an unpublished version cannot be "
                "distinguished from one that never existed. Only 'yanked' is directly "
                "observable. Absence of a malicious finding here is weak evidence."
            ],
        }
        if not fetched["ok"] or fetched["data"] is None:
            out["confidence"] = "indeterminate"
            return out

        for version, files in (fetched["data"].get("releases", {}) or {}).items():
            if not files:
                # An empty file list means every artifact was removed.
                out["unpublished"].append({"version": version, "published": None})
                continue
            ts = _parse_ts(files[0].get("upload_time_iso_8601", ""))
            yanked = any(f.get("yanked") for f in files)
            if _in_window(ts, window_start, window_end):
                out["published_in_window"].append(
                    {"version": version, "published": files[0].get("upload_time_iso_8601"),
                     "unpublished": yanked}
                )
                if yanked:
                    out["malicious"].append(
                        {"name": package, "version": version,
                         "published": files[0].get("upload_time_iso_8601"),
                         "spec": f"{package}@{version}"}
                    )
        return out

    # -------------------------------------------------------------------------
    # Dispatch
    # -------------------------------------------------------------------------

    def analyze(
        self,
        package: str,
        window_start: datetime,
        window_end: datetime,
        ecosystem: str = "npm",
    ) -> Dict[str, Any]:
        eco = (ecosystem or "npm").lower()
        if eco == "npm":
            return self.npm_analyze(package, window_start, window_end)
        if eco in ("cargo", "crates"):
            return self.crates_analyze(package, window_start, window_end)
        if eco == "pypi":
            return self.pypi_analyze(package, window_start, window_end)
        return {
            "package": package, "ecosystem": eco, "ok": False,
            "confidence": "unsupported", "malicious": [],
            "notes": [f"No tier-0 oracle implemented for ecosystem '{eco}'."],
        }

    def derive_malicious_set(
        self,
        packages: List[str],
        window_start: datetime,
        window_end: datetime,
        ecosystem: str = "npm",
    ) -> Dict[str, Any]:
        """
        Build the authoritative malicious name@version set for a candidate package list.

        This is the output the whole hunt is scoped against. It replaces the vendor
        union rather than supplementing it.
        """
        malicious: List[Dict[str, Any]] = []
        per_package: Dict[str, Any] = {}
        unreachable: List[str] = []

        for package in packages:
            analysis = self.analyze(package, window_start, window_end, ecosystem)
            per_package[package] = analysis
            malicious.extend(analysis.get("malicious", []))
            if not analysis.get("ok") or analysis.get("confidence") == "indeterminate":
                unreachable.append(package)

        specs = sorted({item["spec"] for item in malicious})
        return {
            "window": {"start": window_start.isoformat(), "end": window_end.isoformat()},
            "ecosystem": ecosystem,
            "packages_queried": len(packages),
            "malicious_specs": specs,
            "malicious_count": len(specs),
            "malicious_detail": sorted(malicious, key=lambda item: item.get("published") or ""),
            "per_package": per_package,
            "unreachable": unreachable,
            "coverage_warning": (
                f"{len(unreachable)} of {len(packages)} packages could not be authoritatively "
                "resolved; treat these as unknown rather than clean."
            ) if unreachable else None,
        }
