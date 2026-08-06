#!/usr/bin/env python3
"""
Check Azure Artifacts npm feeds for malicious versions withdrawn from the public registry.

The question this answers
------------------------
2,206 of the 2,208 malicious versions are gone from registry.npmjs.org. Every hunt that
resolves a range against the public registry therefore reports them as unreachable — which
is true of npmjs and not necessarily true here.

An Azure Artifacts feed with an npmjs upstream caches a tarball into the feed the first
time anyone requests it, and the cached copy is not removed when the upstream unpublishes.
So a feed that served one of these packages during the attack window may still be serving
it, and a build that resolves through the feed would install it. `npm view` cannot see
this; only the feed's own package list can.

Measured on this estate: three of five feeds have `npmjs` configured as an npm upstream
(`sn-tim`, `sn-tim-packages`, `SleepNumberIndigo`). That is the mechanism, present and
enabled, which is why this check exists rather than being reasoned away.

Three checks, two of them controls
---------------------------------
  1. Does the feed hold any version whose exact `name@version` is in the malicious set?
     A hit is an actionable finding: the tarball is present and installable.
  2. Does the feed hold the affected package NAMES at any version? If the names are absent
     entirely, the feed never proxied these packages, and check 1's zero is structural.
  3. Does this identity actually hold ReadPackages on the feed? This is the control that
     makes check 2's zero reportable. Azure DevOps is honest about the denial itself —
     `SleepNumberIndigo/k8s-manifests` returns

         HTTP 403 FeedNeedsPermissionsException: You need to have 'ReadPackages'

     — but the denial and an empty feed still converge on the same *number*, because a
     paginating reader returns the packages it collected (none) alongside the error. Read
     the count and the feed looks clean; read the error and it was never measured. Both
     are recorded per feed, and a feed without ReadPackages is reported as unmeasured
     rather than counted as clean. The probe is the retention-policy endpoint, which
     requires the same permission and mutates nothing.

     A secondary control is the count of packages of any protocol: a feed returning 520
     NuGet packages and no npm packages has visibly answered the question, whereas a feed
     returning nothing at all has only shown that it is empty of everything.

What this deliberately does NOT do
----------------------------------
It never requests a package from a feed's npm registry endpoint. On a feed with an npmjs
upstream, requesting a package is what *causes* the caching this check is looking for — a
probe for `keyv` would pull `keyv` from npmjs and cache it into the feed. That turns the
measurement into the thing being measured, and writes to production infrastructure. Every
call here is against feed metadata and package inventory only.

Authentication
--------------
Uses an Entra ID access token for the Azure DevOps resource, read from a file rather than
an argument so it does not appear in the process list. Read-only APIs only: feed listing
and package listing. Nothing is downloaded, installed, promoted or deleted.

Transport
---------
curl, not urllib. TLS to `*.visualstudio.com` and `*.dev.azure.com` is intercepted on this
network, and the intercepting CA's certificate does not mark Basic Constraints critical, so
Python's OpenSSL rejects the chain outright:

    SSLCertVerificationError: certificate verify failed: Basic Constraints of CA cert not
    marked critical

curl on macOS validates the same chain against the system keychain and accepts it. The
alternative — disabling verification in a tool whose output is a security finding — would
make every result unattributable, so it is not done. The token is passed to curl through a
mode-0600 config file rather than an argument, for the same reason it is read from a file.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]

# The Azure DevOps resource ID. Constant, not a secret.
ADO_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"
API = "7.1-preview.1"


def get(url: str, config: Path, attempts: int = 3) -> Tuple[Optional[dict], Optional[str]]:
    """One GET via curl. `config` holds the Authorization header, mode 0600."""
    for attempt in range(attempts):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
            body_path = Path(handle.name)
        try:
            completed = subprocess.run(
                ["curl", "-sS", "--max-time", "120", "-K", str(config),
                 "-o", str(body_path), "-w", "%{http_code}", url],
                capture_output=True, text=True, timeout=180)
            if completed.returncode != 0:
                if attempt == attempts - 1:
                    return None, f"curl exit {completed.returncode}: " \
                                 f"{completed.stderr.strip()[:200]}"
                continue
            status = int((completed.stdout or "0").strip() or 0)
            raw = body_path.read_text(errors="replace")
        finally:
            body_path.unlink(missing_ok=True)

        if status in (401, 403):
            return None, f"HTTP {status} (no access to this resource)"
        if status == 404:
            return None, "HTTP 404"
        if status >= 500:
            if attempt < attempts - 1:
                continue
            return None, f"HTTP {status}"
        if status != 200:
            return None, f"HTTP {status}"
        try:
            # A literal `null` is a valid 200 here — a feed with no retention policy set
            # returns exactly that — so parsing is attempted before anything is judged.
            return json.loads(raw), None
        except json.JSONDecodeError:
            if raw.lstrip().lower().startswith(("<!doctype", "<html")):
                # A sign-in page rather than JSON: not authenticated for this org.
                return None, "HTML sign-in page (not authenticated for this organisation)"
            if attempt == attempts - 1:
                return None, f"unparseable 200 body: {raw[:120]!r}"
    return None, "exhausted attempts"


def list_orgs(config: Path) -> Tuple[List[str], Optional[str]]:
    profile, error = get(
        f"https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version={API}",
        config)
    if profile is None:
        return [], f"profile: {error}"
    member_id = profile.get("id")
    accounts, error = get(
        f"https://app.vssps.visualstudio.com/_apis/accounts"
        f"?memberId={urllib.parse.quote(str(member_id))}&api-version={API}", config)
    if accounts is None:
        return [], f"accounts: {error}"
    return [a["accountName"] for a in (accounts.get("value") or [])], None


def list_feeds(org: str, config: Path) -> Tuple[List[dict], Optional[str]]:
    body, error = get(
        f"https://feeds.dev.azure.com/{urllib.parse.quote(org)}"
        f"/_apis/packaging/feeds?api-version={API}", config)
    if body is None:
        return [], error
    return list(body.get("value") or []), None


def packages_url(org: str, feed: dict) -> str:
    project = (feed.get("project") or {}).get("name")
    base = f"https://feeds.dev.azure.com/{urllib.parse.quote(org)}/"
    if project:
        base += f"{urllib.parse.quote(project)}/"
    return base + f"_apis/packaging/Feeds/{feed['id']}/packages"


def probe_read_packages(
        org: str, feed: dict,
        config: Path) -> Tuple[bool, Optional[str], Optional[dict]]:
    """Whether this identity holds ReadPackages on the feed.

    The retention-policy endpoint requires ReadPackages and returns 403
    FeedNeedsPermissionsException without it, whereas the package listing returns an empty
    200. It reads configuration and changes nothing.

    Returns (has_permission, detail, retention_policy). The policy is kept because it bounds
    how long a cached tarball stays observable: a feed that deletes versions after N days
    can erase the evidence this check is looking for.
    """
    project = (feed.get("project") or {}).get("name")
    base = f"https://feeds.dev.azure.com/{urllib.parse.quote(org)}/"
    if project:
        base += f"{urllib.parse.quote(project)}/"
    url = (base + f"_apis/packaging/Feeds/{feed['id']}/retentionpolicies"
                  f"?api-version={API}")
    body, error = get(url, config)
    if error is None:
        # A null body is a feed with no retention policy set. The call still succeeded,
        # which is the only thing being asked here.
        return True, None, body if isinstance(body, dict) else None
    if error.startswith("HTTP 403"):
        return False, "HTTP 403 lacks ReadPackages on this feed", None
    return False, error, None


def list_packages(org: str, feed: dict, config: Path, page_size: int,
                  protocol: Optional[str] = "npm",
                  versions: bool = True) -> Tuple[List[dict], Optional[str]]:
    """Every package in a feed, paginated to completion.

    protocol=None applies no protocol filter, which is how the control measures whether
    the endpoint returns anything at all for this feed.
    """
    base = packages_url(org, feed)
    packages: List[dict] = []
    skip = 0
    while True:
        query = [f"$top={page_size}", f"$skip={skip}", f"api-version={API}"]
        if protocol:
            query.append(f"protocolType={protocol}")
        if versions:
            query.append("includeAllVersions=true")
        body, error = get(f"{base}?{'&'.join(query)}", config)
        if body is None:
            return packages, error
        batch = body.get("value") or []
        packages.extend(batch)
        if len(batch) < page_size:
            return packages, None
        skip += page_size
        if skip > 20000:  # runaway guard, not an expected bound
            return packages, "pagination guard hit at 20000 packages"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--token-file", type=Path, default=Path("/tmp/.ado_tok"),
                        help="File holding an Entra ID access token for the Azure DevOps "
                             "resource. Read from a file so it never enters the process "
                             "list. Acquire with: az account get-access-token "
                             f"--resource {ADO_RESOURCE} --query accessToken -o tsv")
    parser.add_argument("--scope", type=Path,
                        default=REPO_ROOT / "exports/hunt/registry_truth_v2.json")
    parser.add_argument("--confirmed-live", type=Path,
                        default=REPO_ROOT / "exports/hunt/live_tarball_verdicts.json")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/azure_artifacts_feeds.json")
    parser.add_argument("--orgs", nargs="*", default=None,
                        help="Restrict to these ADO organisations. Default: every "
                             "organisation the authenticated identity belongs to.")
    parser.add_argument("--page-size", type=int, default=200)
    args = parser.parse_args()

    if not args.token_file.exists():
        print(f"no token at {args.token_file}", file=sys.stderr)
        return 2
    token = args.token_file.read_text().strip()
    if not token:
        print("token file is empty", file=sys.stderr)
        return 2

    # The bearer token goes into a mode-0600 curl config rather than an argument, so it is
    # not visible in the process list to any other user on this machine. Created with a
    # restrictive umask and removed in the finally block below.
    previous_umask = os.umask(0o077)
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".curlrc",
                                         delete=False) as handle:
            handle.write(f'header = "Authorization: Bearer {token}"\n')
            handle.write('header = "Accept: application/json"\n')
            handle.write('user-agent = "auditgithub-hunt/1.0"\n')
            config = Path(handle.name)
    finally:
        os.umask(previous_umask)
    del token
    try:
        return run(args, config)
    finally:
        config.unlink(missing_ok=True)


def run(args: argparse.Namespace, config: Path) -> int:
    truth = json.loads(args.scope.read_text())
    specs: Set[str] = set(truth.get("malicious_specs") or [])
    if args.confirmed_live.exists():
        verdicts = json.loads(args.confirmed_live.read_text())
        specs |= set((verdicts.get("by_verdict") or {})
                     .get("MALICIOUS_CONFIRMED_BY_HASH") or [])
    affected_names: Set[str] = {spec.rpartition("@")[0] for spec in specs}
    print(f"scope: {len(specs)} specs across {len(affected_names)} names", file=sys.stderr)

    if args.orgs:
        orgs, org_error = list(args.orgs), None
    else:
        orgs, org_error = list_orgs(config)
    if org_error:
        print(f"cannot enumerate organisations: {org_error}", file=sys.stderr)
        return 2
    print(f"organisations: {orgs}", file=sys.stderr)

    results: List[dict] = []
    for org in orgs:
        feeds, error = list_feeds(org, config)
        if error:
            results.append({"org": org, "feed": None, "error": error})
            print(f"{org}: {error}", file=sys.stderr)
            continue
        for feed in feeds:
            npm_upstreams = [
                {"name": u.get("name"), "location": u.get("location")}
                for u in (feed.get("upstreamSources") or [])
                if (u.get("protocol") or "").lower() == "npm"
            ]
            packages, pkg_error = list_packages(org, feed, config, args.page_size)

            # Control 1: does this identity hold ReadPackages? A denial is served as an
            # empty 200 by the listing endpoint, so this must be asked separately.
            can_read, permission_detail, retention_policy = probe_read_packages(
                org, feed, config)

            # Control 2: no protocol filter, no version expansion — the cheapest question
            # that distinguishes "this feed holds no npm packages" from "this query
            # returned nothing". Version expansion is off because the control only needs
            # to know whether rows come back at all.
            all_protocols, control_error = list_packages(
                org, feed, config, args.page_size, protocol=None, versions=False)
            by_protocol = Counter((p.get("protocolType") or "?") for p in all_protocols)
            endpoint_returns_rows = bool(all_protocols)

            names_present: Dict[str, List[str]] = {}
            exact_hits: List[dict] = []
            for package in packages:
                name = package.get("name") or ""
                if name not in affected_names:
                    continue
                versions = [v.get("version") for v in (package.get("versions") or [])
                            if v.get("version")]
                names_present[name] = sorted(versions)
                for version in versions:
                    if f"{name}@{version}" in specs:
                        exact_hits.append({
                            "package": name, "version": version,
                            "spec": f"{name}@{version}",
                            "is_latest": any(v.get("isLatest") for v in
                                             (package.get("versions") or [])
                                             if v.get("version") == version),
                            "protocol_type": package.get("protocolType"),
                        })

            record = {
                "org": org,
                "feed": feed.get("name"),
                "feed_id": feed.get("id"),
                "project": (feed.get("project") or {}).get("name"),
                "npm_upstreams": npm_upstreams,
                "npmjs_upstream_configured": any(
                    "registry.npmjs.org" in (u.get("location") or "")
                    for u in npm_upstreams),
                "npm_packages_listed": len(packages),
                "listing_error": pkg_error,
                # Controls.
                "identity_has_read_packages": can_read,
                "read_packages_probe_detail": permission_detail,
                "retention_policy": retention_policy,
                "packages_any_protocol": len(all_protocols),
                "packages_by_protocol": dict(by_protocol.most_common()),
                "control_endpoint_returns_rows": endpoint_returns_rows,
                "control_error": control_error,
                # A zero is only an answer if this identity could have seen a non-zero.
                "npm_zero_is_measured": can_read,
                # If the affected NAMES are absent, this feed never proxied these packages,
                # and the absence of the malicious versions is structural.
                "affected_names_present": names_present,
                "MALICIOUS_VERSIONS_PRESENT": exact_hits,
            }
            results.append(record)
            flag = ("  <-- MALICIOUS PRESENT" if exact_hits else "")
            print(f"  {org}/{feed.get('name'):26s} npm={len(packages):5d} "
                  f"any={len(all_protocols):5d} {dict(by_protocol.most_common(3))} "
                  f"npmjs_upstream={record['npmjs_upstream_configured']} "
                  f"read_packages={can_read} "
                  f"malicious={len(exact_hits)}{flag}", file=sys.stderr)

    hits = [{"org": r["org"], "feed": r["feed"], **h}
            for r in results for h in (r.get("MALICIOUS_VERSIONS_PRESENT") or [])]
    feeds_with_errors = [{"org": r["org"], "feed": r["feed"],
                          "error": r.get("listing_error") or r.get("control_error")
                          or r.get("error")}
                         for r in results
                         if r.get("listing_error") or r.get("control_error")
                         or r.get("error")]
    feeds_ok = [r for r in results
                if not (r.get("listing_error") or r.get("control_error")
                        or r.get("error"))]
    names_anywhere = sorted({name for r in feeds_ok
                             for name in (r.get("affected_names_present") or {})})
    total_listed = sum(r.get("npm_packages_listed") or 0 for r in feeds_ok)
    upstream_feeds = [f"{r['org']}/{r['feed']}" for r in feeds_ok
                      if r.get("npmjs_upstream_configured")]

    protocol_totals = Counter()
    for record in feeds_ok:
        protocol_totals.update(record.get("packages_by_protocol") or {})

    # A zero is an answer only where this identity could have seen a non-zero.
    measured = [f"{r['org']}/{r['feed']}" for r in results
                if r.get("identity_has_read_packages")]
    unmeasured = [{"feed": f"{r['org']}/{r['feed']}",
                   "reason": r.get("read_packages_probe_detail"),
                   "npmjs_upstream_configured": r.get("npmjs_upstream_configured"),
                   "listing_returned": r.get("npm_packages_listed")}
                  for r in results if not r.get("identity_has_read_packages")]
    # The only gap that matters: a feed that cannot be measured AND has the upstream that
    # would let it cache a withdrawn version. Without the upstream, an unmeasurable feed is
    # still structurally incapable of holding one.
    unmeasured_and_upstream_enabled = [
        u["feed"] for u in unmeasured if u["npmjs_upstream_configured"]]
    # Retention shortens the window in which a cached tarball is still observable, so the
    # policy is recorded next to the finding rather than left for a reader to look up.
    retention = {f"{r['org']}/{r['feed']}": r.get("retention_policy")
                 for r in results if r.get("retention_policy")}
    proved_rows = [f"{r['org']}/{r['feed']}" for r in feeds_ok
                   if r.get("control_endpoint_returns_rows")]

    payload = {
        "identity": "Entra ID access token for the Azure DevOps resource",
        "organisations_checked": orgs,
        "feeds_checked": len(results),
        "feeds_readable": len(feeds_ok),
        "feeds_with_errors": feeds_with_errors,
        "npm_packages_listed_total": total_listed,
        "packages_by_protocol_all_feeds": dict(protocol_totals.most_common()),
        "feeds_with_npmjs_upstream": upstream_feeds,
        "feeds_where_endpoint_proved_it_returns_rows": proved_rows,
        "feeds_measured_identity_has_read_packages": measured,
        "feeds_UNMEASURED_no_read_packages": unmeasured,
        "unmeasured_feeds_with_npmjs_upstream": unmeasured_and_upstream_enabled,
        "retention_policies": retention,
        "affected_names_found_in_any_feed": names_anywhere,
        "MALICIOUS_VERSIONS_FOUND": hits,
        "verdict": (
            "MALICIOUS_VERSION_PRESENT_IN_FEED" if hits else
            "no_malicious_version_and_no_affected_name_proxied"
            if not names_anywhere else
            "affected_names_proxied_but_no_malicious_version"
        ),
        # The estate-level control. At least one feed must have returned rows, or every
        # zero here is a measurement artefact rather than a finding.
        "control_passed_endpoint_returns_rows_somewhere": bool(proved_rows),
        # A negative finding stands only for feeds this identity could actually read, and
        # only matters as a gap where an unreadable feed also has an npmjs upstream.
        "coverage_supports_negative_finding": (
            bool(proved_rows) and not feeds_with_errors
            and not unmeasured_and_upstream_enabled),
        "feeds": results,
        "interpretation": [
            "A feed with an npmjs upstream caches a tarball on first request and keeps the "
            "cached copy when the upstream unpublishes. That is why 'withdrawn from npm' "
            "does not by itself mean 'not installable here'.",
            "packages_by_protocol_all_feeds is the control that makes the npm zero "
            "reportable. Rows returned for another protocol prove the endpoint answers and "
            "the identity can read packages, so an empty npm list is the feed's state "
            "rather than the query's failure.",
            "affected_names_found_in_any_feed is the second control. If it is empty, no "
            "affected package was ever proxied through any feed, and the absence of the "
            "malicious versions is structural rather than merely unobserved.",
            "A feed where this identity lacks ReadPackages returns an empty list rather "
            "than an error. Those feeds are in feeds_UNMEASURED_no_read_packages and are "
            "not clean, they are unread. The gap only matters where such a feed also has "
            "an npmjs upstream, because without the upstream it could not have cached a "
            "withdrawn version in the first place.",
            "Retention policies bound how long a cached tarball remains observable. A feed "
            "that deletes versions after N days can erase this evidence, so the policies "
            "are recorded alongside the result.",
        ],
        "limits": [
            "Covers feeds visible to the authenticated identity in the organisations it "
            "belongs to. A feed in an organisation this identity does not belong to is "
            "outside this run entirely.",
            "Feed-level view only. It does not show whether a build actually resolved "
            "through the feed, and it does not cover npm caches baked into container "
            "images, which are not visible from any registry API.",
            "No package is ever requested from a feed's npm registry endpoint. On an "
            "upstream-enabled feed that request is what causes caching, so probing for a "
            "package would create the condition being hunted and write to production "
            "infrastructure.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2))
    print(f"\nwritten: {args.out}", file=sys.stderr)
    print(f"verdict: {payload['verdict']}", file=sys.stderr)
    print(f"control (rows returned somewhere): "
          f"{payload['control_passed_endpoint_returns_rows_somewhere']} "
          f"{dict(protocol_totals.most_common())}", file=sys.stderr)
    if unmeasured:
        print(f"UNMEASURED ({len(unmeasured)} feeds, no ReadPackages): "
              f"{[u['feed'] for u in unmeasured]}", file=sys.stderr)
    if unmeasured_and_upstream_enabled:
        print(f"*** COVERAGE GAP: unmeasured feed WITH npmjs upstream: "
              f"{unmeasured_and_upstream_enabled} ***", file=sys.stderr)
    if hits:
        print("*** MALICIOUS VERSIONS PRESENT IN A FEED ***", file=sys.stderr)
        for hit in hits:
            print(f"    {hit['org']}/{hit['feed']}: {hit['spec']}", file=sys.stderr)
    return 0 if (not hits and payload["coverage_supports_negative_finding"]) else 3


if __name__ == "__main__":
    sys.exit(main())
