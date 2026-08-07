"""
Microsoft Graph / Defender XDR client for threat hunting.

App-only (client_credentials) access to the security endpoints used by
docs/playbooks/supply-chain-hunt-ttp.md phase 5:

  POST /security/runHuntingQuery     advanced hunting (KQL over Defender XDR tables)
  GET  /security/alerts_v2           unified alerts
  GET  /security/incidents           incidents
  GET  /auditLogs/signIns            Entra sign-in logs

Read-only by construction. Every request goes through _request(), which refuses any
method other than GET and rejects POST to anything outside a two-entry allowlist. A
hunting client with write access to Graph is a lateral-movement tool; the restriction is
mechanical rather than a matter of care.

The API constraints encoded here were all learned the hard way during the mini
Shai-Hulud hunt, and each one silently produces a wrong answer rather than an error:

  * alerts_v2 caps a response at 100 rows and returns **no @odata.nextLink**. A hunt
    that reads len(value) as the alert count under-reports without any signal that it
    did. list_alerts() pages by createdDateTime instead and sets `truncated` when it
    cannot prove completeness.
  * `title` is not $filter-able on alerts_v2 (severity and createdDateTime are).
    Filtering on it returns a 400, or worse, silently different results.
  * `$table` is not available in advanced hunting KQL. Use `withsource=` on union.
  * AADSpnSignInEventsBeta has no UserAgent column.
  * `order by … asc | take N` truncates the *recent* tail, which is the part a hunt
    cares about. lint_kql() rejects it.
  * An app-only token missing a role returns an empty result set or a 403 that reads
    exactly like "nothing found". roles() reports what the token actually carries, and
    require_role() fails loudly instead of returning zero rows.
"""

import base64
import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
LOGIN_BASE = "https://login.microsoftonline.com"

# The only POST endpoints this client will call. Advanced hunting is a POST because the
# query travels in the body; it is still a read.
_POST_ALLOWLIST = ("/security/runHuntingQuery", "/security/microsoft.graph.security.runHuntingQuery")

# Roles required by each capability, so a missing permission is reported as a permission
# problem rather than as an absence of findings.
ROLE_REQUIREMENTS = {
    "runHuntingQuery": ("ThreatHunting.Read.All",),
    "alerts_v2": ("SecurityAlert.Read.All", "SecurityEvents.Read.All"),
    "incidents": ("SecurityIncident.Read.All", "SecurityAlert.Read.All"),
    "signIns": ("AuditLog.Read.All",),
}

# alerts_v2 hard page size. Documented as 100; it is applied without a continuation
# token, which is the dangerous part.
ALERTS_PAGE_CAP = 100


class GraphError(RuntimeError):
    """Graph returned an error, or the client refused to make the call."""


class GraphNotConfigured(GraphError):
    """No Graph credential is available."""


class GraphPermissionError(GraphError):
    """The token lacks a role required for the requested capability."""


class KqlLintError(ValueError):
    """A KQL query uses a construct known to produce silently wrong results."""


@dataclass
class HuntResult:
    """
    Result of an advanced hunting query, with the coverage caveats attached.

    `warnings` is not decoration. A hunt that reports zero rows is only meaningful if
    the reader can see whether the query was capped, the table was unavailable, or the
    lookback exceeded retention.
    """
    query: str
    rows: List[Dict[str, Any]] = field(default_factory=list)
    schema: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    truncated: bool = False
    duration_ms: Optional[int] = None

    @property
    def count(self) -> int:
        return len(self.rows)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "count": self.count,
            "rows": self.rows,
            "schema": self.schema,
            "warnings": self.warnings,
            "truncated": self.truncated,
            "duration_ms": self.duration_ms,
        }


# =============================================================================
# KQL linting — rule 0.4 of the playbook, enforced in code
# =============================================================================

_KQL_TRAPS: List[Tuple[str, str]] = [
    (
        r"\$table",
        "$table is not available in Microsoft Graph advanced hunting. Use "
        "`union withsource=SourceTable ...` to label rows by origin table.",
    ),
    (
        r"order\s+by\s+[^|]*\basc\b[^|]*\|\s*take\s+\d+",
        "`order by ... asc | take N` keeps the OLDEST N rows and discards the recent "
        "tail — the opposite of what a hunt needs. Use `desc`, or use `top N by` .",
    ),
    (
        r"AADSpnSignInEventsBeta[\s\S]*\bUserAgent\b",
        "AADSpnSignInEventsBeta has no UserAgent column. Service-principal sign-ins do "
        "not carry one; read the alert evidence array or IdentityLogonEvents instead.",
    ),
]

# Any construct that mutates state or pulls in outside data. Advanced hunting is
# read-only, but a query is still caller-supplied text reaching a Microsoft API, and an
# explicit deny is cheap.
#
# Note the lookbehind rather than a leading \b: a word boundary cannot match between the
# start of a string and a literal '.', because neither side is a word character. Written
# as r"\b\.drop\b" this pattern silently matches nothing, which is how the first version
# of it let ".drop table Foo" through.
#
# Anchored to the start of a line because a KQL control command must be the first token
# of a statement. Matching a bare `.drop` anywhere would reject legitimate property
# access such as `parse_json(Fields).drop`.
_KQL_FORBIDDEN = re.compile(
    r"^\s*\.(set|set-or-append|set-or-replace|append|create|create-or-alter|drop|"
    r"alter|ingest|delete|rename|move|purge|execute)\b"
    r"|\bexternaldata\b",
    re.IGNORECASE | re.MULTILINE,
)


def lint_kql(query: str, strict: bool = True) -> List[str]:
    """
    Check a KQL query for constructs that silently produce wrong results.

    Returns warnings. Raises KqlLintError when strict and a trap is present, because
    every trap in this list yields plausible-looking output rather than an error — the
    failure mode a hunt cannot detect after the fact.
    """
    warnings: List[str] = []

    if _KQL_FORBIDDEN.search(query):
        raise KqlLintError(
            "Query contains a control-command or data-ingestion construct. This client "
            "is read-only and will not send it."
        )

    for pattern, message in _KQL_TRAPS:
        if re.search(pattern, query, re.IGNORECASE):
            if strict:
                raise KqlLintError(message)
            warnings.append(message)

    if not re.search(r"\b(limit|take|summarize|count|top)\b", query, re.IGNORECASE):
        warnings.append(
            "Query has no explicit row limit or aggregation. Advanced hunting caps "
            "results, so a full-table scan may be silently truncated."
        )

    if not re.search(r"\bTimestamp\b|\bago\s*\(", query, re.IGNORECASE):
        warnings.append(
            "Query has no time predicate. Advanced hunting looks back 30 days at most; "
            "state the window explicitly so a report cannot imply longer coverage."
        )

    return warnings


# =============================================================================
# Client
# =============================================================================

class GraphClient:
    """
    App-only Microsoft Graph client scoped to security reads.

    Construct with from_db() so the credential comes from the encrypted store and its
    provenance travels with the results.
    """

    def __init__(self, client_id: str, client_secret: str, tenant_id: str,
                 provenance: Optional[Dict[str, Any]] = None, timeout: int = 60):
        if not (client_id and client_secret and tenant_id):
            raise GraphNotConfigured("client_id, client_secret and tenant_id are all required")
        self.client_id = client_id
        self._client_secret = client_secret
        self.tenant_id = tenant_id
        self.provenance = provenance or {}
        self.timeout = timeout

        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._roles: Optional[List[str]] = None
        # Advanced hunting is rate limited (documented as 15 requests/minute). Track
        # call times so a fan-out hunt throttles itself rather than collecting 429s that
        # look like empty results to a careless caller.
        self._hunt_calls: List[float] = []

    @classmethod
    def from_db(cls, db, timeout: int = 60) -> "GraphClient":
        """Build a client from the encrypted credential store."""
        from .. import credentials as cred_service

        resolved = cred_service.resolve_graph_credentials(db)
        if not resolved.found:
            raise GraphNotConfigured(
                "No Microsoft Graph credential is stored or present in the environment. "
                "Add one via POST /credentials/graph."
            )
        client_id = resolved.client_id
        tenant_id = resolved.tenant_id
        # resolve_graph_credentials truncates identifiers for reporting; read the raw
        # values from the row for actual use.
        from .. import models

        row = (
            db.query(models.OrganizationCredential)
            .filter(
                models.OrganizationCredential.credential_type == cred_service.GRAPH_APP,
                models.OrganizationCredential.organization_id.is_(None),
                models.OrganizationCredential.is_active.is_(True),
            )
            .first()
        )
        if row:
            client_id = row.client_id or client_id
            tenant_id = row.tenant_id_value or tenant_id
        if not (client_id and tenant_id):
            import os

            client_id = client_id or os.environ.get("GRAPH_CLIENT_ID")
            tenant_id = tenant_id or os.environ.get("GRAPH_TENANT_ID")

        return cls(
            client_id=client_id,
            client_secret=resolved.value,
            tenant_id=tenant_id,
            provenance=resolved.provenance(),
            timeout=timeout,
        )

    # -------------------------------------------------------------------------
    # Auth
    # -------------------------------------------------------------------------

    def _acquire_token(self) -> str:
        """Acquire an app-only token, cached in memory until 60s before expiry.

        Kept in process memory only. Earlier manual hunts wrote the token to
        /tmp/.g_app_tok with mode 600; a file is unnecessary here and every additional
        copy of a bearer token is additional exposure.
        """
        now = time.time()
        if self._token and now < self._token_expires_at - 60:
            return self._token

        resp = requests.post(
            f"{LOGIN_BASE}/{self.tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            # Report the AAD error code, never the request body.
            detail = ""
            try:
                body = resp.json()
                detail = f"{body.get('error')}: {body.get('error_description', '')[:200]}"
            except Exception:
                detail = f"HTTP {resp.status_code}"
            raise GraphError(f"Token acquisition failed for app {self.client_id[:8]}…: {detail}")

        payload = resp.json()
        self._token = payload["access_token"]
        self._token_expires_at = now + int(payload.get("expires_in", 3600))
        self._roles = _decode_roles(self._token)
        logger.info(
            f"Acquired Graph app-only token for app {self.client_id[:8]}… "
            f"roles={self._roles or '(none in token)'}"
        )
        return self._token

    def roles(self) -> List[str]:
        """
        Application roles the issued token actually carries.

        This is the authoritative answer to "what is this app allowed to read", and it
        supersedes whatever was recorded when the credential was stored. An app
        registration's documented permissions and its granted permissions differ often
        enough that the it-spend-tracker assessment could not resolve the blast radius
        of a leaked secret from documentation alone.
        """
        self._acquire_token()
        return list(self._roles or [])

    def require_role(self, capability: str) -> None:
        """
        Fail loudly when the token lacks any role that satisfies a capability.

        Without this, a Defender query with no permission returns an empty result set,
        and an empty result set is indistinguishable from a clean estate.
        """
        needed = ROLE_REQUIREMENTS.get(capability)
        if not needed:
            return
        have = set(self.roles())
        if not have:
            raise GraphPermissionError(
                f"The token carries no application roles, so '{capability}' cannot "
                "succeed. Any empty result from this client would be a permission "
                "artifact, not evidence."
            )
        if not have.intersection(needed):
            raise GraphPermissionError(
                f"'{capability}' requires one of {list(needed)}; the token carries "
                f"{sorted(have)}. Grant the role and consent it, or record this as an "
                "uncovered surface — do not report the resulting zero as a finding."
            )

    def verify(self) -> Dict[str, Any]:
        """
        Confirm the credential works and report what it can reach.

        Returns per-capability availability so a hunt can state its coverage before it
        starts, rather than discovering gaps as ambiguous zeros afterwards.
        """
        result: Dict[str, Any] = {
            "client_id": self.client_id,
            "tenant_id": f"{self.tenant_id[:8]}…",
            "status": "error",
            "roles": [],
            "capabilities": {},
            "provenance": self.provenance,
        }
        try:
            self._acquire_token()
        except GraphError as exc:
            result["detail"] = str(exc)
            return result

        result["status"] = "ok"
        result["roles"] = self.roles()
        for capability in ROLE_REQUIREMENTS:
            try:
                self.require_role(capability)
                result["capabilities"][capability] = {"available": True}
            except GraphPermissionError as exc:
                result["capabilities"][capability] = {"available": False, "reason": str(exc)}
        return result

    # -------------------------------------------------------------------------
    # Transport
    # -------------------------------------------------------------------------

    def _request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None, beta: bool = False,
                 absolute_url: Optional[str] = None) -> Dict[str, Any]:
        """Issue a request, refusing anything that is not a read."""
        method = method.upper()
        if method not in ("GET", "POST"):
            raise GraphError(f"{method} is not permitted: this client is read-only.")
        if method == "POST" and not any(path.endswith(p) or p in path for p in _POST_ALLOWLIST):
            raise GraphError(
                f"POST {path} is not on the read-only allowlist {list(_POST_ALLOWLIST)}."
            )

        url = absolute_url or f"{(GRAPH_BETA if beta else GRAPH_BASE)}{path}"
        headers = {
            "Authorization": f"Bearer {self._acquire_token()}",
            "Content-Type": "application/json",
        }

        resp = requests.request(method, url, headers=headers, params=params,
                                json=json_body, timeout=self.timeout)

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "30"))
            logger.warning(f"Graph throttled {method} {path}; sleeping {retry_after}s")
            time.sleep(retry_after)
            resp = requests.request(method, url, headers=headers, params=params,
                                    json=json_body, timeout=self.timeout)

        if resp.status_code == 403:
            raise GraphPermissionError(
                f"{method} {path} returned 403. The app lacks a required role. Treat this "
                "as an uncovered surface, not as an absence of results. "
                f"Token roles: {self.roles()}"
            )
        if resp.status_code >= 400:
            snippet = resp.text[:400]
            raise GraphError(f"{method} {path} returned {resp.status_code}: {snippet}")

        if not resp.content:
            return {}
        return resp.json()

    # -------------------------------------------------------------------------
    # Advanced hunting
    # -------------------------------------------------------------------------

    def run_hunting_query(self, query: str, strict_lint: bool = True) -> HuntResult:
        """
        Run a KQL query against Defender XDR advanced hunting.

        Lints the query first. The traps in lint_kql all return plausible output rather
        than an error, so catching them before the call is the only place they can be
        caught at all.
        """
        self.require_role("runHuntingQuery")
        warnings = lint_kql(query, strict=strict_lint)

        self._throttle_hunt()
        started = time.time()
        body = self._request("POST", "/security/runHuntingQuery", json_body={"Query": query})
        duration_ms = int((time.time() - started) * 1000)

        rows = body.get("results", []) or []
        schema = body.get("schema", []) or []

        result = HuntResult(query=query, rows=rows, schema=schema,
                            warnings=warnings, duration_ms=duration_ms)

        # Advanced hunting returns at most 100,000 rows. Hitting the ceiling exactly is
        # the signal that the real answer is larger.
        if len(rows) >= 100000:
            result.truncated = True
            result.warnings.append(
                "Result hit the 100,000-row advanced hunting ceiling; the true count is "
                "higher. Narrow the window or aggregate with summarize."
            )
        return result

    def _throttle_hunt(self, per_minute: int = 15) -> None:
        """Self-limit advanced hunting calls to stay under the documented quota."""
        now = time.time()
        self._hunt_calls = [t for t in self._hunt_calls if now - t < 60]
        if len(self._hunt_calls) >= per_minute:
            sleep_for = 60 - (now - self._hunt_calls[0]) + 1
            logger.info(f"Advanced hunting quota reached; sleeping {sleep_for:.0f}s")
            time.sleep(max(0, sleep_for))
            self._hunt_calls = [t for t in self._hunt_calls if time.time() - t < 60]
        self._hunt_calls.append(time.time())

    def coverage_control(self, hours: int = 24) -> Dict[str, Any]:
        """
        Establish that telemetry exists before interpreting any zero.

        Rule 0.1 of the playbook: a zero result needs a control proving the query could
        have returned something. Returns per-hour event counts plus distinct device and
        directory totals. If this comes back empty, every other zero in the hunt is
        meaningless.
        """
        query = f"""
DeviceProcessEvents
| where Timestamp > ago({hours}h)
| summarize Events = count(), Devices = dcount(DeviceId) by bin(Timestamp, 1h)
| order by Timestamp desc
"""
        result = self.run_hunting_query(query.strip())
        buckets = result.rows
        total_events = sum(int(r.get("Events", 0)) for r in buckets)
        return {
            "hours_requested": hours,
            "buckets_returned": len(buckets),
            "total_events": total_events,
            "max_devices_in_any_hour": max((int(r.get("Devices", 0)) for r in buckets), default=0),
            "telemetry_present": total_events > 0,
            "interpretation": (
                "Telemetry present; a zero result from a subsequent query is meaningful."
                if total_events > 0 else
                "NO TELEMETRY. Every zero in this hunt is uninterpretable — the pipeline, "
                "not the estate, is the finding."
            ),
            "buckets": buckets,
            "warnings": result.warnings,
        }

    # -------------------------------------------------------------------------
    # Alerts and incidents
    # -------------------------------------------------------------------------

    def list_alerts(self, since: Optional[datetime] = None, until: Optional[datetime] = None,
                    severities: Optional[List[str]] = None,
                    max_rows: int = 2000) -> Dict[str, Any]:
        """
        List unified alerts, working around the silent 100-row cap.

        alerts_v2 returns at most 100 alerts and, unlike almost every other Graph
        collection, does **not** supply @odata.nextLink. Reading len(value) as the total
        therefore under-reports with no indication that it did. This method walks
        backwards through createdDateTime windows: when a page comes back exactly at the
        cap, the window is halved and re-queried, so completeness is established rather
        than assumed.

        Note that `title` is not $filter-able. Filter by severity or time and match
        titles client-side.
        """
        self.require_role("alerts_v2")

        until = until or datetime.now(timezone.utc)
        since = since or (until - timedelta(days=30))

        collected: Dict[str, Dict[str, Any]] = {}
        warnings: List[str] = []
        windows: List[Tuple[datetime, datetime]] = [(since, until)]
        api_calls = 0

        while windows and len(collected) < max_rows:
            w_start, w_end = windows.pop()
            filters = [
                f"createdDateTime ge {_iso(w_start)}",
                f"createdDateTime le {_iso(w_end)}",
            ]
            if severities:
                # $filter values must be URL-encoded; requests handles the encoding, but
                # the quoting is ours to get right.
                sev_clause = " or ".join(f"severity eq '{s}'" for s in severities)
                filters.append(f"({sev_clause})")

            body = self._request(
                "GET", "/security/alerts_v2",
                params={
                    "$filter": " and ".join(filters),
                    "$top": ALERTS_PAGE_CAP,
                    "$orderby": "createdDateTime desc",
                },
            )
            api_calls += 1
            page = body.get("value", []) or []
            for alert in page:
                collected[alert.get("id")] = alert

            if len(page) >= ALERTS_PAGE_CAP:
                span = w_end - w_start
                if span <= timedelta(minutes=1):
                    warnings.append(
                        f"Window {_iso(w_start)}..{_iso(w_end)} returned the full "
                        f"{ALERTS_PAGE_CAP}-row cap and cannot be split further; alerts "
                        "in this minute may be missing."
                    )
                else:
                    mid = w_start + span / 2
                    windows.extend([(w_start, mid), (mid, w_end)])

        truncated = len(collected) >= max_rows
        if truncated:
            warnings.append(
                f"Stopped at max_rows={max_rows}; more alerts exist in the window."
            )

        return {
            "count": len(collected),
            "alerts": sorted(collected.values(),
                             key=lambda a: a.get("createdDateTime") or "", reverse=True),
            "window": {"since": _iso(since), "until": _iso(until)},
            "api_calls": api_calls,
            "truncated": truncated,
            "warnings": warnings,
            "note": ("alerts_v2 caps pages at 100 with no @odata.nextLink; this result "
                     "was assembled by time-window subdivision, and `title` was not used "
                     "as a filter because it is not $filter-able."),
        }

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """
        Fetch a single alert, including its evidence array.

        The evidence array is where the answer usually is. In the
        corp-functions-it-spend-tracker case, the alert body identified the cause
        outright — `cloudLogonSession.userAgent: "TruffleHog"` — while the alert title
        alone supported an entirely wrong conclusion.
        """
        self.require_role("alerts_v2")
        alert_id = urllib.parse.quote(alert_id, safe="")
        return self._request("GET", f"/security/alerts_v2/{alert_id}")

    def get_incident(self, incident_id: str, with_alerts: bool = True) -> Dict[str, Any]:
        self.require_role("incidents")
        incident_id = urllib.parse.quote(str(incident_id), safe="")
        params = {"$expand": "alerts"} if with_alerts else None
        return self._request("GET", f"/security/incidents/{incident_id}", params=params)

    def list_sign_ins(self, filter_expr: str, top: int = 100,
                      max_pages: int = 20) -> Dict[str, Any]:
        """
        Read Entra sign-in logs. Follows @odata.nextLink, which this endpoint does supply.

        Retention is 30 days on most licenses (7 for some). Absence of a sign-in beyond
        the retention horizon is not evidence it did not happen — rule 0.5.
        """
        self.require_role("signIns")
        rows: List[Dict[str, Any]] = []
        body = self._request("GET", "/auditLogs/signIns",
                             params={"$filter": filter_expr, "$top": top})
        pages = 1
        rows.extend(body.get("value", []) or [])
        next_link = body.get("@odata.nextLink")
        while next_link and pages < max_pages:
            body = self._request("GET", "", absolute_url=next_link)
            rows.extend(body.get("value", []) or [])
            next_link = body.get("@odata.nextLink")
            pages += 1

        return {
            "count": len(rows),
            "sign_ins": rows,
            "pages": pages,
            "truncated": bool(next_link),
            "filter": filter_expr,
            "note": ("Sign-in log retention is 30 days at most. An empty result bounds "
                     "the retained window only, not all time."),
        }


# =============================================================================
# Helpers
# =============================================================================

def _iso(dt: datetime) -> str:
    """Graph $filter wants an ISO-8601 UTC timestamp with a Z suffix."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_roles(access_token: str) -> List[str]:
    """
    Read the `roles` claim from a JWT without verifying its signature.

    Verification is unnecessary and would be misleading here: the token came directly
    from a TLS connection to login.microsoftonline.com moments ago, and this client is
    not the token's audience. The claim is used to report capability, never to make an
    authorization decision.
    """
    try:
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        return sorted(claims.get("roles", []) or [])
    except Exception as exc:
        logger.warning(f"Could not decode roles from access token: {type(exc).__name__}")
        return []
