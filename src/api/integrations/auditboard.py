"""AuditBoard GRC client — file a scanner finding as a GRC issue.

Differs from the Jira integration in one way that drives the whole design:
AuditBoard has no prefill-a-form URL. Creating an issue is an authenticated
API write, so a credential has to live somewhere. It lives here, server-side,
read from settings and never returned to the browser.

Vocabulary was read from the live instance rather than assumed. Two things
that reference confirms, and that are easy to get wrong:

*   ``issue_rating_id`` is **not** a severity. The values are control-testing
    outcomes — Cleared, Tested - Remains Deficient, New Deficiency, N/A.
    Mapping a code severity onto it produces nonsense.
*   ``deficiency_level_id`` is the severity-shaped field: Recommendation - No
    Deficiency, Control Deficiency, Significant Deficiency, Material Weakness.

"Significant Deficiency" and "Material Weakness" are SOX terms of art. This
module will not assert either from a scanner severity on its own — see
``DEFICIENCY_LEVEL_BY_SEVERITY`` — because a static-analysis hit is evidence
of a control weakness, not a determination of one. The caller may override.
"""

import logging
from typing import Any, Dict, List, Optional

import requests

from ..config import settings

logger = logging.getLogger(__name__)

API_PATH = "/api/v1/issues"

# ---------------------------------------------------------------------------
# Reference vocabularies, read from the live instance.
# Verified against GET /api/v1/deficiency_levels and /api/v1/issue_ratings.
# ---------------------------------------------------------------------------

DEFICIENCY_LEVELS: Dict[int, str] = {
    1: "Recommendation - No Deficiency",
    2: "Control Deficiency",
    3: "Significant Deficiency",
    4: "Material Weakness",
    5: "TBD",
    6: "N/A",
}

# Control-testing outcomes. Recorded so nobody maps severity onto them again.
ISSUE_RATINGS: Dict[int, str] = {
    1: "Cleared",
    2: "Tested - Insufficient Sample",
    3: "Tested - Remains Deficient",
    4: "Not Tested - Management Remediated",
    5: "Remediation In Progress",
    6: "New Deficiency",
    7: "TBD",
    8: "N/A",
    9: "Closed",
}

# Our severity ramp onto deficiency levels.
#
# Deliberately conservative at the top: critical and high both land on
# "Control Deficiency". Escalation to Significant Deficiency or Material
# Weakness is a judgement a person makes with business context, not something
# a Semgrep rule earns automatically. Pass ``deficiency_level_id`` explicitly
# to go higher.
DEFICIENCY_LEVEL_BY_SEVERITY: Dict[str, int] = {
    "critical": 2,
    "high": 2,
    "medium": 2,
    "low": 1,
    "info": 1,
}

# How the issue was identified. 7 is "Other", the honest answer for a scanner:
# this was not found by Internal Audit, External Audit or Management.
# Verified against GET /api/v1/issue_idents.
ISSUE_IDENTS: Dict[int, str] = {
    4: "Internal Audit",
    5: "External Audit",
    6: "Management",
    7: "Other",
    8: "TBD",
    9: "N/A",
    10: "IT - Infrastructure",
}
DEFAULT_ISSUE_IDENT_ID = 7

# Statuses this instance actually uses, counted over the whole issues
# collection (28,644 records, paged through) rather than a first page:
#
#   Closed 22,940 · Inactive 2,232 · Pending Remediation 1,643 · Open 1,488
#   Remediated 248 · Canceled 93
#
# An earlier version of this set held only Open, Closed and Remediated and said
# those were the only values across 918 issues. Both figures were wrong: the
# page[number] parameter was being ignored, so the same first page was counted
# repeatedly and three quarters of the vocabulary never appeared.
#
# "Draft" is still not a status here, and sending one that does not exist is
# answered with a bare HTTP 500 that names nothing.
ISSUE_STATUSES = {
    "Open",
    "Closed",
    "Remediated",
    "Pending Remediation",
    "Inactive",
    "Canceled",
}

# The Executive Summary field, in API terms.
#
# AuditBoard exposes it as a generic custom text column; the label is applied
# by the form, not the API. Category 10's form (template 1083) places
# ``issue:customText4`` with the tooltip "Consumable summary of finding for
# stakeholders, less than 30 characters", and category 10 lists ``customText4``
# among its required-at-Open fields. Read attribute is ``custom_text4``.
#
# 30 characters is the form's guidance, not a server limit — existing values in
# the register run to 90-plus. So it is reported to the UI as a target, and the
# hard cap below is the one that actually truncates.
EXECUTIVE_SUMMARY_FIELD = "custom_text4"
EXECUTIVE_SUMMARY_TARGET = 30
MAX_EXECUTIVE_SUMMARY = 255

# Fields category 10 declares required to sit at status Open, read from
# ``issue_required_fields`` on GET /api/v1/issue_categories.
#
# The API enforces none of them: an issue created without a senior owner, a
# vice president or an identified date is accepted and stored. It just is not a
# complete register entry afterwards, which is how an issue can be filed under
# the right category and still not read as one of its records. Recorded here so
# the gap is visible in code rather than discovered in the UI.
CATEGORY_10_REQUIRED_AT_OPEN = (
    "title",
    "description",
    "customText4",
    "seniorOwnerUser",
    "vicePresidentUser",
    "identifiedDate",
)

# Issue categories that hold a standalone issue.
#
# The deciding attribute is an empty ``key``. A category with a key is bound
# to a source object — "compliance", "bcm", "regulatory-compliance-regulation-
# item" — and an issue filed under it is expected to point at one. A scanner
# finding has no AuditBoard test, control or risk behind it, so only a keyless
# category fits. Verified against GET /api/v1/issue_categories, and confirmed
# by creating issue I#1714 under 11: the server set type="standalone" and left
# issuesourceable_type null on its own.
#
# An earlier version of this list included 5, 15 and 18. That was wrong — all
# three carry a key and expect a source.
STANDALONE_CATEGORY_IDS: Dict[int, str] = {
    11: "IT Risk Exception",
    12: "IT Infrastructure Exception",
}

# Categories that are bound to a source object, and the object type each one
# expects in ``issuesourceable_type``.
#
# A keyed category is not unusable — it just needs to be told what the issue
# hangs off. Category 10 "IT Risk Issue" carries key "it-risk-mitigation-plan"
# and every one of the 427 issues already filed under it points at a Risk:
# ``issuesourceable_type: "Risk"`` with a risk ID, and the server still reports
# ``type: "standalone"`` on the result. So the key describes the register the
# category belongs to, not a requirement that the issue come from a test run.
#
# Read from the live instance rather than assumed: GET /api/v1/issue_categories
# for the keys, and the existing category-10 population for the source type.
# Only entries verified that way belong here.
SOURCE_BACKED_CATEGORIES: Dict[int, Dict[str, str]] = {
    10: {"name": "IT Risk Issue", "source_type": "Risk"},
}

MAX_TITLE = 500
MAX_DESCRIPTION = 30000


class AuditBoardError(RuntimeError):
    """Raised when AuditBoard rejects a request or is not configured."""


class AuditBoardClient:
    """Thin client over the AuditBoard issues API."""

    def __init__(self) -> None:
        self.url = (settings.AUDITBOARD_URL or "").rstrip("/")
        self.token = settings.AUDITBOARD_TOKEN or ""
        self.category_id = settings.AUDITBOARD_ISSUE_CATEGORY_ID or 0
        self.create_status = settings.AUDITBOARD_CREATE_STATUS or "Open"
        self.ca_bundle = settings.AUDITBOARD_CA_BUNDLE or ""
        self.ident_id = settings.AUDITBOARD_ISSUE_IDENT_ID or DEFAULT_ISSUE_IDENT_ID
        self.source_id = settings.AUDITBOARD_ISSUE_SOURCE_ID or 0
        self.workspace_id = settings.AUDITBOARD_WORKSPACE_ID or 0
        # AuditBoard user IDs stamped on every issue we file. Category 10
        # requires a senior owner and a vice president at status Open, and
        # neither is derivable from an AuditGitHub login — the two systems
        # share no identity. Unset means the field is omitted, which files an
        # incomplete register entry rather than failing.
        self.senior_owner_user_id = settings.AUDITBOARD_SENIOR_OWNER_USER_ID or 0
        self.vice_president_user_id = settings.AUDITBOARD_VICE_PRESIDENT_USER_ID or 0
        self.tester_user_id = settings.AUDITBOARD_TESTER_USER_ID or 0
        self.reviewer_user_id = settings.AUDITBOARD_REVIEWER_USER_ID or 0

    @property
    def source_type(self) -> Optional[str]:
        """The ``issuesourceable_type`` this category needs, if it needs one."""
        spec = SOURCE_BACKED_CATEGORIES.get(self.category_id)
        return spec["source_type"] if spec else None

    @property
    def category_name(self) -> Optional[str]:
        if self.category_id in STANDALONE_CATEGORY_IDS:
            return STANDALONE_CATEGORY_IDS[self.category_id]
        spec = SOURCE_BACKED_CATEGORIES.get(self.category_id)
        return spec["name"] if spec else None

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.token and self.category_id)

    def config_problem(self) -> Optional[str]:
        """Why the client cannot be used, in words a UI can show."""
        if not self.url:
            return "AUDITBOARD_URL is not set"
        if not self.token:
            return "AUDITBOARD_TOKEN is not set"
        if not self.category_id:
            return "AUDITBOARD_ISSUE_CATEGORY_ID is not set"
        known = set(STANDALONE_CATEGORY_IDS) | set(SOURCE_BACKED_CATEGORIES)
        if self.category_id not in known:
            # Not "this category is invalid" — it is a category nobody has
            # verified a create against. Filing blind into a GRC register is
            # how you get a record you cannot delete.
            return (
                f"Issue category {self.category_id} has not been verified for "
                "filing from this app. Verified categories: "
                + ", ".join(
                    f"{k} {v}" for k, v in sorted(STANDALONE_CATEGORY_IDS.items())
                )
                + ", "
                + ", ".join(
                    f"{k} {v['name']} (needs AUDITBOARD_ISSUE_SOURCE_ID)"
                    for k, v in sorted(SOURCE_BACKED_CATEGORIES.items())
                )
            )
        if self.source_type and not self.source_id:
            spec = SOURCE_BACKED_CATEGORIES[self.category_id]
            return (
                f"Issue category {self.category_id} ({spec['name']}) attaches "
                f"each issue to a {spec['source_type']} record, and "
                "AUDITBOARD_ISSUE_SOURCE_ID is not set. Set it to the "
                f"{spec['source_type'].lower()} ID these findings belong under."
            )
        if self.create_status not in ISSUE_STATUSES:
            return (
                f"AUDITBOARD_CREATE_STATUS={self.create_status!r} is not a status "
                "on this instance. Accepted: " + ", ".join(sorted(ISSUE_STATUSES))
            )
        if not self.ca_bundle:
            return (
                "AUDITBOARD_CA_BUNDLE is not set — refusing to send a bearer "
                "token over a connection that cannot be verified"
            )
        return None

    # -- transport ---------------------------------------------------------

    def _verify(self):
        """TLS verification target.

        Egress to this host takes one of two paths depending on the moment:
        intercepted by Zscaler, which presents its own chain, or direct to
        AWS, which presents Amazon's. The "Basic Constraints of CA cert not
        marked critical" failure that sec-diligence worked around with
        ``verify=False`` is the Zscaler chain. The bundle therefore carries a
        real trust store plus the Zscaler root.

        Switching verification off is not the fix: the request carries a
        bearer token, and an unverified connection means anything in path can
        read it. Note that Zscaler terminates TLS, so the token is already
        readable by that infrastructure — verification protects it from
        everyone else, which is the part still worth having.
        """
        if not self.ca_bundle:
            raise AuditBoardError(
                "AUDITBOARD_CA_BUNDLE is not set. Refusing to transmit the "
                "AuditBoard token without verifying the server certificate."
            )
        return self.ca_bundle

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # -- payload -----------------------------------------------------------

    def build_payload(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        deficiency_level_id: Optional[int] = None,
        status: Optional[str] = None,
        executive_summary: Optional[str] = None,
        identified_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Assemble the create body. Pure — safe to show a user before sending.

        Verified against the live instance on 2026-09-15 by creating and then
        closing issue I#1714. Three things the API does not document publicly
        and that a wrong guess returns a bare HTTP 500 for:

        *   ``issuesourceable_type`` is never the literal "standalone".
            ``type: "standalone"`` is something the server reports, not
            something you ask for, and sending it as a sourceable type is
            rejected with no explanation. For a keyless category (11, 12) the
            sourceable fields are omitted entirely and the server leaves them
            null. For a keyed category they name a real record — "Risk" and a
            risk ID for category 10 — which is how the 427 issues already in
            that category are shaped.
        *   ``status`` must be one of this instance's real statuses, listed in
            :data:`ISSUE_STATUSES`. "Draft" is not one of them.
        *   ``issue_ident_id`` records how the issue was identified. 7 is
            "Other", which is the honest answer for a scanner.

        ``identified_date`` can only be set here, at create. Verified on
        2026-09-16: a PUT of that one field onto an existing issue is refused
        with ``issue:action.editDraft``, while ``custom_text4`` and the four
        user stamps all accept a single-field PUT under this token. So a
        filing that goes out without a date cannot be corrected later by this
        integration — it needs someone with edit rights in the UI.

        The body is wrapped by :meth:`create_issue`, not here, so what this
        returns is exactly the field set a reviewer sees.
        """
        level = deficiency_level_id or DEFICIENCY_LEVEL_BY_SEVERITY.get(
            (severity or "").lower(), 1
        )
        if level not in DEFICIENCY_LEVELS:
            raise AuditBoardError(f"Unknown deficiency_level_id: {level}")

        status = status or self.create_status
        if status not in ISSUE_STATUSES:
            raise AuditBoardError(
                f"Unknown status {status!r}. This instance accepts: "
                + ", ".join(sorted(ISSUE_STATUSES))
            )

        payload: Dict[str, Any] = {
            "title": (title or "Untitled finding")[:MAX_TITLE],
            "description": (description or "")[:MAX_DESCRIPTION],
            "status": status,
            "issue_category_id": self.category_id,
            "issue_ident_id": self.ident_id,
            "deficiency_level_id": level,
        }
        if self.source_type and self.source_id:
            payload["issuesourceable_type"] = self.source_type
            payload["issuesourceable_id"] = self.source_id

        # Executive Summary. Required by category 10 and blank on everything
        # this app has filed so far, which is the difference between an issue
        # in the register and an issue a reader of the register can use.
        summary = (executive_summary or "").strip()
        if summary:
            payload[EXECUTIVE_SUMMARY_FIELD] = summary[:MAX_EXECUTIVE_SUMMARY]

        if identified_date:
            payload["identified_date"] = identified_date

        # Stamped only when configured. An issue with the wrong executive on
        # it is worse than one with none: it routes work to someone who never
        # agreed to own it.
        for field, value in (
            ("senior_owner_user_id", self.senior_owner_user_id),
            ("vice_president_user_id", self.vice_president_user_id),
            ("tester_user_id", self.tester_user_id),
            ("reviewer_user_id", self.reviewer_user_id),
        ):
            if value:
                payload[field] = value

        return payload

    # -- calls -------------------------------------------------------------

    def create_issue(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST a new issue. Returns the created issue as AuditBoard reports it."""
        problem = self.config_problem()
        if problem:
            raise AuditBoardError(problem)

        endpoint = f"{self.url}{API_PATH}"
        try:
            resp = requests.post(
                endpoint,
                # Rails-style root key. An unwrapped body is answered with a
                # bare HTTP 500 that names nothing. The API advertises the key
                # itself in every list response: meta.resourceNames.camelized.
                json={"issue": payload},
                headers=self._headers(),
                verify=self._verify(),
                timeout=30,
            )
        except requests.RequestException as exc:
            logger.error("AuditBoard request failed: %s", exc)
            raise AuditBoardError(f"AuditBoard request failed: {exc}") from exc

        if resp.status_code >= 400:
            # Body can name the rejected field, which is the whole value of
            # the message. It does not echo the token.
            detail = resp.text[:500]
            logger.warning(
                "AuditBoard rejected issue creation (%s): %s", resp.status_code, detail
            )
            raise AuditBoardError(
                f"AuditBoard returned {resp.status_code}: {detail}"
            )

        body = resp.json() if resp.content else {}
        # Create answers with the same envelope as a list: {"issues": [ ... ]}.
        issues = body.get("issues") if isinstance(body, dict) else None
        if isinstance(issues, list) and issues:
            return issues[0]
        if isinstance(body, dict):
            return body.get("issue") or body
        return {}

    def issue_url(self, issue_id: Any) -> Optional[str]:
        """Human-facing link to an issue, for reporting back to the filer.

        The path is ``/workspace/{n}/issues/issue/{id}``, confirmed from a
        working browser URL. An earlier version emitted ``/issues/{id}``,
        which looked fine because AuditBoard is a single-page app — every
        path returns HTTP 200 and the router sorts it out client-side, so a
        wrong link cannot be caught by fetching it.

        The workspace number is configuration rather than something derived.
        It is not in the API: ``/api/v1/workspaces`` lists three workspaces
        and excludes this one by type, ``filter[id]=5`` comes back empty, and
        neither the issue nor its source risk carries a workspace field.

        Returns None when the workspace is unset. A link that goes to the
        wrong place is worse than a badge with no link, because the reader
        cannot tell the difference until they are looking at someone else's
        issue.
        """
        if not self.url or issue_id in (None, "") or not self.workspace_id:
            return None
        return f"{self.url}/workspace/{self.workspace_id}/issues/issue/{issue_id}"

    def unstamped_required_fields(self) -> List[str]:
        """Category-required fields this app cannot fill from configuration.

        Not an error — filing succeeds without them, because the API enforces
        none of the category's required-field list. It is a completeness
        warning, so whoever files knows the record will need finishing by hand
        in AuditBoard rather than discovering it in a register review later.

        ``customText4`` is not listed: it comes from the filer per issue, not
        from configuration, so it is checked at filing time instead.
        """
        if self.category_id != 10:
            return []
        missing = []
        if not self.senior_owner_user_id:
            missing.append("seniorOwnerUser")
        if not self.vice_president_user_id:
            missing.append("vicePresidentUser")
        return missing

    def reference_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Vocabularies a UI needs to let a person override the mapping."""
        return {
            "issue_statuses": sorted(ISSUE_STATUSES),
            "deficiency_levels": [
                {"id": k, "name": v} for k, v in sorted(DEFICIENCY_LEVELS.items())
            ],
            "standalone_categories": [
                {"id": k, "name": v} for k, v in sorted(STANDALONE_CATEGORY_IDS.items())
            ],
            "source_backed_categories": [
                {"id": k, "name": v["name"], "source_type": v["source_type"]}
                for k, v in sorted(SOURCE_BACKED_CATEGORIES.items())
            ],
            "issue_idents": [
                {"id": k, "name": v} for k, v in sorted(ISSUE_IDENTS.items())
            ],
        }


auditboard_client = AuditBoardClient()
