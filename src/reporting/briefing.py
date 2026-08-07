"""
Three-part report structure: Situation, Action Plan, Evidence.

Why the shape
-------------
The reader of these reports is one person wearing several hats, not three people. They
open the document three times, with a different question each time:

    1. "My boss is asking me about this."      -> Part 1, Situation
    2. "What do I actually do, and first?"     -> Part 2, Action Plan
    3. "Engineering wants proof and targets."  -> Part 3, Evidence

So the document is ordered by *question*, not by audience, and each part is complete on
its own — a reader who stops after Part 1 has a true, if coarse, picture, and a reader
who forwards only Part 2 has not forwarded something unsupported.

The split of labour
-------------------
Two things in Parts 1 and 2 are judgement, and one is arithmetic. They are separated
deliberately, because the failure modes differ:

    Ordering      -> code.  `rank_actions` is a pure function of severity and blast
                     radius. Priority is the actionable content of Part 2, and a
                     priority list that reshuffles between renders is not a plan.
    Numbers       -> code.  Every figure is substituted into the prose from
                     `metrics()`. The model is forbidden from emitting digits at all
                     (`_REJECT_DIGITS`), and prose containing one is rejected. A summary
                     that misstates a count is worse than no summary, because it is
                     confidently wrong in the one section a non-technical reader trusts.
    Phrasing      -> the model.  It writes the bottom line, the situation paragraphs and
                     the per-action rationale, from the ranked findings.

Every model-authored claim carries `refs` naming the findings it rests on; unknown refs
are rejected. If the model is unavailable, returns malformed output, or fails validation
twice, `author_briefing` falls back to `deterministic_briefing`. Report generation never
fails because an LLM was down — it degrades to plainer words and says so in the document.

Determinism
-----------
The briefing is authored once, upstream, and persisted into the payload. Rendering stays
a pure function of that payload, so re-exporting a report reproduces it byte for byte.
This module is the "may help author the Markdown upstream, where its output is diffable"
case that `md_to_pdf`'s docstring allows; nothing here runs between the Markdown and the
page.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .mdwrite import md_table, md_text

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Ranking model
# --------------------------------------------------------------------------- #

# Severity carries most of the weight, but not all of it: the gap between critical and
# high is deliberately larger than the gap between high and medium, so a single critical
# outranks a pile of highs rather than being averaged away by volume.
_SEVERITY_WEIGHT = {
    "critical": 100.0,
    "high": 60.0,
    "medium": 25.0,
    "low": 8.0,
    "info": 2.0,
}
_UNKNOWN_SEVERITY_WEIGHT = 25.0  # treated as medium; never dropped

# Blast radius. Severity alone ranks badly — a critical in an archived repository
# outranks nothing, while a high in a repository that ships to production outranks it.
# Archived is damped, not zeroed: a leaked credential in an archived repository is still
# a live credential.
_REACH_MULTIPLIER = {
    "production": 3.0,
    "internal": 1.5,
    "development": 1.0,
    "archived": 0.6,
    "unknown": 1.0,
}

_WAVE_IMMEDIATE = "Immediate"
_WAVE_THIS_WEEK = "This week"
_WAVE_PLANNED = "Planned"

# Score floors for the two upper waves. A critical is promoted to Immediate regardless
# of reach: reach may raise urgency but is not allowed to argue a critical down, because
# the reach signal is itself inferred and is the less trustworthy of the two inputs.
_IMMEDIATE_FLOOR = 150.0
_THIS_WEEK_FLOOR = 50.0

_WAVE_ORDER = {_WAVE_IMMEDIATE: 0, _WAVE_THIS_WEEK: 1, _WAVE_PLANNED: 2}

_WAVE_GUIDANCE = {
    _WAVE_IMMEDIATE: "Start today. Do not wait for a change window.",
    _WAVE_THIS_WEEK: "Schedule inside the current week.",
    _WAVE_PLANNED: "Put on the backlog with an owner and a date.",
}


# --------------------------------------------------------------------------- #
# Effort: a second axis, never folded into the first
# --------------------------------------------------------------------------- #

# Effort is what the work costs; risk is what the problem costs. They are kept apart on
# purpose. Multiplying them into one number would let a two-week fix rank below a
# five-minute one of the same severity, which is how genuinely urgent and genuinely hard
# work ends up at the bottom of a list and stays there. Effort is therefore displayed,
# and used only to order items *within* a deadline band.
_EFFORT_BANDS = ("S", "M", "L", "XL")
_EFFORT_RANK = {band: index for index, band in enumerate(_EFFORT_BANDS)}

_EFFORT_TIME = {
    "S": "under a day, one engineer",
    "M": "a few days, one engineer",
    "L": "one to two weeks, a small team",
    "XL": "over two weeks, cross-team",
}

# Matched against the finding title, detail and recorded mitigation. Ordered most
# expensive first, because a finding that needs both a version pin and an estate-wide
# credential rotation costs the rotation, not the pin.
_EFFORT_SIGNALS: Tuple[Tuple[str, "re.Pattern[str]", str], ...] = (
    ("XL", re.compile(
        r"\b(re-?platform|re-?architect|migrat\w+|redesign|replace the|rewrite|"
        r"estate[- ]wide|every repositor|all repositor|org(anization)?[- ]wide)\b",
        re.IGNORECASE), "architecture or estate-wide change"),
    ("L", re.compile(
        r"\b(rotate|revoke|re-?issue|credential|secret|token|key material|"
        r"self-?hosted runner|access review|permission model|network|firewall|egress)\b",
        re.IGNORECASE), "credential or infrastructure work"),
    ("M", re.compile(
        r"\b(patch|refactor|code change|rebuild|redeploy|pipeline|workflow|"
        r"by hand|manual\w*|triage|confirm or clear|investigat\w+)\b",
        re.IGNORECASE), "code change or hands-on review"),
    ("S", re.compile(
        r"\b(pin|bump|upgrade|update the version|config\w*|setting|flag|allowlist entry|"
        r"add to \.gitignore|remove the file)\b",
        re.IGNORECASE), "version or configuration change"),
)

# What the work needs, so a manager can staff it before reading Part 3. Keyed the same
# way as the effort signals but reported separately: cost and capability are different
# questions, and a cheap change that needs an access nobody on the team holds is not
# cheap.
_CAPABILITY_SIGNALS: Tuple[Tuple["re.Pattern[str]", str], ...] = (
    (re.compile(r"\b(rotate|revoke|credential|secret|token|key material)\b", re.I),
     "secret store access, identity admin"),
    (re.compile(r"\b(runner|pipeline|workflow|ci/?cd|build agent|redeploy|rebuild)\b", re.I),
     "CI/CD admin, deploy window"),
    (re.compile(r"\b(pin|bump|upgrade|dependenc|package|npm|pypi|sbom)\b", re.I),
     "package owner, dependency rebuild"),
    (re.compile(r"\b(network|firewall|egress|allowlist|proxy)\b", re.I),
     "network engineering change"),
    (re.compile(r"\b(endpoint|device|host|edr|telemetry|quarantine)\b", re.I),
     "endpoint tooling access"),
    (re.compile(r"\b(review by hand|manual|triage|confirm or clear)\b", re.I),
     "engineer familiar with the repository"),
)

# Group size escalates effort: the same fix across many resources is a different job.
_GROUP_ESCALATION = ((10, 2), (3, 1))  # (>= this many findings, raise this many bands)


class BriefingRejected(ValueError):
    """Model output failed validation. Carries the reason, which is fed back on retry."""


@dataclass
class Finding:
    """
    One thing that is wrong, normalised across report types.

    `id` is what Parts 1 and 2 cite and what Part 3 anchors, so it must be stable for a
    given payload. `reach` is optional and defaults to "unknown" rather than to a guess:
    an unknown blast radius must not silently rank as a small one.
    """

    id: str
    title: str
    severity: str = "medium"
    resource: str = ""
    detail: str = ""
    reach: str = "unknown"
    mitigation: str = ""
    evidence: str = ""
    effort: str = ""  # explicit S/M/L/XL from the payload; inferred when blank

    @property
    def normalised_severity(self) -> str:
        value = (self.severity or "").strip().lower()
        return value if value in _SEVERITY_WEIGHT else "unknown"

    @property
    def score(self) -> float:
        weight = _SEVERITY_WEIGHT.get(self.normalised_severity, _UNKNOWN_SEVERITY_WEIGHT)
        reach = (self.reach or "unknown").strip().lower()
        return weight * _REACH_MULTIPLIER.get(reach, 1.0)

    @property
    def effort_band(self) -> str:
        """S/M/L/XL for this finding alone, before any group escalation."""
        explicit = (self.effort or "").strip().upper()
        if explicit in _EFFORT_RANK:
            return explicit
        return estimate_effort(self)[0]


def _effort_haystack(finding: Finding) -> str:
    return " ".join((finding.title, finding.detail, finding.mitigation))


def estimate_effort(finding: Finding) -> Tuple[str, str]:
    """
    Infer (band, why) for one finding from the work its mitigation describes.

    Returns "M" with an explicit "not estimated" note when nothing matches, rather than
    "S". An unestimated job guessed as cheap is the estimate that wrecks a plan; guessed
    as mid it is merely wrong, and the note tells the reader which it is.
    """
    explicit = (finding.effort or "").strip().upper()
    if explicit in _EFFORT_RANK:
        return explicit, "as recorded in the finding"
    haystack = _effort_haystack(finding)
    for band, pattern, why in _EFFORT_SIGNALS:
        if pattern.search(haystack):
            return band, why
    return "M", "not estimated — assumed mid-range"


def capabilities_for(findings: Sequence[Finding]) -> List[str]:
    """What the work needs, deduplicated and in a stable order."""
    haystack = " ".join(_effort_haystack(f) for f in findings)
    needs = [label for pattern, label in _CAPABILITY_SIGNALS if pattern.search(haystack)]
    return needs or ["engineer familiar with the resource"]


def _raise_band(band: str, steps: int) -> str:
    return _EFFORT_BANDS[min(_EFFORT_RANK[band] + steps, len(_EFFORT_BANDS) - 1)]


def group_effort(group: Sequence[Finding]) -> Tuple[str, str]:
    """
    Effort for a whole action: the costliest member, escalated by how many there are.

    The same one-line fix applied to fifteen repositories is not a one-line fix; it is a
    coordination problem with a one-line fix inside it.
    """
    if not group:
        return "M", "no findings"
    bands = [(f.effort_band, estimate_effort(f)[1]) for f in group]
    worst_band = max(bands, key=lambda item: _EFFORT_RANK[item[0]])
    band, why = worst_band
    for threshold, steps in _GROUP_ESCALATION:
        if len(group) >= threshold:
            raised = _raise_band(band, steps)
            if raised != band:
                return raised, f"{why}, across {len(group)} findings"
            break
    return band, why


@dataclass
class ActionItem:
    """
    One step in the plan.

    `rank` is global and `wave` is the deadline band, both set by risk. `effort`,
    `effort_note` and `needs` describe the cost of the step and are never allowed to
    change either — they answer "how do I staff this", not "does this matter".
    """

    rank: int
    wave: str
    title: str
    rationale: str = ""
    refs: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    effort: str = "M"
    effort_note: str = ""
    needs: List[str] = field(default_factory=list)
    reach: str = "unknown"

    @property
    def effort_label(self) -> str:
        return f"{self.effort} — {_EFFORT_TIME.get(self.effort, 'unestimated')}"

    @property
    def is_quick_win(self) -> bool:
        """High urgency, low cost: the work to do before the meeting ends."""
        return self.wave == _WAVE_IMMEDIATE and self.effort == "S"


@dataclass
class Briefing:
    """
    Parts 1 and 2 of a report, plus how they were produced.

    `authored_by` is printed in the document. A reader is entitled to know whether the
    summary they are about to repeat to their boss was written by a model or assembled
    by rule, and a degraded fallback that looked identical to the real thing would hide
    exactly the fact that matters.
    """

    bottom_line: str
    situation: List[str]
    actions: List[ActionItem]
    authored_by: str = "deterministic"
    degraded_reason: str = ""


# --------------------------------------------------------------------------- #
# Normalising payloads into findings
# --------------------------------------------------------------------------- #

_PRODUCTION_HINT = re.compile(r"\b(prod|production|live)\b", re.IGNORECASE)
_ARCHIVED_HINT = re.compile(r"\barchiv", re.IGNORECASE)
# Checked before falling back to "internal". Without it the `development` band is
# unreachable from an environment string, so a repository deployed only to a sandbox is
# weighted 1.5x instead of 1.0x and told to the reader as "Internal-facing."
_DEVELOPMENT_HINT = re.compile(r"\b(dev|develop|development|sandbox|local|test|ci)\b",
                               re.IGNORECASE)


def _reach_of(entry: Dict[str, Any]) -> str:
    """
    Classify blast radius from whatever the payload happens to carry.

    Returns "unknown" when nothing in the entry speaks to reach. That value is load
    bearing: `reach_basis()` counts it and prints the count, so a report ranked without
    deployment data says so instead of presenting a confident order built on absence.
    """
    explicit = str(entry.get("reach") or "").strip().lower()
    if explicit in _REACH_MULTIPLIER:
        return explicit
    if entry.get("archived") is True:
        return "archived"

    haystack = " ".join(
        str(v)
        for v in (
            entry.get("environments"),
            entry.get("environment"),
            entry.get("deployment_environments"),
        )
        if v
    )
    if haystack:
        if _PRODUCTION_HINT.search(haystack):
            return "production"
        if _ARCHIVED_HINT.search(haystack):
            return "archived"
        if _DEVELOPMENT_HINT.search(haystack):
            return "development"
        # Anything named but unrecognised: staging, qa, uat, a team's own label. Treated
        # as internal rather than as unknown, because the entry did say where it runs.
        return "internal"
    return "unknown"


def findings_from_zda(payload: Dict[str, Any]) -> List[Finding]:
    """
    Build findings from a zero-day analysis payload.

    Dependency-exposure matches are preferred where present, because they name an exact
    `name@version` in a named repository — a fact an engineer can act on. Repositories
    that appear only as context matches are still emitted, at lower severity, so the
    plan covers everything the report shows rather than only the confirmed part.
    """
    findings: List[Finding] = []
    seen: set = set()

    exposure = ((payload.get("hunt_evidence") or {}).get("hunt_dependency_exposure") or {})
    for index, match in enumerate(exposure.get("matches") or [], 1):
        repo = str(match.get("repository") or "unknown")
        spec = str(match.get("matched_spec") or "")
        findings.append(Finding(
            id=f"E{index}",
            title=f"{spec} present in {repo}" if spec else f"Affected dependency in {repo}",
            severity=str(match.get("severity") or "critical"),
            resource=repo,
            detail=(
                f"Declared as {match.get('declared_version') or 'unspecified'}; "
                f"exposure classified {match.get('exposure') or 'unclassified'}."
            ),
            reach=_reach_of(match),
            mitigation=(
                f"Pin {spec.split('@')[0]} away from the affected version, rebuild, and "
                "redeploy. Rotate any credential the build had access to."
                if spec else
                "Remove the affected dependency version and rotate build credentials."
            ),
            evidence="Dependency exposure query against collected SBOM records.",
            effort=str(match.get("effort") or ""),
        ))
        seen.add(repo)

    for index, repo_entry in enumerate(payload.get("affected_repositories") or [], 1):
        repo = str(repo_entry.get("repository") or "unknown")
        if repo in seen:
            continue
        findings.append(Finding(
            id=f"C{index}",
            title=f"{repo} matched the hunt criteria",
            severity=str(repo_entry.get("severity") or "medium"),
            resource=repo,
            detail=str(repo_entry.get("reason") or "Context match"),
            reach=_reach_of(repo_entry),
            mitigation=(
                "Confirm or clear this repository by hand: a context match is a reason "
                "to look, not a finding."
            ),
            evidence=f"Source: {repo_entry.get('source') or 'unspecified'}.",
            effort=str(repo_entry.get("effort") or ""),
        ))

    return findings


def findings_from_scan(scan_findings: Iterable[Dict[str, Any]]) -> List[Finding]:
    """Build findings from scanner output (title / severity / file_path / description)."""
    result: List[Finding] = []
    for index, raw in enumerate(scan_findings or [], 1):
        location = str(raw.get("file_path") or "")
        line = raw.get("line_number")
        if location and line:
            location = f"{location}:{line}"
        result.append(Finding(
            id=f"S{index}",
            title=str(raw.get("title") or "Untitled finding"),
            severity=str(raw.get("severity") or "medium"),
            resource=location,
            detail=str(raw.get("description") or ""),
            reach=_reach_of(raw),
            mitigation=str(raw.get("remediation") or raw.get("recommendation") or ""),
            evidence=str(raw.get("evidence") or ""),
            effort=str(raw.get("effort") or ""),
        ))
    return result


# --------------------------------------------------------------------------- #
# Arithmetic: counts and ranking, both code-owned
# --------------------------------------------------------------------------- #

def severity_counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {name: 0 for name in _SEVERITY_WEIGHT}
    counts["unknown"] = 0
    for finding in findings:
        counts[finding.normalised_severity] += 1
    return counts


def reach_basis(findings: Sequence[Finding]) -> Tuple[int, int]:
    """Return (findings with a known blast radius, total). Printed, not hidden."""
    known = sum(1 for f in findings if (f.reach or "unknown").lower() != "unknown")
    return known, len(findings)


def _wave_for(finding: Finding) -> str:
    if finding.normalised_severity == "critical":
        return _WAVE_IMMEDIATE
    score = finding.score
    if score >= _IMMEDIATE_FLOOR:
        return _WAVE_IMMEDIATE
    if score >= _THIS_WEEK_FLOOR:
        return _WAVE_THIS_WEEK
    return _WAVE_PLANNED


def rank_actions(findings: Sequence[Finding]) -> List[ActionItem]:
    """
    Turn findings into a priority-ordered plan. Pure, and deliberately so.

    Findings that share a resource are merged into one action: a reader asked to fix
    the same repository in three separate numbered steps will do it once and mark two
    steps as duplicates, which is how a plan loses its meaning.
    """
    grouped: Dict[str, List[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.resource or finding.title, []).append(finding)

    action_scores: Dict[int, float] = {}

    buckets: List[Tuple[float, str, List[Finding]]] = []
    for resource, group in grouped.items():
        top = max(group, key=lambda f: f.score)
        # Additional findings on the same resource add urgency, with diminishing
        # returns, so ten lows never overtake one critical.
        score = top.score + sum(sorted((f.score for f in group), reverse=True)[1:]) * 0.25
        buckets.append((score, resource, group))

    # Sorted by score, then resource name: without the tiebreak, equal-scoring items
    # would order by dict insertion and the plan would drift between runs.
    buckets.sort(key=lambda item: (-item[0], item[1]))

    actions: List[ActionItem] = []
    for rank, (score, resource, group) in enumerate(buckets, 1):
        top = max(group, key=lambda f: f.score)
        band, note = group_effort(group)
        actions.append(ActionItem(
            rank=rank,
            wave=_wave_for(top),
            title=_action_title(resource, group),
            refs=[f.id for f in sorted(group, key=lambda f: -f.score)],
            resources=[resource] if resource else [],
            effort=band,
            effort_note=note,
            needs=capabilities_for(group),
            reach=top.reach or "unknown",
        ))
        # Stashed for the sort below; risk decides the wave, effort only orders inside it.
        action_scores[id(actions[-1])] = score

    # Wave first (risk), then cost, then risk again, then name. Ordering the cheap work
    # first inside a band is the one place effort is allowed to move anything: two items
    # that must both be done today are better done cheapest-first, because the board
    # clears while the expensive one is still being staffed. Across bands it changes
    # nothing — a two-week critical still outranks a five-minute medium.
    actions.sort(key=lambda a: (
        _WAVE_ORDER.get(a.wave, 9),
        _EFFORT_RANK.get(a.effort, 1),
        -action_scores.get(id(a), 0.0),
        a.title,
    ))
    for position, action in enumerate(actions, 1):
        action.rank = position
    return actions


def _action_title(resource: str, group: Sequence[Finding]) -> str:
    """
    A step's title, which must name what to touch.

    Part 2 has no separate target column — six columns is the practical limit in portrait
    — so the target has to be here. Finding titles from a hunt already carry it ("keyv@4.5.4
    present in org/a") but scanner titles do not ("Hardcoded key"), and a plan whose first
    row says only "Resolve: Hardcoded key" cannot be assigned to anyone.
    """
    if len(group) == 1:
        title = group[0].title
        if resource and resource not in title:
            return f"Resolve: {title} ({resource})"
        return f"Resolve: {title}"
    worst = max(group, key=lambda f: f.score).normalised_severity
    return f"Resolve {len(group)} findings in {resource} (worst: {worst})"


# --------------------------------------------------------------------------- #
# Metrics: every number the prose is allowed to contain
# --------------------------------------------------------------------------- #

def metrics(findings: Sequence[Finding], payload: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    The complete set of placeholder values available to authored prose.

    The model writes `{critical}`, never "3". Substitution happens here, so a figure in
    a report is by construction a figure this function computed.
    """
    payload = payload or {}
    counts = severity_counts(findings)
    known_reach, total = reach_basis(findings)
    resources = {f.resource for f in findings if f.resource}
    production = {f.resource for f in findings if (f.reach or "").lower() == "production"}
    actions = rank_actions(findings)

    return {
        "critical": str(counts["critical"]),
        "high": str(counts["high"]),
        "medium": str(counts["medium"]),
        "low": str(counts["low"]),
        "info": str(counts["info"]),
        "unknown_severity": str(counts["unknown"]),
        "total_findings": str(total),
        "critical_and_high": str(counts["critical"] + counts["high"]),
        "affected_resources": str(len(resources)),
        "production_resources": str(len(production)),
        "reach_known": str(known_reach),
        "immediate_actions": str(sum(1 for a in actions if a.wave == _WAVE_IMMEDIATE)),
        "total_actions": str(len(actions)),
        "coverage_gaps": str(len(payload.get("coverage_notes") or [])),
        "quick_wins": str(sum(1 for a in actions if a.is_quick_win)),
        "small_effort_actions": str(sum(1 for a in actions if a.effort == "S")),
        "large_effort_actions": str(sum(1 for a in actions if a.effort in ("L", "XL"))),
        "capabilities_needed": str(len({need for a in actions for need in a.needs})),
    }


# --------------------------------------------------------------------------- #
# Validation: what the model is not allowed to do
# --------------------------------------------------------------------------- #

_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
_REJECT_DIGITS = re.compile(r"\d")


def verify_prose(text: str, allowed: Dict[str, str], *, where: str) -> None:
    """
    Reject authored prose that states a number or cites an unknown quantity.

    Digits are refused outright rather than checked against the data, because checking
    would mean parsing natural language for claims — the placeholder rule is the same
    guarantee obtained by construction.
    """
    for name in _PLACEHOLDER.findall(text):
        if name not in allowed:
            raise BriefingRejected(
                f"{where}: unknown placeholder {{{name}}}. "
                f"Available: {', '.join(sorted(allowed))}"
            )
    stripped = _PLACEHOLDER.sub("", text)
    if _REJECT_DIGITS.search(stripped):
        raise BriefingRejected(
            f"{where}: contains a literal digit. Every quantity must be a placeholder "
            f"such as {{critical}} or {{affected_resources}}."
        )


def verify_refs(refs: Sequence[str], known: Sequence[str], *, where: str) -> None:
    unknown = [r for r in refs if r not in known]
    if unknown:
        raise BriefingRejected(
            f"{where}: cites finding id(s) that do not exist: {', '.join(unknown)}"
        )


def _substitute(text: str, values: Dict[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)), text)


# --------------------------------------------------------------------------- #
# Deterministic authoring: the floor, and the fallback
# --------------------------------------------------------------------------- #

def _plural(count: str, singular: str, plural: str) -> str:
    return singular if count == "1" else plural


def _verb(count: str, singular: str, plural: str) -> str:
    """
    Verb agreeing with a count, where the noun beside it stays plural.

    "1 of the affected systems **reaches** production" — the noun is plural because of
    "of the", the verb is singular because of the one. `_plural` gets this wrong when
    used for both at once.
    """
    return singular if count == "1" else plural


def deterministic_briefing(
    findings: Sequence[Finding],
    payload: Optional[Dict[str, Any]] = None,
    *,
    reason: str = "",
) -> Briefing:
    """
    Assemble Parts 1 and 2 by rule. Correct, reproducible, and plainly mechanical.

    This is both the no-AI configuration and the fallback, and it is written to be
    genuinely readable rather than to be a placeholder — a reader hitting the fallback
    should get a usable briefing, not a notice that they did not get one.
    """
    payload = payload or {}
    values = metrics(findings, payload)
    actions = rank_actions(findings)
    total = int(values["total_findings"])
    critical_high = int(values["critical_and_high"])

    if total == 0:
        bottom_line = (
            "Nothing requiring action was found in what this review was able to examine."
        )
    elif critical_high:
        bottom_line = (
            f"{values['critical_and_high']} "
            f"{_plural(values['critical_and_high'], 'issue needs', 'issues need')} "
            f"attention now, across {values['affected_resources']} "
            f"{_plural(values['affected_resources'], 'system', 'systems')}."
        )
    else:
        bottom_line = (
            f"{values['total_findings']} "
            f"{_plural(values['total_findings'], 'issue was', 'issues were')} found. "
            "None is urgent, but all need an owner."
        )

    situation: List[str] = []
    if total:
        situation.append(
            f"A security review of {values['affected_resources']} "
            f"{_plural(values['affected_resources'], 'system', 'systems')} found "
            f"{values['total_findings']} "
            f"{_plural(values['total_findings'], 'issue', 'issues')}: "
            f"{values['critical']} critical, {values['high']} high, "
            f"{values['medium']} medium and {values['low']} low. "
            f"{values['immediate_actions']} of the "
            f"{values['total_actions']} recommended "
            f"{_plural(values['total_actions'], 'step', 'steps')} should start today."
        )
        if int(values["production_resources"]):
            situation.append(
                f"{values['production_resources']} of the affected systems "
                f"{_verb(values['production_resources'], 'reaches', 'reach')} "
                "production, which is why those items are ranked first: the same fault "
                "carries further there than it does elsewhere."
            )
    else:
        situation.append(
            "This review examined the systems listed in the evidence section and found "
            "no issues requiring action. That is a statement about what was examined, "
            "not about everything that exists."
        )

    # "How bad is it" is followed immediately by "what will it cost me", so the cost
    # shape belongs in Part 1 rather than waiting for the plan.
    quick = int(values["quick_wins"])
    large = int(values["large_effort_actions"])
    if quick or large:
        cost_parts = []
        if quick:
            cost_parts.append(
                f"{values['quick_wins']} of the urgent "
                f"{_plural(values['quick_wins'], 'item is', 'items are')} under a day's "
                "work and can start immediately"
            )
        if large:
            cost_parts.append(
                f"{values['large_effort_actions']} "
                f"{_plural(values['large_effort_actions'], 'item needs', 'items need')} "
                "more than a week and will not fit into anyone's existing workload "
                "without something being moved"
            )
        situation.append("On effort: " + "; ".join(cost_parts) + ".")

    gaps = int(values["coverage_gaps"])
    if gaps:
        situation.append(
            f"{values['coverage_gaps']} "
            f"{_plural(values['coverage_gaps'], 'area was', 'areas were')} outside what "
            "this review could see. Those are listed at the end. A clean result in an "
            "area that was never examined is not a clean result."
        )

    known, total_findings = reach_basis(findings)
    if total_findings and known < total_findings:
        situation.append(
            f"Blast radius is known for {values['reach_known']} of "
            f"{values['total_findings']} "
            f"{_plural(values['total_findings'], 'issue', 'issues')}. For the remainder "
            "the ranking below rests on severity alone, so an item low in the list may "
            "simply be one whose reach was never established."
        )

    for action in actions:
        action.rationale = _deterministic_rationale(action, findings)

    return Briefing(
        bottom_line=bottom_line,
        situation=situation,
        actions=actions,
        authored_by="deterministic",
        degraded_reason=reason,
    )


def _deterministic_rationale(action: ActionItem, findings: Sequence[Finding]) -> str:
    """
    The "Why now" cell. Risk only — cost has its own column beside it.

    Repeating the effort here would invite the reader to trade the two off inside one
    sentence, which is the conflation the two-column layout exists to prevent.
    """
    by_id = {f.id: f for f in findings}
    top = next((by_id[r] for r in action.refs if r in by_id), None)
    if top is None:
        return _WAVE_GUIDANCE.get(action.wave, "")
    reach = (top.reach or "unknown").lower()
    reach_clause = {
        "production": "Reaches production, so the same fault carries further here.",
        "internal": "Internal-facing.",
        "archived": "Archived, which lowers but does not remove the risk.",
        "unknown": "Reach was not established, so this is ranked on severity alone.",
    }.get(reach, "")
    count_clause = (
        f"{len(action.refs)} findings on this resource." if len(action.refs) > 1 else ""
    )
    return " ".join(part for part in (
        f"Severity {top.normalised_severity}.",
        reach_clause,
        count_clause,
    ) if part)


# --------------------------------------------------------------------------- #
# Model authoring
# --------------------------------------------------------------------------- #

_SYSTEM_PROMPT = """\
You write the opening of a security report for one reader: a person who owns the
response but is not a security specialist, and who must answer their manager's questions
before they can start work.

You are given findings that have ALREADY been ranked. You do not change the order, add
items, or remove them. You supply the words.

Hard rules, checked automatically. Violating any of them causes your output to be
discarded:

1. NEVER write a digit or a spelled-out quantity. Every number is a placeholder from the
   provided list, written in braces, for example {critical} or {affected_resources}.
   Write "{critical} systems", never "3 systems" and never "three systems".
2. Use only placeholders from the supplied list. An unknown placeholder is rejected.
3. Every situation paragraph must list the finding ids it rests on, in its "refs" array.
   Cite only ids from the supplied findings.
4. No jargon in "bottom_line" or "situation". No CVE numbers, no package syntax, no tool
   names, no acronyms beyond ones a general manager uses. Say "a supplier's software
   update carried hostile code", not "a compromised transitive dependency".
5. State uncertainty where the data is uncertain. Do not round an unknown up to a fact.

Write "rationale" for each action in the register of a competent engineering manager:
concrete, one or two sentences, saying WHY this is placed where it is. Jargon is allowed
here; hand-waving is not.

The rationale is about RISK, not cost. Effort, the capabilities required and the blast
radius are already shown in their own columns beside your text. Do not repeat them, and
never argue that something should wait because it is hard — the ordering is fixed and
that trade-off is the reader's to make, not yours.

In "situation", if the plan contains work that is both urgent and cheap, say so: it is
the most useful sentence a manager can be given. Use {quick_wins}. If it contains work
that will not fit into anyone's existing week, say that too, using
{large_effort_actions} — an unresourced plan fails quietly.

Return ONLY a JSON object:

{
  "bottom_line": "One sentence. What a manager needs if they read nothing else.",
  "situation": [
    {"text": "Paragraph of plain prose.", "refs": ["E1"]}
  ],
  "rationales": {"1": "Why action 1 is first.", "2": "..."}
}
"""


def _author_payload(
    findings: Sequence[Finding],
    actions: Sequence[ActionItem],
    values: Dict[str, str],
    payload: Dict[str, Any],
) -> str:
    return json.dumps({
        "context": {
            "question_asked": str(payload.get("query") or ""),
            "coverage_limits": [str(n) for n in (payload.get("coverage_notes") or [])][:20],
        },
        "available_placeholders": sorted(values),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.normalised_severity,
                "resource": f.resource,
                "reach": f.reach,
                "detail": f.detail[:400],
            }
            for f in findings[:80]
        ],
        "ranked_actions": [
            {
                "rank": a.rank,
                "wave": a.wave,
                "title": a.title,
                "refs": a.refs,
                # Supplied so the prose can acknowledge cost without restating it, and
                # so the model can see that the order was not chosen by cost.
                "effort": a.effort,
                "effort_means": _EFFORT_TIME.get(a.effort, ""),
                "needs": a.needs,
                "reaches": a.reach,
            }
            for a in actions
        ],
    }, indent=2, default=str)


def _parse_model_json(raw: str) -> Dict[str, Any]:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"\A```[a-zA-Z]*\r?\n", "", text)
        text = re.sub(r"\r?\n```\s*\Z", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise BriefingRejected("model returned no JSON object")
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise BriefingRejected(f"model JSON did not parse: {exc}") from exc
    if not isinstance(data, dict):
        raise BriefingRejected("model JSON was not an object")
    return data


def _build_from_model(
    data: Dict[str, Any],
    findings: Sequence[Finding],
    actions: List[ActionItem],
    values: Dict[str, str],
    model_name: str,
) -> Briefing:
    known_ids = [f.id for f in findings]

    bottom_line = str(data.get("bottom_line") or "").strip()
    if not bottom_line:
        raise BriefingRejected("bottom_line was empty")
    verify_prose(bottom_line, values, where="bottom_line")

    raw_situation = data.get("situation")
    if not isinstance(raw_situation, list) or not raw_situation:
        raise BriefingRejected("situation must be a non-empty array")

    situation: List[str] = []
    for index, entry in enumerate(raw_situation, 1):
        if isinstance(entry, str):
            text, refs = entry, []
        elif isinstance(entry, dict):
            text = str(entry.get("text") or "").strip()
            refs = [str(r) for r in (entry.get("refs") or [])]
        else:
            raise BriefingRejected(f"situation[{index}] is neither text nor an object")
        if not text:
            raise BriefingRejected(f"situation[{index}] was empty")
        verify_prose(text, values, where=f"situation[{index}]")
        # Only enforced when there is something to cite. A no-findings report has a
        # true and uncitable summary, and demanding a reference would force invention.
        if known_ids and not refs:
            raise BriefingRejected(
                f"situation[{index}] cites no findings. Every claim must name the "
                f"finding ids it rests on."
            )
        verify_refs(refs, known_ids, where=f"situation[{index}]")
        situation.append(_substitute(text, values))

    rationales = data.get("rationales") or {}
    if not isinstance(rationales, dict):
        raise BriefingRejected("rationales must be an object keyed by action rank")
    for action in actions:
        text = str(rationales.get(str(action.rank)) or "").strip()
        if text:
            verify_prose(text, values, where=f"rationales[{action.rank}]")
            action.rationale = _substitute(text, values)
        else:
            action.rationale = _deterministic_rationale(action, findings)

    return Briefing(
        bottom_line=_substitute(bottom_line, values),
        situation=situation,
        actions=actions,
        authored_by=model_name,
    )


def author_briefing(
    findings: Sequence[Finding],
    payload: Optional[Dict[str, Any]] = None,
    *,
    provider: Any = None,
    attempts: int = 2,
) -> Briefing:
    """
    Author Parts 1 and 2, preferring the model and falling back to rule.

    The fallback is not an error path but a supported configuration: a site with no LLM
    configured gets a complete report. When the model was tried and rejected, the reason
    travels on the Briefing and is printed in the document, so a reader can tell a
    deliberate deterministic build from a silently degraded one.
    """
    payload = payload or {}
    values = metrics(findings, payload)

    if provider is None:
        try:
            from ..services.llm_provider import get_llm_provider

            provider = get_llm_provider()
        except Exception as exc:
            logger.info("No LLM provider available for briefing; using rules: %s", exc)
            return deterministic_briefing(
                findings, payload,
                reason="No language model was configured for this deployment.",
            )

    user_message = _author_payload(findings, rank_actions(findings), values, payload)
    last_error = ""
    for attempt in range(1, max(1, attempts) + 1):
        content = user_message if attempt == 1 else (
            f"{user_message}\n\nYour previous answer was rejected: {last_error}\n"
            f"Return corrected JSON."
        )
        try:
            response = provider.create_message(
                messages=[{"role": "user", "content": content}],
                system=_SYSTEM_PROMPT,
                max_tokens=2048,
                # Low but non-zero: this is prose, and a rejected attempt that retries at
                # the same temperature tends to reproduce the same violation.
                temperature=0.2,
            )
            data = _parse_model_json(response.get("content", ""))
            return _build_from_model(
                data,
                findings,
                rank_actions(findings),
                values,
                str(response.get("model") or "language model"),
            )
        except BriefingRejected as exc:
            last_error = str(exc)
            logger.warning("Briefing attempt %d rejected: %s", attempt, exc)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("Briefing attempt %d failed: %s", attempt, last_error)
            break

    return deterministic_briefing(
        findings, payload,
        reason=f"The written summary could not be produced ({last_error}).",
    )


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

def briefing_to_dict(briefing: Briefing) -> Dict[str, Any]:
    """
    Serialise a briefing for storage alongside the analysis that produced it.

    Authoring happens once, at analysis time; every later export reads this back. That
    is what keeps a re-exported report identical to the original — and it is why the
    export path never calls a model.
    """
    return {
        "bottom_line": briefing.bottom_line,
        "situation": list(briefing.situation),
        "authored_by": briefing.authored_by,
        "degraded_reason": briefing.degraded_reason,
        "actions": [
            {
                "rank": a.rank, "wave": a.wave, "title": a.title,
                "rationale": a.rationale, "refs": list(a.refs),
                "resources": list(a.resources), "effort": a.effort,
                "effort_note": a.effort_note, "needs": list(a.needs), "reach": a.reach,
            }
            for a in briefing.actions
        ],
    }


def briefing_from_dict(
    data: Dict[str, Any],
    findings: Sequence[Finding],
) -> Optional[Briefing]:
    """
    Rebuild a stored briefing, or return None if it no longer fits the findings.

    The ranking is recomputed from `findings` and only the *prose* is restored. A stored
    plan whose steps no longer match the data would be a report whose Part 2 tells the
    reader to fix something Part 3 does not show — so a mismatch discards the stored
    copy and falls back, rather than rendering a document that contradicts itself.
    """
    if not isinstance(data, dict):
        return None
    bottom_line = str(data.get("bottom_line") or "").strip()
    situation = [str(s) for s in (data.get("situation") or []) if str(s).strip()]
    if not bottom_line or not situation:
        return None

    actions = rank_actions(findings)
    stored_actions = data.get("actions") or []

    def key(title: Any, resources: Any) -> Tuple[str, Tuple[str, ...]]:
        return str(title), tuple(str(r) for r in (resources or []))

    # Keyed on title *and* target rather than on rank. Rank is positional and shifts
    # whenever the finding set changes, which would silently attach one step's reasoning
    # to another. Title alone is not enough either: the same scanner finding in two
    # repositories produces the same title, and one of them would inherit the other's
    # justification.
    by_step = {
        key(a.get("title"), a.get("resources")): str(a.get("rationale") or "")
        for a in stored_actions
        if isinstance(a, dict)
    }
    if stored_actions and not any(
        key(a.title, a.resources) in by_step for a in actions
    ):
        return None
    for action in actions:
        action.rationale = by_step.get(
            key(action.title, action.resources)
        ) or _deterministic_rationale(action, findings)

    return Briefing(
        bottom_line=bottom_line,
        situation=situation,
        actions=actions,
        authored_by=str(data.get("authored_by") or "deterministic"),
        degraded_reason=str(data.get("degraded_reason") or ""),
    )


# --------------------------------------------------------------------------- #
# Composition: the three-part document
# --------------------------------------------------------------------------- #

PART_TITLES = {
    1: "Part 1 — What Happened",
    2: "Part 2 — What To Do, In Order",
    3: "Part 3 — Evidence, Targets and Fixes",
}


def part_anchor(part: int) -> str:
    """
    The anchor a cross-reference must use to reach a part.

    Computed with the renderer's own slugifier rather than written out, because a
    hand-written anchor that stops matching its heading does not fail — it renders as a
    link to nothing and a blank page number, which is the one class of error a reader
    cannot detect. Changing a part title now moves its references with it.
    """
    from .md_to_pdf import _slugify

    return _slugify(PART_TITLES[part], {})


_escape = md_text
_table = md_table


_ATX_HEADING = re.compile(r"^(#{1,6})(\s+\S)", re.MULTILINE)
_FENCE = re.compile(r"^(?:```|~~~)", re.MULTILINE)


def _demote_headings(markdown: str, by: int = 1) -> str:
    """
    Push every heading down `by` levels so an embedded document nests under its host.

    Fenced blocks are skipped: a `#` opening a line inside a shell or Python fence is a
    comment, and deepening it would corrupt the code a reader is meant to run. Headings
    already at h6 stay there rather than growing a seventh hash, which is not a heading.
    """
    out: List[str] = []
    in_fence = False
    for line in markdown.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        match = _ATX_HEADING.match(line)
        if match:
            level = min(len(match.group(1)) + by, 6)
            out.append("#" * level + line[len(match.group(1)):])
        else:
            out.append(line)
    return "\n".join(out)


def situation_markdown(briefing: Briefing, findings: Sequence[Finding]) -> List[str]:
    """Part 1. No tables, no identifiers, no jargon — one page a manager can repeat."""
    lines = [
        f"# {PART_TITLES[1]}",
        "",
        "*Read this if someone has asked you what is going on. It is written to be "
        "repeated out loud. No action is required from this part.*",
        "",
        "## The Short Version",
        "",
        f"**{_escape(briefing.bottom_line)}**",
        "",
    ]
    for paragraph in briefing.situation:
        lines.append(_escape(paragraph))
        lines.append("")

    lines.append(
        f"The steps to take are in [Part 2](#{part_anchor(2)}), in the order to take "
        f"them. The proof behind every statement here is in "
        f"[Part 3](#{part_anchor(3)})."
    )
    lines.append("")
    return lines


def action_plan_markdown(briefing: Briefing, findings: Sequence[Finding]) -> List[str]:
    """Part 2. Ordered, owner-assignable, with the target named on every line."""
    lines = [
        f"# {PART_TITLES[2]}",
        "",
        "*Work down this list. It is ordered by how much damage the item can do and how "
        "far it reaches, not by how hard it is to fix. Each step names what to touch; "
        f"the detail for each is in [Part 3](#{part_anchor(3)}).*",
        "",
    ]

    if not briefing.actions:
        lines += [
            "No action is required from this report. That is a conclusion about the "
            "systems listed in Part 3 and about nothing else.",
            "",
        ]
        return lines

    lines.extend(_effort_summary(briefing.actions))

    for wave in (_WAVE_IMMEDIATE, _WAVE_THIS_WEEK, _WAVE_PLANNED):
        items = [a for a in briefing.actions if a.wave == wave]
        if not items:
            continue
        lines.append(f"## {wave}")
        lines.append("")
        lines.append(f"*{_WAVE_GUIDANCE[wave]}*")
        lines.append("")
        # Six columns is the practical limit in portrait. `Reaches` is dropped because
        # the rationale already states it, and `Target` because `_action_title` guarantees
        # the resource appears in the action itself — a column that repeats the one beside
        # it costs width that the rationale needs more.
        lines.extend(_table(
            ["#", "Action", "Why now", "Effort", "Needs", "Owner"],
            [
                [
                    str(action.rank),
                    action.title,
                    action.rationale,
                    action.effort,
                    "; ".join(action.needs),
                    " ",  # left blank on purpose: the reader writes a name here
                ]
                for action in items
            ],
        ))
        lines.append("")

    lines.append("### Before this document is filed")
    lines.append("")
    lines.append(
        "Assign an owner to every row. An unowned step in a priority list is "
        "indistinguishable from a step that was completed."
    )
    lines.append("")
    lines.append(
        "Effort is an estimate of the work, not of the risk, and it never moved an item "
        "between bands. A large item high in this list is there because of what it "
        "protects; if it cannot start today, that is a resourcing decision to make "
        "deliberately rather than by letting it drift down the page."
    )
    lines.append("")

    unknown_reach = [f for f in findings if (f.reach or "unknown").lower() == "unknown"]
    if unknown_reach:
        count = str(len(unknown_reach))
        lines.append(
            f"Ranking caveat: {count} of {len(findings)} findings "
            f"{_verb(count, 'has', 'have')} no recorded blast radius, so "
            f"{_plural(count, 'it is', 'they are')} placed on severity alone. If any of "
            f"{_plural(count, 'them', 'those')} turns out to reach production it belongs "
            "higher than it sits here."
        )
        lines.append("")

    unestimated = [a for a in briefing.actions if "not estimated" in a.effort_note]
    if unestimated:
        count = str(len(unestimated))
        lines.append(
            f"Effort caveat: {count} of {len(briefing.actions)} steps could not be "
            f"sized from the remediation on record, so "
            f"{_plural(count, 'it is', 'they are')} shown as mid-range "
            f"({', '.join('#' + str(a.rank) for a in unestimated[:12])}"
            f"{', …' if len(unestimated) > 12 else ''}). Treat "
            f"{_plural(count, 'that figure', 'those figures')} as a prompt to estimate, "
            "not as an estimate."
        )
        lines.append("")
    return lines


def _effort_summary(actions: Sequence[ActionItem]) -> List[str]:
    """
    What the whole plan costs, before the reader reaches the first row.

    Quick wins lead because they are the only part of a plan a manager can action in the
    meeting they are sitting in.
    """
    lines: List[str] = ["## What This Plan Costs", ""]

    quick = [a for a in actions if a.is_quick_win]
    large = [a for a in actions if a.effort in ("L", "XL")]
    needs = sorted({need for a in actions for need in a.needs})

    lines.extend(_table(
        ["Size", "Meaning", "Steps"],
        [
            [band, _EFFORT_TIME[band], str(sum(1 for a in actions if a.effort == band))]
            for band in _EFFORT_BANDS
        ],
    ))
    lines.append("")

    if quick:
        lines.append(
            f"**{len(quick)} of the urgent "
            f"{'step is' if len(quick) == 1 else 'steps are'} under a day's work "
            f"({', '.join('#' + str(a.rank) for a in quick)}). Start there** — they "
            "close real exposure today and cost almost nothing to schedule."
        )
        lines.append("")

    if large:
        lines.append(
            f"{len(large)} "
            f"{'step needs' if len(large) == 1 else 'steps need'} more than a week and "
            f"cannot be absorbed into someone's existing load: "
            f"{', '.join('#' + str(a.rank) for a in large)}. These need a named owner "
            "and time set aside, or they will not happen."
        )
        lines.append("")

    if needs:
        lines.append("Capabilities this plan draws on: " + "; ".join(needs) + ".")
        lines.append("")
    return lines


def evidence_markdown(
    findings: Sequence[Finding],
    body_sections: Optional[str] = None,
) -> List[str]:
    """
    Part 3, in the three orders an engineer asks for it: proof, targets, fixes.

    The full evidence body is placed under 3.1 rather than in an appendix because it is
    the proof, and a reader who has come this far has come for exactly that.
    """
    lines = [
        f"# {PART_TITLES[3]}",
        "",
        "*Everything behind Parts 1 and 2, in full. Nothing here is summarised.*",
        "",
        "## 3.1 Proof",
        "",
    ]
    if body_sections and body_sections.strip():
        # The evidence builders emit `##`, which at this point in the document would sit
        # level with "3.1 Proof" rather than inside it — the table of contents would show
        # "Hunt Evidence" as a peer of the part's own subsections.
        lines.append(_demote_headings(body_sections.strip(), by=1))
        lines.append("")
    else:
        lines.append("_No evidence detail was recorded for this run._")
        lines.append("")

    lines.append("## 3.2 Target Resources")
    lines.append("")
    if findings:
        lines.append(
            "Every finding, with the identifier used to cite it elsewhere in this "
            "document. Blast radius shown as recorded; `unknown` means it was never "
            "established, not that it is small."
        )
        lines.append("")
        lines.extend(_table(
            ["ID", "Severity", "Reach", "Resource", "Finding"],
            [
                [f.id, f.normalised_severity, f.reach or "unknown", f.resource or "—",
                 f.title]
                for f in sorted(findings, key=lambda f: (-f.score, f.id))
            ],
        ))
        lines.append("")
    else:
        lines.append("No resources were identified as affected.")
        lines.append("")

    lines.append("## 3.3 Mitigations and Safeguards")
    lines.append("")
    with_fix = [f for f in findings if f.mitigation.strip()]
    if with_fix:
        lines.extend(_table(
            ["ID", "Resource", "Effort", "Mitigation"],
            [[f.id, f.resource or "—", f.effort_band, f.mitigation] for f in
             sorted(with_fix, key=lambda f: (-f.score, f.id))],
        ))
        lines.append("")
        lines.append(
            "Effort sizes: "
            + "; ".join(f"**{band}** {_EFFORT_TIME[band]}" for band in _EFFORT_BANDS)
            + ". Sizes are per finding here; Part 2 shows them per step, which is "
            "larger where one step covers several findings."
        )
        lines.append("")
    else:
        lines.append(
            "_No per-finding mitigation was recorded. Treat Part 2 as the remediation "
            "plan and record the fix applied against each identifier above._"
        )
        lines.append("")

    without_fix = [f for f in findings if not f.mitigation.strip()]
    if with_fix and without_fix:
        lines.append(
            f"No mitigation is recorded for {len(without_fix)} of {len(findings)} "
            f"findings ({', '.join(f.id for f in without_fix[:12])}"
            f"{', …' if len(without_fix) > 12 else ''}). Those need a decision, not a "
            "default."
        )
        lines.append("")
    return lines


def provenance_markdown(briefing: Briefing) -> List[str]:
    """
    How Parts 1 and 2 were written. Printed, always.

    A reader repeating the summary to their management is entitled to know whether a
    model phrased it, and every quantity in it was substituted by code either way.
    """
    if briefing.authored_by == "deterministic":
        how = (
            "Parts 1 and 2 were assembled by rule, without a language model."
            + (f" {briefing.degraded_reason}" if briefing.degraded_reason else "")
        )
    else:
        how = (
            f"The wording of Parts 1 and 2 was drafted by {briefing.authored_by}. "
            "The priority order was computed from severity and blast radius, not chosen "
            "by the model, and every figure was substituted from the finding data — the "
            "model is prevented from writing a number."
        )
    return ["---", "", f"*{_escape(how)}*", ""]


def compose_document(
    briefing: Briefing,
    findings: Sequence[Finding],
    *,
    evidence_body: Optional[str] = None,
) -> str:
    """Assemble the three parts into one Markdown document."""
    lines: List[str] = []
    lines.extend(situation_markdown(briefing, findings))
    lines.extend(action_plan_markdown(briefing, findings))
    lines.extend(evidence_markdown(findings, evidence_body))
    lines.extend(provenance_markdown(briefing))
    return "\n".join(lines).rstrip() + "\n"
