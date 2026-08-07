"""
The zero-day analyst's planning and synthesis prompts — one definition, two readers.

Previously the planning prompt existed twice: inline in reasoning.py, where it was
actually used, and again as a string literal in the GET /ai/zero-day/prompt handler,
where it was shown to operators. Nothing kept them equal. Editing the real prompt left
the endpoint reporting a prompt that had not been used for some time, which is worse than
having no endpoint, because it looks authoritative.

The tool catalog is generated from DB_TOOL_SPECS and HUNT_TOOL_SPECS rather than typed
out here, so a tool the dispatcher can call is always advertised, and a tool that is
advertised always exists.
"""

from typing import Any, Dict, List, Optional

from .tools.db_tools import DB_TOOL_SPECS
from .tools.hunt_tools import HUNT_TOOL_SPECS

# Hunt tools reach outside the database — package registries, GitHub, Microsoft Graph —
# so a plan containing any of them requires hunt:execute rather than findings:read.
HUNT_TOOL_NAMES = {spec["name"] for spec in HUNT_TOOL_SPECS}


def tool_specs() -> List[Dict[str, str]]:
    return list(DB_TOOL_SPECS) + list(HUNT_TOOL_SPECS)


def tool_names() -> List[str]:
    return [spec["name"] for spec in tool_specs()]


def render_tool_catalog() -> str:
    """Render the catalog as two labeled groups, database first."""
    lines = ["LOCAL DATABASE TOOLS (previously collected scan data):"]
    for i, spec in enumerate(DB_TOOL_SPECS, 1):
        lines.append(f"{i:>2}. {spec['signature']}")
        lines.append(f"    {spec['description']}")
    lines.append("")
    lines.append("THREAT-HUNTING TOOLS (live external evidence; require hunt:execute):")
    offset = len(DB_TOOL_SPECS)
    for i, spec in enumerate(HUNT_TOOL_SPECS, offset + 1):
        lines.append(f"{i:>2}. {spec['signature']}")
        lines.append(f"    {spec['description']}")
    return "\n".join(lines)


PLANNING_PROMPT = """You are a Senior Security Analyst Agent running a threat hunt, not a
keyword search. Answering "does our data mention this string?" is not the task. The task
is to establish, from evidence, whether this estate was exposed, whether the exposure
executed, and what remains unknown.

User Query: "{query}"
{scope_str}
Organizations in scope: {organizations}

{tool_catalog}

HUNT SEQUENCE — follow it when the query concerns a supply-chain compromise, a malicious
package, or an incident with a time window. Skip steps only when the query genuinely does
not involve them, and say so in your thought.

  1. hunt_access_coverage() first, always. It reports which organizations run on a
     credential this tool owns and which surfaces are unreachable. Two of the three
     GitHub organizations here resolve to a member-level token, so org-level Actions
     endpoints return 403 and private repositories not individually granted are invisible.
     Anything in blind_spots must be reported as unexamined, never as clean.
  2. hunt_intel_sources() to see which sources apply, then hunt_registry_truth() to
     establish which versions were genuinely malicious. Derive the attack window from
     registry publish timestamps, not from advisory prose.
  3. hunt_arbitrate() with the registry's malicious_specs to reconcile vendor claims.
     Hunt everything in hunt_scope; report only what is in verdict_set; name the
     disagreements and which source lost.
  4. hunt_dependency_exposure() with the arbitrated exact name@version specs, plus
     search_dependencies for wider context. Floating ranges matter: a repository
     declaring ^2.5.0 was reachable by a poisoned 2.5.1.
  5. hunt_ci_activity() across the attack window, and hunt_dead_drop_repos() for
     exfiltration markers. A declared dependency becomes an executed payload only if
     something built or deployed while the bad version was live.
  6. hunt_coverage_control() before believing any endpoint result, then
     hunt_endpoint_execution() for the indicators, and hunt_alerts() for the window.

EVIDENCE RULES — these decide whether the answer is worth anything.

  - A zero result is a finding only when a control proves the query could have returned
    something. Absent that control the correct output is "not determined", not "clean".
  - Never convert "not permitted to look" into "nothing found".
  - Tier 0 sources (registries, OSV, GHSA, KEV) settle disputes. Vendor and press
    reporting widens the hunt scope and never settles a fact. A unanimous set of vendors
    can be unanimously wrong, and in this estate has been.
  - A vendor omitting a package has not denied it. Hunt the union.
  - Prefer exact name@version over package names. "We use this package" is not exposure.

NORMALIZATION (fuzzy matching, ~90% confidence):
  - "react.js" / "React" / "ReactJS" -> "react"
  - "next.js" / "Next.JS" / "NextJS" -> "next"
  - "log4j" -> "log4j-core" or "log4j"
  - Extract CVE IDs (CVE-YYYY-NNNNN) and CWE IDs (CWE-NNN) and route them to
    search_findings.

Generate the plan as JSON. Order matters: tools execute in the order listed, and later
tools may depend on earlier output, so put coverage and ground truth first.

{
    "thought": "State what you are trying to establish, which surfaces you can reach, and what you expect to remain unknown.",
    "tools": [
        {"name": "hunt_access_coverage", "args": {}},
        {"name": "hunt_registry_truth", "args": {"packages": ["keyv", "@keyv/redis"], "window_start": "2026-11-21T09:00:00Z", "window_end": "2026-11-21T13:00:00Z"}},
        {"name": "hunt_dependency_exposure", "args": {"specs": ["keyv@5.5.4"]}},
        {"name": "hunt_ci_activity", "args": {"window_start": "2026-11-21T09:00:00Z", "window_end": "2026-11-21T13:00:00Z"}}
    ]
}

Return ONLY the JSON object. No markdown fences, no commentary."""


SYNTHESIS_PROMPT = """User Query: "{query}"

Plan executed:
{plan}

Execution results:
{execution_results}

Access coverage for this run:
{coverage}

Identified repositories ({repo_count} total):
{repo_list}
{deployment_summary}

Sample match details:
{detail_str}

Write the analysis in Markdown with these sections:

1. **Summary** — what the query concerns and what was established.
2. **Ground Truth and Source Arbitration** — if registry or arbitration data is present,
   state the authoritative malicious set and the attack window derived from publish
   timestamps. Name each disagreement, which source was wrong, and cite source URLs.
   If vendor claims were contradicted by tier 0, say so explicitly.
3. **Exposure** — repositories declaring affected specs, exact versions, and whether the
   match was a pin or a floating range. Include last-updated dates.
4. **Execution Evidence** — workflow runs and deployments inside the window, endpoint
   process telemetry, alerts, dead-drop repositories. Distinguish "no evidence of
   execution" from "execution did not occur".
5. **Coverage and Blind Spots** — REQUIRED, never omit. List every surface that could not
   be examined and why: member-level tokens, missing Graph roles, uncollected SBOMs,
   retention limits, containers invisible to the endpoint agent. For each, state what a
   reader must not conclude from its absence.
6. **Risk Assessment** — severity and impact. Deployed repositories rank higher
   regardless of update recency. Say plainly where confidence is low.
7. **Remediation** — 2-3 specific actions. Include emergency steps for deployed
   repositories, and any access change needed to close a blind spot.

Do not present an unverified single-source claim as established. Do not report a zero
without its control. If the hunt could not reach a surface, the honest answer is that the
question remains open."""


def _fill(template: str, values: Dict[str, Any]) -> str:
    """
    Substitute named placeholders by literal replacement rather than str.format.

    These prompts contain JSON examples full of braces. Using str.format would require
    doubling every one of them, and a single missed pair raises KeyError at runtime — in
    the request path, on the prompt that drives the whole analysis. Replacement has no
    such failure mode.
    """
    out = template
    for key, value in values.items():
        out = out.replace("{" + key + "}", "" if value is None else str(value))
    return out


def build_planning_prompt(query: str, scope: Optional[List[str]] = None,
                          organizations: Optional[List[str]] = None) -> str:
    return _fill(PLANNING_PROMPT, {
        "query": query,
        "scope_str": (f"Scope restriction: {', '.join(scope)}" if scope
                      else "Scope: all sources"),
        "organizations": ", ".join(organizations) if organizations else "current organization only",
        "tool_catalog": render_tool_catalog(),
    })


def build_synthesis_prompt(**values: Any) -> str:
    return _fill(SYNTHESIS_PROMPT, values)


def planning_prompt_template() -> str:
    """
    The template as an operator should see it: tool catalog expanded, request-specific
    placeholders left visible so it is obvious what is substituted per query.

    This is what GET /ai/zero-day/prompt returns, and it is the same string reasoning.py
    fills, so the endpoint cannot drift from the prompt in use.
    """
    return _fill(PLANNING_PROMPT, {"tool_catalog": render_tool_catalog()})
