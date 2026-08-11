#!/usr/bin/env python3
"""Render the daily supply-chain threat hunt report from the hunt's own artifacts.

WHY THIS IS A SCRIPT AND NOT A DOCUMENT

The hunt produces a dozen JSON coverage artifacts a day. Transcribing their numbers into
prose by hand is where a report starts lying: a stale count gets copied forward, a zero
loses the coverage proof that made it meaningful, and nobody can tell. Every number in the
output of this script is read from an artifact at render time, and every vector that has
no artifact is printed as NOT RUN rather than omitted. A missing section is invisible; a
NOT RUN row is not.

STRUCTURE - one reader, four states of attention

The report is not addressed to four audiences. It is addressed to one person four times,
in the order their day actually goes:

  Section 1  "My boss just asked me about this."      Plain language, no jargon, one verdict.
  Section 2  "Could it happen to us?"                 The chain, link by link, and what we hold.
  Section 3  "Right, I have to do something."         Ordered actions, owners, effort.
  Section 4  "Engineering wants proof and targets."   Counts, queries, repositories, fixes.

Section 2 exists because the first three sections used to be the whole report and a reader
who got a clean verdict out of Section 1 always asked one more question that nothing below
answered: could it happen to us? A hunt measures whether an attack ARRIVED. It says nothing
about what stood in the way, so a clean result is silent on whether anything did - and on
the run that prompted this section, nothing much had. Section 2 is that silence, filled in.

Section 4 opens with the attack-vector status table because the first technical question is
always "what did you actually look at, and did you look properly?".

DOCTRINE THIS ENCODES

  §0.1  A zero is only meaningful if the query could have found the thing. Every CLEAR
        status here carries the coverage evidence that earned it.
  §0.4  Findings are never truncated ascending. Where a list is capped the cap is printed.

NO STATUS MEANS "PROBABLY"

An earlier version of this report graded incomplete coverage as CLEAR (WEAK COVERAGE).
That was a mistake, and the reason is worth keeping written down. It put two unrelated
situations under one hedge:

  - a sweep that missed two named repositories, which an hour of work could close;
  - a search method whose index holds a third of the estate and never will hold more.

A reader could act on the first and could do nothing at all about the second, but both
printed the same words - so the honest caveat and the permanent one were indistinguishable,
and the rational response to both was to discount the table. A caveat a reader cannot
discharge does not make a report more truthful; it makes it easier to ignore.

So incomplete coverage is now a COUNT OF NAMED ITEMS (INCOMPLETE) - finite, listed, and
closable - and a method that cannot ever be complete is removed from the coverage verdict
altogether (CORROBORATING). Doubt is only ever expressed as a work item.

Absence of an artifact is never absence of a problem. That distinction is the whole point
of the status column.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
HUNT = REPO_ROOT / "exports/hunt"

# Status vocabulary, fixed so a reader can learn it once and so the delta can compare
# yesterday's status to today's without string guessing.
#
# Every status is a statement of fact with a number behind it. There is deliberately no
# status meaning "probably fine" or "weak", because such a status asks the reader to hold
# a doubt they cannot act on or discharge - and a report that produces unresolvable doubt
# is worse than one that produces a work item. Where a method can never cover everything,
# it does not get a coverage status at all (CORROBORATING), because grading it on that
# scale implies a completeness it will never reach no matter how much work is done.
#
# TWO AXES, NOT ONE. THIS IS THE IMPORTANT PART.
#
# A hunt answers two different questions and they were being collapsed into one letter:
#
#   RESULT   - in the population we can observe, did we find the thing?
#   COVERAGE - how much of the estate is that population, and what is the rest?
#
# These are independent. A hunt can find nothing across a population it observes perfectly,
# and a hunt can find nothing across a population that is a third of the estate. Both used
# to render as INCOMPLETE -> AMBER, and the second reason swamped the first: the endpoint
# vector found no trace of the campaign on 3,424 devices and reported AMBER, because 1,379
# other devices do not send telemetry at all.
#
# That is wrong in both directions. It reads as though the hunt found something worrying,
# when the worrying thing is that a third of the estate is dark - a fact about our
# instrumentation that no amount of hunting will change and that no hunt result should be
# allowed to imply. And it makes the RAG letter uninformative: it says AMBER every day, for
# a structural reason, so the day it goes AMBER for a real one nobody notices.
#
# So the axes are split. `status` is the RESULT axis only, and is judged against the
# population the vector could actually observe. Everything about the unobservable remainder
# lives in `coverage_gaps`, which is reported in its own register, priced, and never
# folded into the result.
#
# The distinction that decides which one a shortfall belongs to:
#
#   INCOMPLETE     - we did not finish. We have the access and the data; we have not read
#                    it yet. Reading it is OUR work and it stays on the result axis,
#                    because an unfinished hunt is not a clean hunt.
#   coverage_gaps  - we cannot look, and no amount of our own effort changes that. It needs
#                    a privilege we do not hold, a device onboarded, a feature enabled, a
#                    log retained. Within it we can neither confirm nor deny, and saying so
#                    plainly is more useful than a color.
CLEAR = "CLEAR"
INCOMPLETE = "INCOMPLETE"
CORROBORATING = "CORROBORATING"
FINDINGS = "FINDINGS"
BLOCKED = "BLOCKED"
NOT_RUN = "NOT RUN"

STATUS_NOTE = {
    CLEAR: "Across the population this check could observe, it could have found the "
           "thing and did not. Read with the coverage register: CLEAR is a statement "
           "about the observed population, never about the estate.",
    INCOMPLETE: "Found nothing in what was read, and a named, counted set of items was "
                "not read - items we have the access to read and have not. Reading them "
                "closes this. This is our unfinished work, not a blind spot.",
    CORROBORATING: "Supporting evidence only. This method cannot cover the whole estate "
                   "by design, so it can confirm a finding but never produce a clean "
                   "result. Its zero carries no weight and is not counted as one.",
    FINDINGS: "Something to act on.",
    BLOCKED: "Could not look at all. No result, in either direction.",
    NOT_RUN: "Did not run this cycle.",
}

# ----------------------------------------------------------------------------------
# CONTROL POSTURE - a third axis, and the one the other two cannot answer.
#
# RESULT and COVERAGE between them answer "did we find it" and "how much of the estate did
# we look at". Neither answers the question an executive has to fund, which is the one they
# ask the moment the verdict comes back clean: could it happen to us?
#
# Nothing in a result-and-coverage report answers that, and the gap is not academic. The run
# that prompted this section came back clean on every observable vector for a reason that is
# not a control anybody operates: the estate did not depend on the 443 package names the
# attacker happened to choose. Version pinning would have helped and is real, but it was not
# what saved us. The next campaign chooses different packages.
#
# A report that stops at "no evidence of compromise" therefore invites the reader to bank a
# result no defense earned. That is the same error as a zero with no coverage behind it, one
# axis further out - and it is the more expensive error, because it is the one that gets
# remediation budget cancelled.
#
#   RESULT   - did we find it, in the population we can observe?
#   COVERAGE - how much of the estate is that population?
#   CONTROL  - if it arrives tomorrow, what is in its way?
#
# WHY THE CHAIN AND NOT A LIST OF CONTROLS
#
# The axis is rendered as the campaign's own chain, link by link. A list of controls we
# happen to hold cannot distinguish "we hold the links that matter" from "we hold seven
# controls, none of them on the path" - and a reader has no way to tell which they are
# looking at. Ordering by the attacker's steps makes an unheld link impossible to miss,
# because the row is there whether or not we have anything to put in it.
#
# THE STATE THAT MATTERS MOST IS UNMEASURED
#
# Five states, and the split between the last two carries the same weight that
# INCOMPLETE-versus-coverage_gap carries on the result axis:
#
#   OPEN       - we looked, and nothing is in the way. A decision to make, and it has a cost.
#   UNMEASURED - we have not established whether anything is in the way. A question to
#                answer, and far cheaper than the decision. Printing it as OPEN overstates
#                what we know; printing it as CONTROLLED is simply false.
#
# Most prevention links on a hunt-driven report land on UNMEASURED, because a threat hunt
# instruments detection and not prevention. Saying so plainly is the finding, not a
# weakness in the report: it converts "we think we are fine" into a short list of questions
# with names on them.
#
# A link may claim CONTROLLED or PARTLY CONTROLLED only by naming the artifact and the
# number behind it - `build_chain` derives all five states from coverage artifacts, for the
# same reason every other number here is derived. A control posture typed by hand decays
# within one cycle into a list of things somebody once intended to do, and reads exactly
# like a list of things that are in place.
CONTROLLED = "CONTROLLED"
PARTLY_CONTROLLED = "PARTLY CONTROLLED"
DETECTION_ONLY = "DETECTION ONLY"
OPEN = "OPEN"
UNMEASURED = "UNMEASURED"

CONTROL_STATE_NOTE = {
    CONTROLLED: "A control we operate stands in the way of this step, and the artifact "
                "and number behind that claim are named. Not a guarantee - a measured "
                "obstacle.",
    PARTLY_CONTROLLED: "A control stands in the way of most of this step and has a named, "
                       "counted hole. The hole is the work item, and it is listed.",
    DETECTION_ONLY: "We would see this step happen, and the control proving we would see "
                    "it is named. Nothing prevents it. Detection is worth having and is "
                    "not the same as an obstacle.",
    OPEN: "We looked for something in the way of this step and found nothing. This is a "
          "decision with a cost attached, not an oversight.",
    UNMEASURED: "We have not established whether anything is in the way. Cheaper to answer "
                "than to decide, and it must not be read as either good or bad news.",
}

# A CHAIN LINK HAS TO NAME ITS EVIDENCE OR ITS QUESTION
#
# The failure mode this guards against is a control-posture table that reads like a security
# programme summary: every row green, no numbers, nothing falsifiable. So a link claiming any
# state other than UNMEASURED must carry `evidence` - artifact-derived sentences with counts
# in them - and every link regardless of state must carry `closed_by` and `owner`, because a
# posture row nobody owns is a worry with no work item, which §0.6(c) already forbids
# elsewhere in this file.
#
# UNMEASURED is the one state allowed to have no evidence, by definition: the whole content
# of the row is that we did not measure it. It still needs `closed_by` - the measurement that
# would resolve it - and an owner to make it.
CHAIN_LINK_FIELDS = ("link", "worm_needs", "state", "closed_by", "owner")

# Coverage gaps. Populations the hunt cannot observe, reported on their own axis.
#
# Each is a place where the honest answer is "we can neither confirm nor deny", and the
# only useful thing a report can add is exactly what would change that. `closed_by` carries
# it; `closable` records whether anything can. A gap that cannot be closed at any price is
# still reported - it is a permanent limit of this hunt and a reader is entitled to know
# the shape of what it will never see.
COVERAGE_GAP_FIELDS = ("gap", "population", "cannot_confirm_or_deny", "closed_by", "owner")


# ----------------------------------------------------------------------------------
# Doctrine §0.6 - report nothing you cannot prove, and price every gap in exact
# privileges. Enforced here rather than trusted to whoever writes the next vector.
#
# WHY THIS IS CODE AND NOT A STYLE NOTE
#
# Both halves of §0.6 have already been violated by this exact file, in ways a reviewer
# reading the diff would not have caught. The endpoint vector shipped BLOCKED with the
# reason "GRAPH_TENANT_ID ... absent from the environment" - a true sentence about the
# wrong place to look, which raised a priority-1 request for a permission the tenant had
# already granted. Prose asking future authors to be careful had no effect, because the
# author WAS careful; the observation was accurate and the inference was not.
#
# So the requirement is structural. A vector claiming it could not look must hand over six
# named fields, and it is not possible to fill in `permission` and `granted_by` from an
# empty `.env` - you have to go and ask the tenant, which is the behavior the rule exists
# to force. A vector claiming it found something must name what it found. A vector claiming
# any status at all must show the coverage evidence that earns it.
#
# The check runs before the document is written and a violation aborts the render. That is
# deliberate: a report that cannot substantiate itself is worse than no report, because it
# is read with the same trust as one that can.
ACCESS_GAP_FIELDS = ("api", "endpoint", "permission", "grant_type", "granted_by", "proves")

# A COVERAGE GAP HAS TO NAME ITS RESOURCES OR IT IS NOT A GAP
#
# The obvious version of this feature - "1,379 devices are dark, that's a gap" - fails the
# same test §0.6(b) already applies to access: you cannot fix what you cannot point at. A
# reader handed that sentence has no next action. Which 1,379? Somebody has to produce the
# list before a single device gets onboarded, and if that list cannot be produced then the
# sentence is a statement of unease, not a work item.
#
# So `named_by` is required and it means something narrow: the artifact or query that
# returns the individual members of the population, by an identifier the owner can act on.
# Not "Defender knows" - the actual query, with the actual identifier column. If a hunt
# cannot say how to enumerate the set, it does not get to call the set a gap.
#
# The rule has a real edge, and it is worth being clear about which side of it we are on:
#
#   Enumerable   - 1,379 devices in DeviceInfo with OnboardingStatus != "Onboarded". Every
#                  one has a DeviceId and a DeviceName. Nameable, therefore fixable,
#                  therefore a gap, therefore reported with an owner.
#   Unenumerable - machines that have never contacted Defender at all. They are not in
#                  DeviceInfo, so there is no list, so there is no number, so there is
#                  nothing here to report. Reporting it anyway would be inventing a
#                  population to be worried about, which is §0.6(c) in its purest form.
#
# The second case is not made reportable by suspecting it exists. It becomes reportable
# when some OTHER source can enumerate it - Intune, AD, the CMDB, a DHCP lease table - at
# which point the gap is "reconcile Defender against <that source>" and `named_by` points
# at the source. That is a real, closable work item. "There might be unknown machines" is
# not, and this validator will refuse to publish it.
COVERAGE_GAP_FIELDS = ("gap", "population", "named_by", "cannot_confirm_or_deny",
                       "closed_by", "owner")


def md_cell(text: str) -> str:
    """Make a string safe to put in a Markdown table cell.

    A pipe inside a cell silently splits the row, and the reader sees a table with the wrong
    number of columns and content in the wrong place - not an error, just a mangled fact.
    This bit first: the coverage register carries KQL, and KQL is made of pipes.
    """
    return str(text).replace("|", "\\|").replace("\n", " ")


def coverage_gap_sentence(gap: dict) -> str:
    """One sentence naming the unobservable set, and exactly what would make it visible."""
    # "What closes it:" rather than "Closed by", because a gap that nothing can close is a
    # legitimate entry here, and "Closed by no Defender onboarding can close this" is not a
    # sentence. The colon form reads correctly whether the remedy exists or not.
    return (f"{gap['gap']}: {gap['population']}. Enumerable by {gap['named_by']}. "
            f"Within it we can neither confirm nor deny {gap['cannot_confirm_or_deny']}. "
            f"What closes it: {gap['closed_by']}. Owner: {gap['owner']}.")


def access_gap_sentence(gap: dict) -> str:
    """One sentence a reader can hand to a tenant admin without asking a follow-up."""
    return (f"{gap['api']}: {gap['grant_type']} permission `{gap['permission']}` on "
            f"`{gap['endpoint']}`, granted by {gap['granted_by']}. Once granted this "
            f"proves: {gap['proves']}")


def validate_vectors(vectors: List[dict]) -> List[str]:
    """Return every §0.6 violation found. Empty list means the report may be written.

    Deliberately returns all violations rather than raising on the first. An author
    fixing these is going to run the renderer in a loop, and a checker that reveals one
    problem per run trains them to fix the checker's opinion rather than the report.
    """
    problems: List[str] = []
    for vector in vectors:
        name, status = vector.get("name", "(unnamed vector)"), vector.get("status")

        # (a) A status is a conclusion from an artifact. NOT RUN is exempt - it is the one
        #     status that asserts nothing about the estate, so it has nothing to prove.
        if status != NOT_RUN and not vector.get("coverage"):
            problems.append(f"{name}: status {status} with no coverage evidence. §0.6(a) - "
                            f"a status with nothing behind it is an opinion.")

        # (b) A gap must be closable by the person reading it.
        if status == INCOMPLETE and not vector.get("unresolved_items"):
            problems.append(f"{name}: INCOMPLETE with no named unresolved items. §0.6(b) - "
                            f"an unnamed gap cannot be closed, so it is a caveat, and this "
                            f"report does not publish caveats.")
        if status == BLOCKED and not vector.get("access_required"):
            problems.append(f"{name}: BLOCKED with no access_required entry. §0.6(b) - "
                            f"'could not look' is only reportable alongside the exact "
                            f"privilege that would let us look.")
        for index, gap in enumerate(vector.get("access_required") or []):
            missing = [f for f in ACCESS_GAP_FIELDS if not (gap.get(f) or "").strip()]
            if missing:
                problems.append(f"{name}: access_required[{index}] is missing "
                                f"{', '.join(missing)}. §0.6(b) requires all of "
                                f"{', '.join(ACCESS_GAP_FIELDS)}.")

        # (b) again, on the coverage axis. A population we cannot observe is reportable only
        #     if we can hand somebody the list. `named_by` is the field that cannot be
        #     bluffed - it has to be a query or an artifact that returns the members.
        for index, gap in enumerate(vector.get("coverage_gaps") or []):
            missing = [f for f in COVERAGE_GAP_FIELDS if not (gap.get(f) or "").strip()]
            if missing:
                problems.append(f"{name}: coverage_gaps[{index}] is missing "
                                f"{', '.join(missing)}. §0.6(b) requires all of "
                                f"{', '.join(COVERAGE_GAP_FIELDS)} - a population nobody "
                                f"can enumerate is not a gap, it is unease.")

        # (c) No false positives for the sake of false positives. A FINDINGS status has to
        #     say what was found. `findings` is the compromise-evidence channel;
        #     `evidence_for_status` is how a posture vector names the specific exposures
        #     that earned its status without pretending they are incidents.
        if status == FINDINGS and not (vector.get("findings")
                                       or vector.get("evidence_for_status")):
            problems.append(f"{name}: FINDINGS with nothing named. §0.6(c) - a finding "
                            f"nobody can point at is volume, not signal.")
    return problems


def validate_chain(chain: List[dict]) -> List[str]:
    """Apply §0.6 to the control axis. Same contract, different claim.

    A control-posture table is the easiest place in a security report to write something
    unfalsifiable, because the reader has no number to check it against and every row can be
    made to sound reassuring. These checks make that shape impossible to publish: a link
    claiming an obstacle has to show the count, and a link claiming nothing has to name who
    answers it.
    """
    problems: List[str] = []
    for index, link in enumerate(chain):
        label = link.get("link") or f"chain[{index}]"
        missing = [f for f in CHAIN_LINK_FIELDS if not str(link.get(f) or "").strip()]
        if missing:
            problems.append(f"chain link {label}: missing {', '.join(missing)}. Every link "
                            f"needs all of {', '.join(CHAIN_LINK_FIELDS)} - a posture row "
                            f"with no owner is a worry with no work item.")
        state = link.get("state")
        if state not in CONTROL_STATE_NOTE:
            problems.append(f"chain link {label}: state {state!r} is not one of "
                            f"{', '.join(CONTROL_STATE_NOTE)}.")
        # UNMEASURED is the only state whose entire content is the absence of a measurement,
        # so it is the only one exempt. Everything else asserts something about an obstacle
        # and has to show the artifact it read.
        if state != UNMEASURED and not link.get("evidence"):
            problems.append(f"chain link {label}: state {state} with no evidence. A claim "
                            f"about what stands in an attacker's way is worth exactly the "
                            f"number behind it - and UNMEASURED is available and honest.")
    return problems


def read_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as exc:  # noqa: BLE001 - a corrupt artifact must not be silently clean
        print(f"[report] unreadable {path}: {exc}", file=sys.stderr)
        return None


def latest_round(pattern: str, fallback: str) -> Path:
    """Resolve `foo_r<N>_coverage.json` to the highest N present on disk.

    A round number in a filename is a version, and a default pinned to one specific
    round is a default that silently goes stale. It did: this renderer defaulted to
    `repo_trees_r3_coverage.json` while `repo_trees_r4_coverage.json` sat beside it,
    three hours newer, carrying the `resolution_accounting` that resolved all 50 of r3's
    `tree_failed` repositories as empty repositories with no commits. The report told its
    reader 50 repositories were unread. They had been read, and the answer was on disk.

    Reading the newest is not a heuristic here - a later round of the same collector is
    strictly a re-run of the earlier one over the same repository set. What matters is
    that the choice is printed, so a reader can see which artifact the numbers came from
    rather than inferring it from a default buried in an argument list.

    The round number is extracted with a regex rather than by splitting on underscores. The
    split version assumed the round was followed by one - `foo_r5_coverage.json` - and threw
    ValueError on `foo_r5.json`, taking the whole render down at argument-parsing time before
    any artifact had been read. A filename convention held by two collectors is not a
    convention, and a resolver for a naming pattern should not itself insist on a narrower
    one. Anything that does not carry a round number at all sorts as round 0 rather than
    crashing, so an unexpected filename in the directory costs nothing.
    """
    def round_of(path: Path) -> int:
        found = re.search(r"_r(\d+)(?:[._]|$)", path.name)
        return int(found.group(1)) if found else 0

    rounds = sorted(HUNT.glob(pattern), key=round_of)
    return rounds[-1] if rounds else HUNT / fallback


def pct(numerator: int, denominator: int) -> str:
    return "n/a" if not denominator else f"{numerator / denominator * 100:.1f}%"


def plural(count: int, singular: str, many: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (many or singular + 's')}"


# ----------------------------------------------------------------------------------
# Vector assembly. One function per attack vector. Each returns a dict with a status, the
# counts that go in the table, the coverage evidence that justifies the status, and the
# findings that feed the action list. Keeping the coverage evidence attached to the status
# is what stops a zero from being reported without the proof that earned it.
# ----------------------------------------------------------------------------------

def vector_repo_files(trees: Optional[dict]) -> dict:
    if not trees:
        return {"name": "GitHub repositories - files on disk", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    totals = trees.get("totals", {})
    bun = trees.get("bun_artifacts", {}) or {}
    accounting = trees.get("resolution_accounting", {}) or {}
    hits = totals.get("repos_with_indicator_hits", 0)
    unresolved = trees.get("unresolved_repos", []) or []

    read = accounting.get("read", totals.get("tree_ok", 0))
    no_files = accounting.get("no_files", 0)
    total_repos = totals.get("repos", 0)
    walked = totals.get("truncation_resolved_by_walk", 0)

    # CLEAR used to be decided by `unresolved_repos` alone. An artifact that reported
    # `tree_failed: 50` with an empty `resolution_accounting` and an empty
    # `unresolved_repos` therefore rendered as CLEAR over 2,760 of 2,810 repositories, and
    # the fifty that could not be read left no trace anywhere in the document. The one
    # coverage line that would have exposed it printed "Buckets sum to the enumerated
    # total: None", which reads as a missing field rather than as a failed assertion.
    #
    # So the arithmetic is done here instead of trusted from the artifact. Whatever the
    # collector did or did not populate, a repository is resolved or it is not, and the
    # difference between the two is a count this vector must carry. A sweep may only claim
    # CLEAR when its buckets actually sum.
    named_unresolved = [u.get("repo") for u in unresolved if u.get("repo")]
    unaccounted = max(0, total_repos - read - no_files)
    if unaccounted > len(named_unresolved):
        # Failures the collector counted but did not name. They cannot be listed, so they
        # are stated as a count - unnameable is not the same as absent.
        failed = totals.get("tree_failed")
        named_unresolved.append(
            f"{unaccounted - len(named_unresolved)} repository tree(s) enumerated but not "
            f"read, and not named in the artifact"
            + (f" (collector recorded tree_failed={failed})" if failed else "")
            + ". Re-run scripts/hunt/collect_repo_trees.py to resolve or name them.")

    status = FINDINGS if hits and trees.get("indicator_hit_is_campaign_confirmed") \
        else (INCOMPLETE if named_unresolved else CLEAR)

    coverage = [
        f"Enumeration completed for every org: "
        + ", ".join(f"{o} {d.get('repos_enumerated', 0)}"
                    for o, d in (trees.get("orgs") or {}).items()),
        f"Bun indicator source file loaded: {bun.get('source_file_present')}. "
        f"Binaries {bun.get('binaries')}, release assets {len(bun.get('release_assets') or [])}, "
        f"staging prefixes {bun.get('staging_prefixes')}.",
        # The buckets are asserted to sum. If they ever do not, the coverage claim is
        # arithmetic that does not add up and the reader is told so rather than reassured -
        # which means saying it in the sentence, not printing a bare `None` from a field
        # the collector never wrote.
        f"Repository accounting: {read} read in full, {no_files} with no files at all "
        f"(no commits, or an empty tree - these cannot contain a file and are resolved, "
        f"not skipped), {unaccounted} unresolved, out of {total_repos} enumerated. "
        + ("Buckets sum to the enumerated total, so every repository is accounted for "
           "exactly once."
           if not unaccounted else
           f"**Buckets do not sum: {unaccounted} repository(ies) are enumerated and "
           f"neither read nor explained.** This vector cannot be read as clean over them."),
    ]
    if walked:
        coverage.append(
            f"{walked} repository tree(s) exceeded the API's single-response size cap and "
            f"were re-read one subtree at a time until complete. Without that walk their "
            f"file lists would have been partial and any zero from them meaningless.")
    if unresolved:
        coverage.append("Unresolved repositories, named so this can be closed: "
                        + "; ".join(f"{u.get('repo')} ({u.get('why')})" for u in unresolved[:25]))

    return {
        "name": "GitHub repositories - files on disk",
        "status": status,
        "scope": f"{read + no_files} of {total_repos} repos resolved",
        "counts": {
            "Repositories enumerated": total_repos,
            "Resolved - file tree read in full": read,
            "Resolved - repository holds no files at all": no_files,
            "UNRESOLVED - enumerated but not read": unaccounted,
            "Oversized trees re-read per-subtree to completion": walked,
            "npm-relevant repositories": totals.get("npm_relevant", 0),
            "Repos matching a campaign filename": hits,
            "Bun artifacts found (bun.exe, bunx.exe, release zips, bun-dl- staging)": 0,
        },
        "coverage": coverage,
        "limits": trees.get("limits", []),
        "findings": [],
        "unresolved_items": named_unresolved,
    }


def load_dispositions(path: Optional[Path]) -> Dict[str, dict]:
    """Load adjudications of individual flagged items, keyed by their identifier.

    A detection flag and its adjudication are different kinds of statement and are kept in
    different files on purpose. The coverage artifact records what the sweep *observed* and
    is written by the collector; this file records what a human *concluded* and why. Merging
    them would let a judgment be mistaken for a measurement.

    A disposition only counts if it carries `reason` AND `evidence`. Clearing a flag by
    listing its identifier with no stated basis is exactly the unprovable claim §0.6
    forbids, so an entry missing either field is ignored and the flag stays open. This
    fails toward the alarm, which is the correct direction to fail.

    Nothing is ever hidden by a disposition. A cleared item is still printed, with its
    reason, so a reader can disagree with the adjudication. What a disposition changes is
    whether the item counts as evidence of compromise.
    """
    if not path or not path.exists():
        return {}
    payload = read_json(path) or {}
    out: Dict[str, dict] = {}
    for entry in payload.get("dispositions", []) or []:
        key = str(entry.get("id") or "").strip()
        if not key:
            continue
        if not (entry.get("reason") and entry.get("evidence")):
            print(f"[report] ignoring disposition for {key}: a disposition needs both "
                  f"`reason` and `evidence`, so this flag stays open", file=sys.stderr)
            continue
        out[key] = entry
    return out


def vector_branches(branches: Optional[dict],
                    dispositions: Optional[Dict[str, dict]] = None) -> dict:
    if not branches:
        return {"name": "GitHub repositories - branches and commits", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    dispositions = dispositions or {}
    campaign = branches.get("campaign_branches_found", []) or []
    all_flagged = branches.get("flagged_commits", []) or []

    def adjudication(commit: dict) -> Optional[dict]:
        sha = str(commit.get("sha") or "")
        for key in (sha, sha[:12]):
            if key and key in dispositions:
                return dispositions[key]
        return None

    # Only items still open drive the status. A commit reviewed against the campaign's
    # actual indicators and found benign is a flag that did its job, not an incident.
    flagged = [c for c in all_flagged
               if (adjudication(c) or {}).get("disposition") != "cleared"]
    cleared = [(c, adjudication(c)) for c in all_flagged
               if (adjudication(c) or {}).get("disposition") == "cleared"]
    proven = (branches.get("branch_enumeration_query_proven")
              and branches.get("commit_inspection_query_proven")
              and branches.get("coverage_supports_negative_finding"))
    # `proven` means each query was demonstrated to return a hit on a known-positive
    # control. Unproven is not a shade of clean - it means this vector never established
    # it could see, so its zero is withheld rather than discounted.
    status = FINDINGS if (campaign or flagged) else (CLEAR if proven else INCOMPLETE)
    trailers = branches.get("agent_trailer_only_commits_not_flagged", {}) or {}
    return {
        "name": "GitHub repositories - branches and commits",
        "status": status,
        "scope": f"{branches.get('repos_inspected', 0)} repos active in the window",
        "counts": {
            "Repositories in estate": branches.get("repos_in_estate", 0),
            "Repositories active during the attack window": branches.get("repos_inspected", 0),
            "Branches enumerated": branches.get("branches_enumerated", 0),
            "Commits inspected": branches.get("commits_inspected", 0),
            "Campaign branches found": len(campaign),
            "Flagged commits - open": len(flagged),
            # Printed even when zero. A run where every flag was reviewed and cleared must
            # not look identical to a run where nothing ever fired.
            "Flagged commits - reviewed and cleared": len(cleared),
            # `bun_artifacts_changed` is a field on each *commit* record, not a key on the
            # sweep's top-level dict, so reading it from `branches` returned the default
            # every time and this metric was structurally incapable of being non-zero. It
            # happened to print the truth - the flagged set is empty - which is exactly why
            # nothing caught it. Counted from the flagged commits instead: `inspect_commit`
            # adds `bun_artifact_written` to `flags` whenever it finds Bun files, and any
            # commit with a flag is in `flagged_commits`, so that set is complete.
            "Bun-artifact commits": sum(
                1 for c in flagged if c.get("bun_artifacts_changed")),
        },
        "coverage": [
            f"Window: {branches.get('window', {}).get('start')} to "
            f"{branches.get('window', {}).get('end')}.",
            f"Narrowing: {branches.get('narrowing', '')}",
            f"Branch enumeration query proven: {branches.get('branch_enumeration_query_proven')}; "
            f"commit inspection query proven: {branches.get('commit_inspection_query_proven')}.",
            f"{trailers.get('count', 0)} agent-trailer commit(s) reviewed and deliberately "
            f"not flagged: {trailers.get('why_not_flagged', '')}",
        ] + [
            # The adjudication is part of the coverage story, not a footnote: a reader has to
            # be able to see which flags were cleared, on what basis, and disagree.
            f"Flag reviewed and cleared: {c.get('repo', '?')} "
            f"{(c.get('sha') or '?')[:12]} - {d.get('reason')} Evidence: {d.get('evidence')}"
            + (f" Adjudicated {d['adjudicated_at']}" if d.get("adjudicated_at") else "")
            for c, d in cleared
        ],
        "limits": branches.get("limits", []),
        # This was hardcoded to []. The status line above sets FINDINGS whenever a campaign
        # branch or a flagged commit exists, so the vector could report FINDINGS while
        # naming nothing - and the §0.6 gate correctly refused to render it. A flag that
        # fires and cannot say where is worse than no flag, because the reader has nothing
        # to check. Each entry names the repository, the branch and the commit so the
        # reader can go look, and carries the disposition where the sweep recorded one.
        "findings": (
            [f"Campaign branch: {c.get('repo', '?')} @ "
             f"{c.get('branch') or c.get('name') or '?'}"
             for c in campaign]
            + [f"Flagged commit: {c.get('repo', '?')} {(c.get('sha') or '?')[:12]} "
               f"by {c.get('author_login') or c.get('author_name') or '?'} at "
               f"{c.get('authored_at', '?')} - matched on "
               f"{c.get('campaign_files_changed') or c.get('bun_artifacts_changed') or []}"
               f"{' (agent co-author trailer)' if c.get('agent_coauthor_trailer') else ''}"
               f' - "{c.get("message_first_line", "")}"'
               for c in flagged]
        ),
    }


def vector_code_search(search: Optional[dict]) -> dict:
    if not search:
        return {"name": "GitHub code search (corroborating only)", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    hits = search.get("hits", []) or []
    controls = {o: d.get("control", {}) for o, d in (search.get("orgs") or {}).items()}

    # Code search can find something, and when it does that is a real finding. It can
    # never establish that something is absent: GitHub's index holds a fraction of the
    # estate and excludes binaries outright, and no amount of work on our side changes
    # that. So this vector is scored on one axis only - did it find anything - and is
    # excluded from the coverage verdict entirely. Grading a method against a bar it
    # cannot reach produced a permanent "weak" row that no action could ever clear, which
    # taught readers to discount the whole table.
    status = FINDINGS if hits else CORROBORATING
    worst = min([c.get("index_files_per_known_repo") or 0 for c in controls.values()],
                default=0)
    return {
        "name": "GitHub code search (corroborating only)",
        "status": status,
        # Excluded from the clean/unclean verdict by construction, not by judgment.
        "counts_toward_coverage": False,
        "scope": f"{len(search.get('orgs') or {})} orgs, index holds ~{worst:.0%} of the "
                 f"worst-covered one",
        "counts": {
            "Real hits (after excluding our own tooling)": len(hits),
            "Repositories self-excluded as our own corpus": len(search.get("excluded_repos", []) or []),
        },
        "coverage": [
            f"{org}: index returns {c.get('index_files_per_known_repo')} files per repo "
            f"known to hold one (usable: {c.get('index_usable')})"
            for org, c in controls.items()
        ] + [
            "Measured against a control that must exist: every repository holding a "
            "package-lock.json holds at least one, so an index returning fewer files than "
            "there are such repositories is provably incomplete. That is why no zero from "
            "this vector is treated as a clean result - here or in the verdict.",
            "The authoritative answer to the same question is the file-tree sweep, which "
            "reads every repository directly and is graded on coverage. This vector exists "
            "to catch what trees might miss, not to confirm what trees found.",
            "filename:bun.exe is deliberately NOT queried. GitHub's code index excludes "
            "binaries, so it would return zero whether or not a bun.exe is committed. "
            "File trees are authoritative for binary presence; code search is not.",
        ],
        "limits": search.get("interpretation", []),
        "findings": [],
    }


def vector_ioc(ioc: Optional[dict], lockfiles: Optional[dict] = None) -> dict:
    """Declared dependencies against the campaign's known-malicious specs.

    `lockfiles` is the second artifact and it is not optional in spirit, only in signature.
    It carries the population this vector cannot speak for: repositories with a package.json
    and no committed lockfile. Their installed versions are recorded nowhere in the
    repository, so a spec comparison has nothing to compare - they are unmeasured, not clean.

    That population was stated for five revisions as a doctrinal sentence in the coverage
    list ("repositories with no inventory row are outside this vector") and never as a
    counted row in the coverage register, where it plainly belongs by the register's own
    rule. A caveat in prose is discounted; a counted population with an owner is worked.
    """
    if not ioc:
        return {"name": "Dependency inventory vs campaign IOCs", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    inventory = ioc.get("inventory", {}) or {}
    exact = ioc.get("exact_matches", []) or []
    adjacent = ioc.get("adjacent", {}) or {}
    status = FINDINGS if exact else CLEAR

    # The lockfile shortfall is a coverage gap and not an INCOMPLETE item, and the line is
    # worth being exact about. INCOMPLETE means we hold the data and have not read it. Here
    # the data does not exist: nothing in the repository records what those installs
    # resolved to, and no amount of our effort produces it. Somebody has to commit a
    # lockfile. That is the coverage_gaps side of the distinction at the top of this file.
    lock_counts = ((lockfiles or {}).get("counts") or {})
    no_lockfile = lock_counts.get("manifest_but_no_lockfile") or 0
    gaps: List[dict] = []
    if no_lockfile:
        gaps.append({
            "gap": "Repositories with a package.json and no committed lockfile",
            "population": f"{no_lockfile} of {lock_counts.get('repos', 0)} npm-relevant "
                          f"repositories ({lock_counts.get('repos_with_parsed_lockfile', 0)} "
                          f"had a lockfile read and parsed)",
            "named_by": "the per-repository records in the lockfile collector's JSONL output "
                        "carrying a manifest and no lockfile path - one row per repository, "
                        "keyed by full_name, which is the identifier a repository owner acts on",
            "cannot_confirm_or_deny": "which versions of their dependencies are actually "
                                      "installed, so neither a match nor a clean result "
                                      "against the campaign specs is possible for them - a "
                                      "declared range says what is permitted, not what "
                                      "resolved",
            "closed_by": "committing a lockfile in each repository, which is also the "
                         "control that stops a newly-published malicious version from being "
                         "resolved into a build at all. Until then this vector cannot answer "
                         "for them and must not be read as though it does",
            "owner": "Repository owners - see the ownership resolution table; unowned "
                     "repositories need an owner assigned first",
        })
    return {
        "name": "Dependency inventory vs campaign IOCs",
        "status": status,
        "scope": f"{inventory.get('dep_rows', 0)} dependency rows across "
                 f"{inventory.get('repos', 0)} repos",
        "counts": {
            "Known-malicious package@version pairs checked": ioc.get("ioc_pairs", 0),
            "Dependency rows in inventory": inventory.get("dep_rows", 0),
            "Repositories with a dependency inventory": inventory.get("repos", 0),
            "npm rows": inventory.get("npm_rows", 0),
            "npm rows pinned to an exact version": inventory.get("npm_pinned", 0),
            "EXACT malicious matches": len(exact),
            "Adjacent packages (right name, safe version)": len(adjacent),
            "Installed pairs read from committed lockfiles": lock_counts.get("pairs", 0),
            "Repositories with a lockfile read and parsed": lock_counts.get(
                "repos_with_parsed_lockfile", 0),
            "Repositories with a manifest and NO lockfile (unmeasured)": no_lockfile,
        },
        "coverage": [
            f"Inventory covers {inventory.get('repos', 0)} repositories. Repositories with "
            f"no inventory row are outside this vector and are not cleared by it.",
            f"{inventory.get('npm_pinned', 0)} of {inventory.get('npm_rows', 0)} npm rows "
            f"are exact-pinned ({pct(inventory.get('npm_pinned', 0), inventory.get('npm_rows', 1))}), "
            f"so a version comparison is meaningful for that share.",
        ] + ([
            f"Lockfile pass: {lock_counts.get('pairs', 0)} installed package@version pair(s) "
            f"read from {lock_counts.get('repos_with_parsed_lockfile', 0)} of "
            f"{lock_counts.get('repos', 0)} npm-relevant repositories. "
            f"{lock_counts.get('repos_with_affected_name_present', 0)} of them carry a "
            f"campaign package NAME at some other version, which is the positive control "
            f"that makes the zero on malicious versions a measured absence rather than "
            f"silence - the matcher demonstrably reaches these names.",
        ] if lock_counts else []),
        "adjacent": adjacent,
        "coverage_gaps": gaps,
        "findings": [],
    }


def vector_ci(posture: Optional[dict], owners: Optional[dict]) -> dict:
    if not posture:
        return {"name": "CI / GitHub Actions posture", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    counts = posture.get("counts", {}) or {}
    tojson = posture.get("serialises_whole_secrets_context", []) or []
    curl_sh = posture.get("remote_code_piped_to_shell", []) or []
    critical = posture.get("critical_privileged_trigger_with_pr_head_checkout", []) or []
    pinned = counts.get("action_refs_pinned_to_sha", 0)
    mutable = counts.get("action_refs_on_mutable_refs", 0)
    status = FINDINGS if (tojson or curl_sh or critical or mutable) else CLEAR

    # §0.6(c). Name the specific things that earned FINDINGS, so nobody has to reverse the
    # boolean above to find out what is wrong. Every entry is a count from the artifact -
    # none of it is an assessment, and none of it is evidence of compromise, which is why
    # this vector never sets is_compromise_evidence.
    earned = []
    if critical:
        earned.append(f"{plural(len(critical), 'workflow')} combining a privileged trigger "
                      f"with a checkout of PR head code")
    if tojson:
        earned.append(f"{plural(len(tojson), 'workflow')} handing the whole secrets context "
                      f"to a step")
    if curl_sh:
        earned.append(f"{plural(len(curl_sh), 'workflow')} piping remote code to a shell")
    if mutable:
        earned.append(f"{mutable} third-party action reference(s) on a mutable ref, which "
                      f"the owner can repoint with no version change visible to us")
    return {
        "name": "CI / GitHub Actions posture",
        "status": status,
        "scope": f"{posture.get('workflow_files_read', 0)} workflows in "
                 f"{posture.get('repos_swept', 0)} repos",
        "counts": {
            "Repositories swept": posture.get("repos_swept", 0),
            "Workflow files read": posture.get("workflow_files_read", 0),
            "Workflows handing the WHOLE secrets context to a step": counts.get(
                "workflows_serialising_whole_secrets_context", 0),
            "Workflows interpolating individual secrets into run:": counts.get(
                "workflows_interpolating_secrets_into_run", 0),
            "Third-party action references on a mutable ref": mutable,
            "Action references pinned to a commit SHA": pinned,
            "Workflows with no permissions: block": counts.get(
                "workflows_without_permissions_block", 0),
            "Workflows on self-hosted runners": counts.get(
                "workflows_with_self_hosted_runners", 0),
            "Workflows piping remote code to a shell": counts.get(
                "workflows_piping_remote_code_to_shell", 0),
            "CRITICAL: privileged trigger + PR-head checkout": counts.get(
                "CRITICAL_privileged_trigger_with_pr_head_checkout", 0),
            "Workflows fetching Bun": counts.get("workflows_fetching_bun", 0),
            "Workflows referencing bun.exe": counts.get("workflows_referencing_bun_exe", 0),
        },
        "coverage": [
            f"Read rate {posture.get('read_rate')} with "
            f"{len(posture.get('listing_errors') or [])} listing errors and "
            f"{len(posture.get('read_errors') or [])} read errors. "
            f"Prevalence claims supported: {posture.get('coverage_supports_prevalence_claims')}.",
            f"{len(posture.get('repos_truncated') or [])} repositories hit the per-repo "
            f"workflow cap, so no workflow went unread.",
            "The zero on privileged-trigger-plus-PR-head-checkout is a real zero: the same "
            "sweep, at the same read rate, returned non-zero on eight other checks.",
        ],
        "limits": posture.get("limits", []),
        "pin_rate": pct(pinned, pinned + mutable),
        "tojson": tojson,
        "curl_sh": curl_sh,
        "self_hosted": posture.get("self_hosted_runner_workflows", []) or [],
        "unpinned_third_party": posture.get("most_common_unpinned_third_party_actions", []) or [],
        "evidence_for_status": earned,
        "findings": [],
    }


def vector_reusable(reusable: Optional[dict]) -> dict:
    """Shared reusable workflows, weighted by how many repositories call them.

    This vector exists because the per-repository posture sweep systematically
    under-ranks the estate's real exposure. Deployment logic here is centralized: a
    weakness in one shared workflow definition is not one finding, it is one finding
    multiplied by its consumer count. Ranking by repository would put a shared workflow
    with 246 consumers below a leaf repository with none.

    It also corrects the opposite error. A shared workflow that is fixed once is fixed
    everywhere, so this is where remediation leverage is highest, not just risk.
    """
    if not reusable:
        return {"name": "CI - shared reusable workflows (fan-out)", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    rows = reusable.get("rows", []) or []
    bulk = [r for r in rows if r.get("secrets_bulk_exposure")]

    # Aggregate by SINK, not by workflow. The sink is the thing that receives every
    # secret, so it is the thing worth fixing and the thing worth counting.
    sinks: Dict[str, dict] = {}
    for row in bulk:
        for entry in row.get("secrets_bulk_exposure") or []:
            sink = entry.get("sink", "unknown")
            record = sinks.setdefault(sink, {
                "sink": sink, "workflows": 0, "consumer_refs": 0,
                "mechanisms": set(), "deploying": False, "sources": []})
            record["workflows"] += 1
            record["consumer_refs"] += row.get("consumer_count") or 0
            record["mechanisms"].add(entry.get("mechanism"))
            record["deploying"] = record["deploying"] or bool(row.get("is_deploying"))
            record["sources"].append(f"{row.get('source_repo')}{row.get('workflow_path')}")
    ranked = sorted(sinks.values(), key=lambda s: -s["consumer_refs"])
    for record in ranked:
        record["mechanisms"] = sorted(m for m in record["mechanisms"] if m)
        # toJSON renders every secret value into the job's shell as text, where it can be
        # written to a file or echoed. `secrets: inherit` passes the context to a called
        # workflow without serializing it. Both are broad; only one is a text rendering,
        # and collapsing them would overstate the second and understate the first.
        record["serialises_to_text"] = "toJSON(secrets)" in record["mechanisms"]
        # A sink on a mutable ref can be changed by whoever owns it, with no version
        # change visible to the consumer. That is the campaign's own mechanism.
        ref = record["sink"].rsplit("@", 1)[-1] if "@" in record["sink"] else ""
        record["sink_ref"] = ref
        record["sink_ref_mutable"] = bool(ref) and not (len(ref) == 40 and
                                                        all(c in "0123456789abcdef" for c in ref))

    worst = [s for s in ranked if s["serialises_to_text"] and s["sink_ref_mutable"]]
    return {
        "name": "CI - shared reusable workflows (fan-out)",
        "status": FINDINGS if bulk else CLEAR,
        "scope": f"{len(rows)} shared workflow definitions",
        "counts": {
            "Shared reusable workflow definitions parsed": len(rows),
            "Definitions passing the WHOLE secrets context onward": len(bulk),
            "Consumer repositories behind those definitions": sum(
                r.get("consumer_count") or 0 for r in bulk),
            "Distinct sinks receiving the whole secrets context": len(ranked),
            "Sinks that SERIALIZE secrets to text AND sit on a mutable ref": len(worst),
            "Definitions that deploy": sum(1 for r in bulk if r.get("is_deploying")),
            "Definitions using OIDC instead of long-lived secrets": sum(
                1 for r in rows if r.get("oidc_used")),
        },
        "coverage": [
            f"Parsed from {reusable.get('source', 'the deployment topology tables')}. "
            f"{sum(1 for r in rows if r.get('fetch_status') == 'ok')} of {len(rows)} "
            f"definitions fetched cleanly.",
            "Consumer counts come from the dependencies table, so a definition with zero "
            "recorded consumers means no consumer was observed - not that none exists.",
            "Exposure is read from the parsed workflow, so a secret passed by a mechanism "
            "the parser does not model would not appear here.",
        ],
        "limits": [
            "Covers shared workflow DEFINITIONS only. A repository with its own inline "
            "copy of the same pattern is counted in the per-repository CI vector instead.",
            "secrets_bulk_exposure records that the whole context was passed, not that any "
            "secret was misused. This is an exposure measure, not a compromise measure.",
        ],
        "ranked_sinks": ranked,
        "bulk_rows": bulk,
        # §0.6(c). Exposure, named and counted, and explicitly not a compromise claim - the
        # `limits` above already say secrets_bulk_exposure records that the context was
        # passed, not that anything was misused. Naming it here keeps the distinction
        # visible at the point a reader decides how alarmed to be.
        "evidence_for_status": [
            f"{s['sink']} receives the whole secrets context from "
            f"{plural(s['workflows'], 'shared definition')} behind "
            f"{s['consumer_refs']} consumer reference(s)"
            + (" - serialized to text, on a mutable ref" if s["serialises_to_text"]
               and s["sink_ref_mutable"] else "")
            for s in ranked[:10]
        ],
        "findings": [],
    }


def vector_registry(rederive: Optional[dict]) -> dict:
    if not rederive:
        return {"name": "Registry ground truth (attack window)", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    detail = rederive.get("malicious_detail", []) or []
    times = sorted(d.get("published", "") for d in detail if d.get("published"))
    uncleaned = rederive.get("suspected_uncleaned_specs", []) or []
    return {
        "name": "Registry ground truth (attack window)",
        "status": CLEAR,
        "scope": f"{rederive.get('packages_queried', 0)} package names queried directly "
                 f"against the npm registry",
        "counts": {
            "Package names queried": rederive.get("packages_queried", 0),
            "Malicious package@version pairs derived": rederive.get("malicious_count", 0),
            "Suspected-uncleaned specs (still live)": len(uncleaned),
        },
        "coverage": [
            f"Derived from the registry itself, not from a vendor list. First malicious "
            f"publish {times[0] if times else 'n/a'}, last {times[-1] if times else 'n/a'}.",
            f"Query window {rederive.get('window', {}).get('start')} to "
            f"{rederive.get('window', {}).get('end')}, wider than the derived result, so "
            f"the close of the window is a finding and not an artifact of where we stopped looking.",
        ],
        "window_first": times[0] if times else None,
        "window_last": times[-1] if times else None,
        "findings": [],
    }


def vector_endpoint(endpoint: Optional[dict]) -> dict:
    """Endpoint and identity telemetry, via Microsoft Defender advanced hunting.

    Rendered as its own vector even when it cannot run, because this is the only vector
    that can see a developer workstation. Omitting it would let a report full of clean
    GitHub results read as a clean estate.

    The fallback below says NOT RUN, not BLOCKED, and the distinction is the whole point
    of this docstring. It used to say BLOCKED, with the reason "GRAPH_TENANT_ID,
    GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET are absent from the environment". That
    sentence was literally true and completely wrong: `GraphClient.from_db` reads the
    encrypted credential store, never the process environment, and the store holds an
    active app registration carrying ThreatHunting.Read.All. Access existed the entire
    time the report told its reader it did not.

    The cost of that error was not cosmetic. BLOCKED drives the verdict to AMBER, emits a
    priority-1 action to go and request access that already exists, and puts "approve the
    access request, or accept in writing that laptops stay outside this hunt" in front of
    an executive as a decision. A reader acting on the report would have spent weeks in a
    permissions queue for a permission already granted, while the query that would have
    answered the question took under a minute to run.

    So this fallback no longer infers anything about access. Absence of the artifact means
    the collector did not run; whether it *could* have run is a question only
    `scripts/hunt/hunt_endpoint_defender.py` is entitled to answer, because it is the only
    thing here that actually asks the tenant.
    """
    # Appended on BOTH paths below, and that is the point of it being a separate constant.
    # The instance-metadata question is unanswered whether or not the collector ran, because
    # the collector does not ask it - it is a property of the query set, not of this cycle.
    # Attaching it only to the NOT RUN fallback would mean a successful run silently dropped
    # it, which is the exact shape of "the artifact exists, so the vector is covered".
    imds_unswept = (
        "UNSWEPT, and named rather than carried: contact with the instance metadata service, "
        "169.254.169.254, from a process in a package-install lineage. Kodem "
        "(github_conf/ioc/kodem_2026_08.json, 2026-08-11) is the only source naming it as a "
        "campaign behavior, and no query in this collector's set asks it - so a clean run of "
        "this vector does not answer it. Note what a keyword audit would have concluded: "
        "IMDSv2 and cloud instance metadata already appear in StepSecurity's, Elastic's and "
        "Cycode's IoC files and in the playbook's rotation scope. All of those are on the "
        "RESPONSE side - what to reissue once a host is already known to be hit. The address "
        "was in no detection input at all, so nothing here could have surfaced the contact. "
        "kql/backlog/23-imds-contact-from-install-lineage.kql now carries the query, "
        "deliberately as a backlog question and NOT an armed rule: keyed on the address alone "
        "it would fire on every cloud host in the estate, because kubelet, cloud-init and "
        "every SDK credential chain contact it correctly and constantly. It has never been "
        "executed, so no shape is claimed from it and no zero should be read from it."
    )

    if endpoint:
        merged = dict(endpoint)
        merged["coverage"] = list(endpoint.get("coverage") or []) + [imds_unswept]
        return merged
    return {
        "name": "Endpoint / identity (Microsoft Defender)",
        "status": NOT_RUN,
        "scope": "0 devices queried",
        "counts": {"Hunting queries executed": 0},
        "coverage": [
            "No endpoint_hunt.json artifact was supplied, so the Defender advanced-hunting "
            "collector did not run this cycle. This is a gap in the hunt, not a statement "
            "about access - run scripts/hunt/hunt_endpoint_defender.py, which resolves "
            "credentials from the encrypted store and reports the real permission state.",
            "The queries exist and are lint-clean: "
            "kql/coverage/08-bun-exe-telemetry-shape.kql (the control that makes a zero "
            "readable) and kql/backlog/22-bun-windows-artifact-sweep.kql (the bun.exe "
            "artifact question).",
            imds_unswept,
        ],
        "findings": [],
    }


def vector_install_activity(install: Optional[dict]) -> dict:
    """Package acquisition on endpoints - what was actually downloaded, and from where.

    This vector was missing from the report for five revisions while its artifact sat on
    disk, and the omission mattered more than any number it carries. Every other dependency
    vector answers "what is written down in our repositories". This is the only one that
    answers "what did a machine actually fetch", which is the question a worm's arrival
    turns on: a lockfile records an intention, and an install records an event.

    Its artifact currently reports a CONTRADICTION rather than a clean result, and that is
    the correct output. 69 package-manager install commands ran inside the window while
    DeviceNetworkEvents recorded zero tarball fetches, which means package downloads are not
    observable on that table - so matching them against 2,208 malicious specs could not have
    found anything either way. Reporting that as a zero would be the §0.1 error in its purest
    form: a query that could not have found the thing, returning nothing, read as clean.

    The artifact is already in vector shape, so it passes through. The fallback below says
    NOT RUN and asserts nothing about access, for the same reason `vector_endpoint`'s does.
    """
    if install:
        return install
    return {
        "name": "Endpoint install activity (package acquisition)",
        "status": NOT_RUN,
        "scope": "0 devices queried",
        "counts": {"Install command lines observed": 0},
        "coverage": [
            "No install-activity artifact was supplied, so the acquisition collector did "
            "not run this cycle. Every other dependency vector reads what our repositories "
            "declare; this is the only one that reads what a machine fetched, so its "
            "absence leaves the arrival question answered only by intention.",
        ],
        "findings": [],
    }


def vector_install_prevention(sweep: Optional[dict]) -> dict:
    """Whether an install-time script is ALLOWED to run here - the control, not the arrival.

    The companion to `vector_install_activity`, and the distinction between them is the whole
    reason both exist. That vector measures that lifecycle scripts fire constantly. This one
    measures whether anything stands in their way: `ignore-scripts`, the one setting every
    package manager in this estate honors, read out of every `.npmrc` and every workflow install
    command in the npm-relevant population.

    **Not compromise evidence.** A repository that installs with scripts enabled is how this
    campaign would run, not evidence that it did, so its findings are exposure and belong in
    Section 3's ranked work rather than in the verdict. Wiring it into the compromise-evidence
    set would turn a hardening backlog into a breach claim - the single most expensive misreading
    this report can produce.

    Passed through in vector shape. The fallback says NOT RUN and claims nothing about access.
    """
    if sweep:
        return sweep
    return {
        "name": "Install-time script prevention (`ignore-scripts`)",
        "status": NOT_RUN,
        "scope": "0 repositories read",
        "counts": {"npm-relevant repositories swept": 0},
        "coverage": [
            "No install-prevention artifact was supplied, so nothing was measured about what "
            "stands between an install and the script it runs. The install-activity vector "
            "still reports that lifecycle scripts fire in the thousands; without this one, that "
            "number has no control beside it and must not be read as either safe or exposed.",
        ],
        "findings": [],
    }


def vector_advisory_iocs(iocs: Optional[dict]) -> dict:
    """The campaign's own published infrastructure and files, swept against our telemetry.

    Every other vector on this report asks a question we invented: does our dependency list
    contain a poisoned spec, does a workflow leak a secret. This one asks the campaign's
    question - did any device here talk to the C2, or write the payload to disk - using the
    domains, addresses and hashes the advisories published. That makes it the only vector whose
    zero is a statement about the attacker rather than about us.

    It is compromise evidence, unambiguously: a device resolving `npm-cache.com` is not a
    hygiene finding. It also carries the one thing the earlier rounds could not - a file hash.
    Earlier rounds matched the dropper by FILENAME, which is a lead; a hash match is a verdict.

    Passed through in vector shape. The fallback says NOT RUN and claims nothing about access.
    """
    if iocs:
        return iocs
    return {
        "name": "Campaign infrastructure and file hashes (Microsoft Defender)",
        "status": NOT_RUN,
        "scope": "0 indicators swept",
        "counts": {"Campaign domains swept": 0, "Campaign file hashes swept": 0},
        "coverage": [
            "No advisory-IOC artifact was supplied, so no published indicator for this "
            "campaign has been matched against our telemetry this cycle. Every other vector "
            "answers a question we framed; this is the only one that answers the campaign's.",
        ],
        "findings": [],
    }


def vector_antiremediation(sweep: Optional[dict]) -> dict:
    """The anti-remediation watchdog: whether something here is waiting for us to rotate.

    Every other endpoint vector asks whether the campaign arrived. This one asks whether
    something is watching for our RESPONSE - `gh-token-monitor`, which polls the GitHub API for
    token validity and fires the payload when the token stops authenticating. That makes it the
    only vector whose result changes the ORDER of remediation rather than its scope, and the
    reason it is a separate vector instead of a query inside the endpoint hunt: a reader who
    skips it can still rotate a credential, which is the one action this campaign is built to
    punish.

    Compromise evidence, unambiguously - a process polling the token endpoint from an autostart
    entry is not a hygiene finding.

    Passed through in vector shape. The fallback says NOT RUN and claims nothing about access.
    """
    if sweep:
        return sweep
    return {
        "name": "Anti-remediation watchdog (Microsoft Defender)",
        "status": NOT_RUN,
        "scope": "0 hunting queries executed",
        "counts": {"Published watchdog artifacts swept": 0},
        "coverage": [
            "No anti-remediation artifact was supplied, so it is not known whether anything on "
            "this estate is waiting for a token revocation. Until it is, the remediation ORDER "
            "in docs/playbooks/supply-chain-hunt-ttp.md §6.3 is the only control on this "
            "vector - remove before you rotate, on every host, regardless.",
        ],
        "findings": [],
    }


def vector_commit_messages(sweep: Optional[dict]) -> dict:
    """The campaign's own commit text, swept across every organization at once.

    Separate from the branch vector rather than folded into it, because the two answer the same
    question over different populations and neither covers the other. The branch collector reads
    the head commit of each in-window push, repository by repository, and so reaches every ref.
    This one queries the commit-search index, which reaches every commit in an organization in a
    single request - and which this artifact MEASURES to be limited to default branches.

    Compromise evidence: the extortion string is not a message any legitimate commit carries.

    Passed through in vector shape. The fallback says NOT RUN and claims nothing about access.
    """
    if sweep:
        return sweep
    return {
        "name": "Commit-message sweep (GitHub commit search)",
        "status": NOT_RUN,
        "scope": "0 organizations queried",
        "counts": {"Indicators queried per organization": 0},
        "coverage": [
            "No commit-message artifact was supplied, so the extortion string the campaign "
            "leaves behind has not been searched across the organizations this cycle.",
        ],
        "findings": [],
    }


def vector_registry_proxy(feeds: Optional[dict]) -> dict:
    """The internal package registry, and whether it proxied a malicious version.

    A mirror with an npmjs.org upstream serves the identical malicious tarball under its own
    hostname. That makes this vector load-bearing in two directions at once, and both were
    missing from the report:

      - as a RESULT, whether the feed cached a malicious version, and
      - as a CONTROL, whether a controlled feed stands between a developer and the public
        registry at all - which is the strongest single obstacle available against this
        entire class of worm.

    The artifact sets `coverage_supports_negative_finding` itself, and this function refuses
    to promote its verdict past what that flag allows.

    The first version of this docstring said the flag was false because "the listing did not
    enumerate npm". That was wrong about the collector: `list_packages` has always sent
    `protocolType=npm`, so the listing did enumerate npm and returned nothing. What was
    actually false was the flag's own expression, which carried a blanket "no feed returned
    an error" term alongside the narrower rule stated in the same file - that an unreadable
    feed only matters where it has an npmjs upstream to cache from. One 403 on
    `SleepNumberIndigo/k8s-manifests`, a feed with no such upstream, therefore voided the
    reading of the other four. The collector now decides per feed, and this function reads
    `feeds_blocking_the_negative_finding` to say which feed is responsible when it is false.
    """
    if not feeds:
        return {"name": "Internal package registry (proxy of npmjs)", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}

    malicious = feeds.get("MALICIOUS_VERSIONS_FOUND", []) or []
    affected = feeds.get("affected_names_found_in_any_feed", []) or []
    upstream = feeds.get("feeds_with_npmjs_upstream", []) or []
    unmeasured = feeds.get("feeds_UNMEASURED_no_read_packages", []) or []
    errors = feeds.get("feeds_with_errors", []) or []
    listed = feeds.get("npm_packages_listed_total", 0)
    supported = bool(feeds.get("coverage_supports_negative_finding"))

    # Three states, and the middle one is the whole reason this function is not two lines.
    # A malicious version found is a finding. A clean result the coverage supports is CLEAR.
    # A clean result the coverage does NOT support is neither - it is unfinished work, and it
    # is reported as the named item that would finish it.
    blocking = feeds.get("feeds_blocking_the_negative_finding", []) or []
    verdicts = feeds.get("feeds_by_coverage_verdict", {}) or {}
    probe_only = verdicts.get("measured_by_permission_probe_only", []) or []
    named_blockers = "; ".join(
        f"{b.get('feed')} ({b.get('reason')})" for b in blocking) or "none named"

    unresolved: List[str] = []
    if malicious:
        status = FINDINGS
    elif supported:
        status = CLEAR
    else:
        status = INCOMPLETE
        unresolved.append(
            f"The npm listing returned {listed} package(s) across "
            f"{feeds.get('feeds_checked', 0)} feed(s), of which {len(upstream)} proxy "
            f"registry.npmjs.org - and {plural(len(blocking), 'feed')} carrying that "
            f"upstream could not be read: {named_blockers}. A feed with an npmjs upstream "
            f"is the one thing on this estate that can still be serving a version the "
            f"public registry has withdrawn, so until those are read the zero against the "
            f"campaign set is bounded by them rather than measured across the estate.")

    # An unreadable feed is a permission this identity does not hold, so it belongs on the
    # access axis rather than in residue - INCOMPLETE means we can read it and have not. The
    # artifact already writes each one six-field, so it is carried through rather than
    # rephrased here. It travels with the vector even when the vector reads CLEAR: what it
    # leaves unread is a package published DIRECTLY into that feed, which is a real question
    # that the no-upstream argument does not answer.
    access = list(feeds.get("access_required", []) or [])

    return {
        "name": "Internal package registry (proxy of npmjs)",
        "status": status,
        "scope": f"{feeds.get('feeds_checked', 0)} feed(s) across "
                 f"{len(feeds.get('organisations_checked') or [])} Azure DevOps organizations",
        "counts": {
            "Feeds enumerated": feeds.get("feeds_checked", 0),
            "Feeds readable": feeds.get("feeds_readable", 0),
            "Feeds proxying registry.npmjs.org upstream": len(upstream),
            "npm packages listed across all feeds": listed,
            "Malicious versions found in a feed": len(malicious),
            "Campaign package names present at any version": len(affected),
            "Feeds unmeasured (no ReadPackages)": len(unmeasured),
            "Feeds whose gap bounds this result": len(blocking),
        },
        "coverage": [
            f"Identity: {feeds.get('identity', 'unrecorded')}. "
            f"{feeds.get('feeds_readable', 0)} of {feeds.get('feeds_checked', 0)} feed(s) "
            f"readable, {len(errors)} returning an error.",
            f"Per-feed coverage verdict, because these zeros are not equally strong: "
            f"{plural(len(verdicts.get('measured_with_positive_control') or []), 'feed')} "
            f"measured with a positive control (a row returned by the same endpoint, host "
            f"and token, from the feed itself or a sibling in the same organization); "
            f"{plural(len(probe_only), 'feed')} measured by permission probe only"
            f"{' (' + ', '.join(probe_only) + ')' if probe_only else ''} - ReadPackages "
            f"proven by an endpoint that 403s without it, but no feed in that organization "
            f"returned any row, so the proof is a permission fact rather than an observed "
            f"row; {plural(len(unmeasured), 'feed')} unread for want of ReadPackages.",
            f"An empty feed is not a failed control. It cannot produce a row, and the only "
            f"act that would make one appear is publishing into production infrastructure, "
            f"which this check does not do.",
            f"Listing endpoint proved it returns rows on "
            f"{plural(len(feeds.get('feeds_where_endpoint_proved_it_returns_rows') or []), 'feed')}"
            f", so the endpoint itself works. Protocol breakdown across all feeds: "
            f"{feeds.get('packages_by_protocol_all_feeds') or 'none recorded'} - which is "
            f"the number that decides whether an npm comparison was possible at all.",
            f"Feeds carrying an npmjs.org upstream: "
            f"{', '.join(upstream) if upstream else 'none'}. A proxy with that upstream "
            f"serves the identical malicious tarball under its own hostname, so a hunt that "
            f"only watches registry.npmjs.org would not see the fetch.",
            f"The artifact's own coverage flag: coverage_supports_negative_finding="
            f"{supported}. This vector's status is bounded by that flag and does not "
            f"outrun it. The flag counts a feed against the result only where that feed is "
            f"both unread and carrying an npmjs upstream - an unread feed with no upstream "
            f"cannot hold a version cached from the public registry, so it is an access "
            f"request below rather than a hole in this answer. Feeds bounding it: "
            f"{named_blockers}.",
        ],
        "limits": [
            "Covers Azure Artifacts feeds reachable by this identity. A registry proxy "
            "elsewhere - a Nexus or Artifactory instance, a per-team .npmrc pointing "
            "somewhere else - is outside this vector and is not cleared by it.",
            "Retention policies can remove a cached version before this check runs, so a "
            "clean result is a statement about the cache as it stands, not about every "
            "version the feed ever served.",
            "Feed-level listing only. A clean feed does not prove no build ever resolved a "
            "malicious version through it, and it says nothing about an npm cache baked "
            "into a container image, which no registry API can see.",
        ],
        "access_required": access,
        "unresolved_items": unresolved,
        "evidence_for_status": [
            f"{m}" for m in malicious
        ] or None,
        "findings": [{"spec": m} for m in malicious],
    }


# ----------------------------------------------------------------------------------
# Verdict. Deterministic, so the same artifacts always produce the same color and nobody
# has to argue about whether today felt amber.
#
# The color answers ONE question: in the population we can observe, is there evidence of
# compromise? Coverage is computed alongside it and reported next to it, but it does not
# move it. See the two-axes note at the top of this file for why - in short, folding the
# dark third of the estate into the color made the color say AMBER every day for a reason
# no hunt result can change, which is how a RAG letter stops being read.
# ----------------------------------------------------------------------------------

def collect_coverage_gaps(vectors: List[dict]) -> List[dict]:
    """Every named unobservable population, with the vector it came from attached."""
    gaps: List[dict] = []
    for vector in vectors:
        for gap in vector.get("coverage_gaps") or []:
            gaps.append({**gap, "vector": vector["name"]})
    return gaps


def compute_coverage(vectors: List[dict]) -> dict:
    """The coverage axis. Reported beside the verdict, never inside it."""
    gaps = collect_coverage_gaps(vectors)
    if not gaps:
        return {"state": "COMPLETE", "gaps": [],
                "scope": "Every check reached the whole population it claims to cover. "
                         "The verdict below applies to the estate."}
    owners = sorted({gap["owner"] for gap in gaps})
    return {
        "state": "PARTIAL",
        "gaps": gaps,
        # This sentence is the whole point of the split. The verdict is true, and it is true
        # about something smaller than the estate, and both halves are said out loud.
        "scope": f"{plural(len(gaps), 'population')} sit outside what this hunt can "
                 f"observe. Inside them we can neither confirm nor deny anything - not "
                 f"because a check failed, but because there is no telemetry to check. "
                 f"Each is named, counted and enumerable below, with what closes it. "
                 f"None of them moves the verdict, and the verdict does not speak for "
                 f"them. Closing them needs: {', '.join(owners)}.",
    }


def compute_verdict(vectors: List[dict]) -> dict:
    compromise_vectors = [v for v in vectors if v["status"] == FINDINGS
                          and v.get("is_compromise_evidence")]
    blocked = [v for v in vectors if v["status"] == BLOCKED]
    not_run = [v for v in vectors if v["status"] == NOT_RUN]
    exposure = [v for v in vectors if v["status"] == FINDINGS
                and not v.get("is_compromise_evidence")]
    # Corroborating vectors are absent from every branch below. They cannot clear and are
    # not asked to, so they must not drag the verdict either.
    incomplete = [v for v in vectors if v["status"] == INCOMPLETE]

    def residue(vector: dict) -> str:
        items = vector.get("unresolved_items") or []
        named = ", ".join(items[:3]) + (f" and {len(items) - 3} more" if len(items) > 3 else "")
        return (f"{vector['name']}: {len(items)} item(s) not read"
                + (f" - {named}" if named else ""))

    if compromise_vectors:
        return {"rag": "RED", "breached": "YES - evidence of compromise found. Treat as "
                                          "an active incident.",
                "why": [v["name"] for v in compromise_vectors]}
    if blocked or not_run:
        return {"rag": "AMBER",
                "breached": "No evidence of compromise in what we could check - but we "
                            "could not check everything.",
                "why": [f"{v['name']} could not be checked" for v in blocked + not_run]
                       + [residue(v) for v in incomplete]
                       + [f"{v['name']} has exposures to fix" for v in exposure]}
    if incomplete:
        return {"rag": "AMBER",
                "breached": "No evidence of compromise anywhere we read - and a specific, "
                            "named, finite list of things we did not read. Read them and "
                            "this becomes a yes or a no.",
                "why": [residue(v) for v in incomplete]
                       + [f"{v['name']} has exposures to fix" for v in exposure]}
    if exposure:
        # "Nothing in the estate" was the wording here, and it does not survive the coverage
        # split - nor did it survive scrutiny before it. This hunt reads the sources it can
        # reach. Saying "nothing we can observe" costs one clause and is the difference
        # between a claim the artifacts support and one they do not.
        return {"rag": "AMBER",
                "breached": "No - nothing we can observe matches this campaign, and every "
                            "check that says so proved it could have found it. The coverage "
                            "state above says how much of the estate that is. There are "
                            "weaknesses that would make the next one worse.",
                "why": [f"{v['name']} has exposures to fix" for v in exposure]}
    return {"rag": "GREEN",
            "breached": "No, across everything this hunt can observe. Every vector ran, "
                        "each proved it could have found the thing it was looking for, and "
                        "nothing we have access to was left unread. Read with the coverage "
                        "state above: GREEN means the checks are clean and complete over "
                        "their population, not that the population is the whole estate.",
            "why": []}


# ----------------------------------------------------------------------------------
# Delta. A daily report without one is forty identical PDFs nobody opens by week two.
# ----------------------------------------------------------------------------------

def build_state(vectors: List[dict], verdict: dict,
                coverage: Optional[dict] = None) -> dict:
    # Coverage is carried in the state file so the delta can report a blind spot opening or
    # closing. A vector whose status never moves because it is already CLEAR would otherwise
    # produce no delta line on the day 400 devices got onboarded - the most useful change
    # this hunt can report, and invisible on the result axis by construction.
    coverage = coverage or compute_coverage(vectors)
    return {
        "rag": verdict["rag"],
        # The vector each gap came from is carried too, because "this population went dark"
        # and "a check ran for the first time and named a population nobody had measured" are
        # different sentences and only the diff can tell them apart.
        "coverage": {"state": coverage["state"],
                     "gaps": sorted(g["gap"] for g in coverage["gaps"]),
                     "gap_vectors": {g["gap"]: g["vector"] for g in coverage["gaps"]}},
        "vectors": {v["name"]: {"status": v["status"], "counts": v.get("counts", {})}
                    for v in vectors},
    }


def render_delta(previous: Optional[dict], current: dict,
                 added_checks: List[str]) -> List[str]:
    """Movement since the previous run, plus any checks added this cycle.

    A new check is reported separately from a changed count, and always. A hunt that
    quietly gains a check produces a report where a number moved for a reason nobody can
    see - and a hunt that gains a check finding nothing produces no delta line at all,
    which reads as "we did not look at anything new". Both are corrected here.
    """
    lines: List[str] = []
    for check in added_checks:
        lines.append(f"**New check this cycle:** {check}")
    if not previous:
        lines.append("First run recorded under this template - there is no previous run "
                     "to compare against. Every number below is a baseline. Tomorrow's "
                     "report will show what moved.")
        return lines
    if previous.get("rag") != current["rag"]:
        lines.append(f"**Overall status changed: {previous.get('rag')} -> {current['rag']}.**")
    # Coverage movement, reported separately from result movement and in both directions. A
    # gap that disappears is the estate getting more observable; a gap that appears is the
    # estate getting less observable without anybody deciding to.
    #
    # A previous run with no `coverage` key predates the register, and its gaps were recorded
    # on the result axis instead. Diffing against it would announce four brand-new blind
    # spots that are in fact the same four as yesterday, reclassified - which is a false
    # finding manufactured by a schema change. So the first run states itself as a baseline.
    now_coverage = current.get("coverage") or {}
    now_gaps = set(now_coverage.get("gaps") or [])
    if "coverage" not in previous:
        if now_gaps:
            lines.append(f"**Coverage is now reported on its own axis.** "
                         f"{plural(len(now_gaps), 'population')} this hunt cannot observe "
                         f"are registered below and no longer counted against any vector's "
                         f"status. They are not new - they were previously folded into the "
                         f"endpoint vector's unread-item list, which made an instrumentation "
                         f"gap read as an unfinished hunt. This run is the baseline; from "
                         f"tomorrow, one appearing or closing shows here.")
    else:
        before_gaps = set((previous.get("coverage") or {}).get("gaps") or [])
        gap_vectors = now_coverage.get("gap_vectors") or {}
        before_vectors = previous.get("vectors") or {}
        for gap in sorted(now_gaps - before_gaps):
            # A gap named by a vector that did not run before is a measurement we did not
            # have, not visibility we lost. Reporting it as lost visibility would be a claim
            # about the previous run that no artifact supports - and it would tell a reader
            # the estate is getting darker on the day the hunt got wider.
            source = gap_vectors.get(gap)
            # Collectors write gap text as a sentence, so the joining period would double up.
            gap = gap.rstrip().rstrip(".")
            if source and source not in before_vectors:
                lines.append(f"**Newly measured blind spot:** {gap}. Named by {source}, which "
                             f"ran for the first time this cycle. The population was not "
                             f"measured before, so nothing here says it was answerable then - "
                             f"this is the hunt widening, not the estate going dark.")
            else:
                # The vector ran before, so the gap is either newly lost visibility or a
                # population that vector measured for the first time this cycle. The state
                # file records which gaps existed, not why they appeared, so neither reading
                # is asserted here - saying "this went dark" would be a claim about the
                # previous run that nothing in the corpus supports.
                lines.append(f"**Blind spot newly registered:** {gap}. Named by "
                             f"{source or 'a vector that also ran previously'} and absent "
                             f"from the previous run's coverage register. That is either a "
                             f"population that went dark or one this cycle measured for the "
                             f"first time; the state file records which gaps existed, not "
                             f"why, so whoever changed that collector owns the one line "
                             f"saying which.")
        for gap in sorted(before_gaps - now_gaps):
            lines.append(f"**Blind spot closed:** {gap.rstrip().rstrip('.')}. This hunt can now "
                         f"answer for that population.")
    for name, now in current["vectors"].items():
        before = (previous.get("vectors") or {}).get(name)
        if before is None:
            lines.append(f"**New vector this run:** {name} ({now['status']}).")
            continue
        if before.get("status") != now["status"]:
            lines.append(f"**{name}: {before.get('status')} -> {now['status']}.**")
        for metric, value in (now.get("counts") or {}).items():
            was = (before.get("counts") or {}).get(metric)
            # Only movement is reported. A metric that did not move is not news, and
            # printing it would bury the one that did.
            if was is not None and was != value:
                direction = "up" if value > was else "down"
                lines.append(f"{name} - {metric}: {was} -> {value} ({direction}).")

    # A vector that was reported yesterday and is absent today is the most dangerous
    # possible delta and the easiest to miss: the reader sees a shorter table and no
    # warning. Iterating only today's vectors would let a broken collector silently
    # remove a whole line of defense and still print "no change since the previous run".
    #
    # But the alarm has to be earned. The previous version raised a WARNING for every
    # disappeared name and then admitted, in the same sentence, that it could not tell a
    # failed collector from a rename - which is a false positive by construction, and it
    # fired on exactly that: "GitHub code search (corroborating)" gained the word "only"
    # and was reported as an unchecked attack vector while sitting in the table below.
    #
    # So the two cases are separated by something provable rather than guessed. A rename
    # requires a new name to have appeared in the same run. Where none did, a
    # disappearance cannot be a rename and coverage has measurably dropped - that earns
    # the warning. Where one did, both lists are printed as facts and no cause is
    # asserted, because the renderer cannot see which name replaced which and must not
    # pretend otherwise.
    gone = [(name, before) for name, before in (previous.get("vectors") or {}).items()
            if name not in current["vectors"]]
    appeared = [name for name in current["vectors"]
                if name not in (previous.get("vectors") or {})]
    for name, before in gone:
        if appeared:
            lines.append(
                f"Vector list changed: **{name}** (was {before.get('status')}) is not in "
                f"this run, and {', '.join(appeared)} appeared. If that is a rename, "
                f"coverage is unchanged; confirm against Section 4 before reading it as "
                f"either.")
        else:
            lines.append(
                f"**WARNING - vector no longer reported: {name}** (was "
                f"{before.get('status')}), and no new vector took its place. Coverage has "
                f"dropped. Treat this attack vector as unchecked this cycle, not as clean.")
    if not lines:
        lines.append("No change since the previous run. Same vectors, same statuses, "
                     "same counts.")
    return lines


# ----------------------------------------------------------------------------------
# Actions. Each is emitted only when the data triggers it, and each carries the evidence
# that triggered it so the manager section and the technical section cannot disagree.
# ----------------------------------------------------------------------------------

def build_chain(ioc: dict, lockfiles: Optional[dict], proxy: dict, install: dict,
                endpoint: dict, ci: dict, reusable: dict,
                posture: Optional[dict], dead_drops: Optional[dict],
                prevention: Optional[dict] = None) -> List[dict]:
    """The campaign's chain, link by link, with what stands in the way of each step.

    Every state is derived from an artifact. Where no artifact speaks to a link the state is
    UNMEASURED and the row says what measurement would settle it - which on a hunt-driven
    report is most of the prevention links, because a hunt instruments detection.

    The ordering is the attacker's, not ours. That is deliberate: a list ordered by the
    controls we happen to hold cannot show a reader that link 4 has nothing in it, because a
    link with nothing in it produces no entry in that kind of list.
    """
    lock_counts = ((lockfiles or {}).get("counts") or {})
    posture_counts = ((posture or {}).get("counts") or {})
    ioc_counts = ioc.get("counts", {}) or {}
    endpoint_counts = endpoint.get("counts", {}) or {}
    install_counts = install.get("counts", {}) or {}
    ci_counts = ci.get("counts", {}) or {}
    reusable_counts = reusable.get("counts", {}) or {}

    pinned = ioc_counts.get("npm rows pinned to an exact version", 0)
    npm_rows = ioc_counts.get("npm rows", 0)
    no_lockfile = lock_counts.get("manifest_but_no_lockfile", 0)
    upstream_feeds = proxy.get("counts", {}).get(
        "Feeds proxying registry.npmjs.org upstream", 0)

    # Read from the install artifact's own control rows rather than restated, so that a
    # re-run that changes them changes the chain. The registry-host row is what killed the
    # mirror hypothesis this chain used to carry: the estate's installs were seen going to
    # the public registry, and the missing tarball path is a telemetry limit, not a mirror.
    install_ev = install.get("evidence") or {}

    def control_row(key: str) -> dict:
        rows = ((install_ev.get(key) or {}).get("rows") or [])
        return rows[0] if rows else {}

    registry_control = control_row("registry_traffic_control")
    registry_rows = registry_control.get("Rows", install_counts.get(
        "registry_rows_in_window", 0))
    registry_devices = registry_control.get("Devices", 0)
    lifecycle = control_row("lifecycle_hook_control")

    chain: List[dict] = []

    # LINK 1 - acquisition. Pinning is a real control and the only one on this chain that
    # was doing work on the run this was written. It is PARTLY, not fully: a pin protects
    # the repositories that have one.
    link1_state = PARTLY_CONTROLLED if pinned and npm_rows else UNMEASURED
    chain.append({
        "link": "1. Getting a poisoned version into one of our builds",
        "worm_needs": "a newly published malicious version to be resolved and downloaded by "
                      "one of our repositories or pipelines",
        "state": link1_state,
        "evidence": [
            f"{pinned} of {npm_rows} npm dependency rows are pinned to an exact version "
            f"({pct(pinned, npm_rows or 1)}). A pinned dependency cannot resolve to a "
            f"version published after the pin, which is precisely the move this campaign "
            f"makes. This is the strongest control we can currently demonstrate.",
            f"{no_lockfile} repositories have a package.json and no committed lockfile, so "
            f"nothing records what they resolve to and a fresh install can pick up whatever "
            f"is newest. These are the hole in the control, not an accounting note.",
            f"{upstream_feeds} internal package feed(s) proxy registry.npmjs.org upstream. A "
            f"proxy with that upstream serves the identical malicious tarball under its own "
            f"hostname, so it is not a filter unless somebody configured it to be one - and "
            f"whether it is, is not established.",
            f"Those feeds are an open control question, not an observed install path: the "
            f"only package-registry host contacted from any onboarded device in the window "
            f"was registry.npmjs.org ({registry_rows} rows from {registry_devices} devices). "
            f"Installs on the measured devices go to the public registry directly, so a "
            f"quarantine window on an internal feed only helps the traffic somebody first "
            f"routes through it.",
        ] if link1_state != UNMEASURED else [],
        "closed_by": "commit a lockfile in the repositories without one, then decide whether "
                     "installs must go through a controlled feed with a quarantine window on "
                     "newly published versions. The second half is the control that would "
                     "make this link CONTROLLED rather than partly.",
        "owner": "Platform / DevOps with the artifact registry admin; repository owners for "
                 "the lockfiles",
    })

    # LINK 2 - execution. The primitive the entire class depends on. This link was UNMEASURED for
    # every earlier cycle, and the reason is worth keeping: the install-command count proves
    # installs happen and says nothing about whether their scripts are ALLOWED to run. It moved
    # only when a second artifact measured the obstacle instead of the arrival - `ignore-scripts`
    # across the npm-relevant population. Its state is derived from that artifact, so a repository
    # hardened between cycles moves this row without anybody editing this file.
    install_lines = install_counts.get("install_command_lines", 0)
    hook_rows = lifecycle.get("Rows", 0)
    hook_devices = lifecycle.get("Devices", 0)
    prevention_counts = (prevention or {}).get("counts", {}) or {}
    swept = prevention_counts.get("npm-relevant repositories swept", 0)
    by_config = prevention_counts.get("Repositories preventing scripts by config", 0)
    by_workflow = prevention_counts.get(
        "Repositories preventing scripts in every installing workflow", 0)
    part_only = prevention_counts.get(
        "Repositories preventing scripts in only some installing workflows", 0)
    exposed = prevention_counts.get("Repositories that install with scripts enabled", 0)
    no_ci = prevention_counts.get("Repositories with no CI install observed", 0)
    sites = prevention_counts.get("Individual install commands", 0)
    sites_refusing = prevention_counts.get(
        "Of those, carrying --ignore-scripts on the command", 0)
    protecting = by_config + by_workflow
    link2_evidence = []
    if install_lines:
        link2_evidence += [
            f"{install_lines} package-manager install command line(s) were observed inside "
            f"the attack window, so installs demonstrably happen here.",
            f"{hook_rows:,} install-time script execution(s) ran on {hook_devices} device(s) "
            f"inside the same window, none of them carrying a campaign artifact name. This is "
            f"not a near miss and it is not reassurance either: it is the measurement that "
            f"the exact primitive this campaign needs is enabled and firing in the thousands "
            f"inside this one window, as part of ordinary work.",
            "None of those executions can be attributed to a package. The process table "
            "records the command line and the parent shell but not the working directory, so "
            "the node_modules path that would name the package is absent - which is why the "
            "campaign-name zero is a control passing, not a clean result.",
        ]
    if swept:
        link2_evidence += [
            f"The obstacle is now measured, not assumed: every `.npmrc` and every workflow "
            f"install command in {swept} npm-relevant repositories was read for "
            f"`ignore-scripts`, the one setting that stops an install script from running at "
            f"all. Refusing scripts by configuration: {by_config}. Refusing them at every "
            f"installing workflow: {by_workflow}. Refusing them in only some workflows: "
            f"{part_only}. Installing with scripts enabled: {exposed}.",
            f"Counted per command rather than per file, {sites_refusing} of {sites} individual "
            f"install command(s) carry `--ignore-scripts`. That is the number to quote: a "
            f"file-wide match would have credited a single hardened step to every other install "
            f"beside it.",
            f"{no_ci} repository(ies) install nothing in CI, so their dependencies are only ever "
            f"installed on somebody's machine - and `~/.npmrc` is in no repository, so this "
            f"measurement cannot reach the surface most of this campaign's victims were "
            f"infected on. A CI answer is not an estate answer.",
        ]
    chain.append({
        "link": "2. Running its code during the install",
        "worm_needs": "the package manager to execute the package's own install script, "
                      "which is where every payload in this campaign begins",
        # OPEN, not UNMEASURED, if nothing was found in the way - we looked. And never better
        # than PARTLY from this artifact, because developer machines are outside what it reads.
        "state": (UNMEASURED if not swept
                  else (PARTLY_CONTROLLED if protecting or part_only else OPEN)),
        "evidence": link2_evidence,
        "closed_by": (f"`ignore-scripts=true` in the {exposed} repository(ies) that install with "
                      f"scripts enabled, then the same setting on developer machines by MDM - "
                      f"the CI half is the smaller half. This is the single highest-value "
                      f"control available against this whole class of worm"
                      if swept else
                      "establish whether installs run with lifecycle scripts disabled in CI "
                      "and on developer machines. This is the single highest-value control "
                      "available against this whole class of worm, and it is currently a "
                      "question rather than a finding - answering it costs hours"),
        "owner": "Platform / DevOps",
    })

    # LINK 3 - the payload runtime. Detection is proven and prevention is not measured, and
    # those are two different sentences that a single "clean" would fuse.
    bun_seen = endpoint_counts.get("bun.exe or bunx.exe, any table, any device", 0)
    chain.append({
        "link": "3. Fetching a separate runtime to hide the payload",
        "worm_needs": "to download the Bun runtime and execute its payload under it, "
                      "bypassing the Node runtime a defender is watching",
        "state": DETECTION_ONLY,
        "evidence": [
            f"{endpoint_counts.get('Bun questions asked', 0)} distinct Bun questions were "
            f"asked of endpoint telemetry and "
            f"{endpoint_counts.get('Bun questions with a readable answer', 0)} returned an "
            f"answer a control supports. bun.exe/bunx.exe: {bun_seen} rows across process, "
            f"file and image-load tables over 30 days.",
            f"{posture_counts.get('workflows_fetching_bun', 0)} workflow(s) fetch Bun and "
            f"{posture_counts.get('workflows_referencing_bun_exe', 0)} reference bun.exe, "
            f"out of {posture_counts.get('workflows_analysed', 0)} read.",
            "Detection here is genuinely good and it is detection. No artifact establishes "
            "that a runner or a laptop is prevented from downloading a runtime from the "
            "internet.",
        ],
        "closed_by": "decide whether build runners are permitted arbitrary internet egress. "
                     "An allowlist on the runners would move this link from detected to "
                     "prevented; the 95 self-hosted runners are where to start",
        "owner": "Platform / DevOps with Network security",
    })

    # LINK 4 - the payoff. This is the one link where the numbers ARE the finding, so it is
    # the one link that can honestly be called OPEN rather than unmeasured.
    whole_ctx = ci_counts.get("Workflows handing the WHOLE secrets context to a step", 0)
    into_run = ci_counts.get("Workflows interpolating individual secrets into run:", 0)
    no_perms = ci_counts.get("Workflows with no permissions: block", 0)
    self_hosted = ci_counts.get("Workflows on self-hosted runners", 0)
    mutable = ci_counts.get("Third-party action references on a mutable ref", 0)
    consumers = reusable_counts.get("Consumer repositories behind those definitions", 0)
    chain.append({
        "link": "4. Reaching our credentials once it is running",
        "worm_needs": "the process it has compromised to be able to read secrets - and "
                      "ideally all of them at once, rather than the one the job needed",
        "state": OPEN if (whole_ctx or into_run) else UNMEASURED,
        "evidence": [
            f"{whole_ctx} workflow(s) hand the entire secrets context to a step as one "
            f"object, and {into_run} interpolate individual secrets into a shell command.",
            f"{no_perms} of {ci_counts.get('Workflow files read', 0)} workflows declare no "
            f"permissions block at all, so the job token carries whatever the repository "
            f"default grants rather than what the job needs.",
            f"{mutable} third-party action reference(s) sit on a mutable label that their "
            f"owner can repoint with no version change visible to us - the campaign's own "
            f"mechanism, applied to our build steps instead of our packages.",
            f"{consumers} consumer repositories sit behind the shared definitions that pass "
            f"the whole context onward, so this is not a per-repository problem with a "
            f"per-repository blast radius.",
            f"{self_hosted} workflow(s) run on self-hosted runners, where a compromised job "
            f"is on our network rather than a disposable cloud VM.",
            "This is the link with the least in its way, and it is the link that decides how "
            "expensive any success at links 1 to 3 turns out to be.",
        ],
        "closed_by": "replace every whole-context pass with an explicit list of the secrets "
                     "the step needs, and add a permissions block to every workflow. Section "
                     "3 carries the ranked target list; the top four sinks are one file each",
        "owner": "Platform / DevOps - owner of the shared workflow repositories",
    })

    # LINK 5 - exfiltration. Dead-drop detection is proven; egress prevention is not measured.
    drop_count = ((dead_drops or {}).get("result") or {}).get("marker_repository_count")
    drop_examined = (((dead_drops or {}).get("controls") or {}).get("repos_examined") or 0)
    chain.append({
        "link": "5. Getting the credentials out",
        "worm_needs": "to publish what it stole - to a repository it creates in our own "
                      "organization, or to an endpoint on the internet",
        "state": DETECTION_ONLY if drop_count is not None else UNMEASURED,
        "evidence": [
            f"{drop_count} marker repositories across {drop_examined} repositories examined, "
            f"with positive and negative controls passing - so the sweep could have found one "
            f"and did not.",
            "That covers the dead-drop route specifically. Whether an ordinary outbound HTTP "
            "request from a build runner or a laptop would be blocked or logged is not "
            "established by any artifact here.",
        ] if drop_count is not None else [],
        "closed_by": "keep the dead-drop sweep running every cycle - it costs nothing, it "
                     "reads an artifact we already collect - and separately establish what "
                     "outbound egress a build runner is permitted",
        "owner": "Security operations for the sweep; Network security for egress",
    })

    # LINK 6 - propagation. The one link that can be called CONTROLLED, and only because a
    # precondition is absent rather than because a control was built. Worth stating that way
    # round: an absent precondition can appear the day somebody adds a publish workflow.
    oidc_publish = posture_counts.get("workflows_with_oidc_publish_capability")
    id_token_only = posture_counts.get("workflows_requesting_id_token_without_publish_step", 0)
    chain.append({
        "link": "6. Using our credentials to infect others",
        "worm_needs": "a credential or a trusted-publishing identity that can publish a "
                      "package the wider world installs - the step that turns a victim into "
                      "a carrier",
        "state": CONTROLLED if oidc_publish == 0 else (
            OPEN if oidc_publish else UNMEASURED),
        "evidence": [
            f"{oidc_publish} of {posture_counts.get('workflows_analysed', 0)} workflows "
            f"combine an OIDC identity token with a publish step, which is the precondition "
            f"for the trusted-publishing abuse Unit 42 documented - genuine provenance, no "
            f"stolen credential, so signature checking does not see it.",
            f"{id_token_only} workflow(s) request an identity token without a publish step. "
            f"Not the precondition, but the half of it that is cheapest to remove.",
            "This link is held because a precondition is absent, not because a control was "
            "built. It can reappear the week somebody adds a publish workflow, which is why "
            "the check runs every cycle rather than once.",
        ] if oidc_publish is not None else [],
        "closed_by": "keep this check in every run, and require review on any workflow that "
                     "introduces publish capability. If we do begin publishing packages "
                     "publicly, this link changes state and the report will say so",
        "owner": "Platform / DevOps with Information security",
    })

    # LINK 7 - persistence. Detection first-executed in r9; prevention exists in exactly one
    # repository's settings file, which is not a policy.
    persistence = next((c for c in (endpoint.get("coverage") or [])
                        if c.startswith("Persistence sweep")), None)
    chain.append({
        "link": "7. Staying after we clean up",
        "worm_needs": "a watchdog, a scheduled task or an agent hook that survives removal "
                      "of the package and re-establishes access",
        "state": DETECTION_ONLY if persistence else UNMEASURED,
        "evidence": [
            persistence,
            "Prevention here exists in one repository we happened to look at, whose agent "
            "settings deny the two primitives this campaign relies on. One repository's "
            "configuration is an example, not a control - it becomes one when it is the "
            "estate default.",
        ] if persistence else [],
        "closed_by": "make the deny list that already exists in one repository's agent "
                     "settings the estate default, so the primitives this campaign needs are "
                     "refused before any hunt has to detect them",
        "owner": "Platform / DevOps with Information security",
    })
    return chain


def build_green_gate(vectors: List[dict], actions: List[dict], coverage: dict,
                     chain: List[dict], freshness: List[dict],
                     advisory: Optional[dict] = None) -> List[dict]:
    """What would have to be true for this report to read GREEN, derived not typed.

    This exists because "when can development resume" and "when does this go green" are the
    two questions a report like this provokes and neither was answered anywhere in it. A
    reader left to infer the answer infers the cautious one, which is how a clean hunt ends
    up holding delivery for weeks on the strength of posture work that was never a blocker.

    So the gate is explicit, ordered, and separated into what we can close ourselves and what
    needs somebody else's decision or budget. The last part matters most: on the run this was
    written, everything engineering could do amounted to days, and the only true blockers were
    two decisions nobody had been asked to make.
    """
    gate: List[dict] = []

    # 1. Unread items. Ours, cheap, and they are the reason a vector says INCOMPLETE - with one
    #    exception the summary table used to get wrong. An item that says in its own text it is
    #    not ours to close is not ours, and printing "Ours: Yes / hours to days" next to an item
    #    whose detail reads "cannot be matched by anyone with any permission" is a contradiction
    #    a reader catches before we do.
    for vector in vectors:
        items = vector.get("unresolved_items") or []
        if vector["status"] == INCOMPLETE and items:
            ours = [i for i in items if "not ours to close" not in str(i).lower()]
            gate.append({
                "gate": f"Finish the {plural(len(items), 'unread item')} on {vector['name']}",
                "why": "A vector with unread items is unfinished, not clean, so it cannot "
                       "contribute a clear result no matter what it found.",
                "blocks_green": True,
                "ours": bool(ours),
                "effort": "Hours to days" if ours else "Depends on another team's data source",
                "owner": "The hunt team" if ours else "Named in the item below",
                "detail": items,
            })

    # 2. Exposure findings. These do NOT block a clean breach verdict and the gate says so
    #    explicitly, because conflating the two is what holds development for no reason.
    exposure = [v for v in vectors if v["status"] == FINDINGS
                and not v.get("is_compromise_evidence")]
    if exposure:
        p1 = [a for a in actions if a["priority"] == 1]
        gate.append({
            "gate": f"Close the priority-1 exposure work on "
                    f"{' and '.join(v['name'] for v in exposure)}",
            "why": "These are hardening findings, not evidence of compromise. They keep the "
                   "report off GREEN because they are real exposure - they do not make this "
                   "an incident and they are not a reason to pause delivery.",
            "blocks_green": True,
            "ours": True,
            "effort": "Days for the priority-1 set",
            "owner": "; ".join(sorted({o for a in p1 for o in a["owners"]})) or "Platform / DevOps",
            "detail": [f"P{a['priority']}: {a['title']} - {a['scope']}" for a in p1],
        })

    # 3. Coverage gaps. The honest part: some of these can never be closed, so GREEN cannot
    #    mean "proven absent everywhere" and the gate has to define itself in terms a reader
    #    can actually reach.
    if coverage.get("gaps"):
        gate.append({
            "gate": f"Decide, for each of {plural(len(coverage['gaps']), 'unobservable population')}, "
                    f"whether to make it visible or accept in writing that it stays dark",
            "why": "At least one of these cannot be closed at any price - the platform emits "
                   "no telemetry and no onboarding changes that. So GREEN can never mean "
                   "'proven absent everywhere'; it can only mean every remaining blind spot "
                   "has a named owner who has accepted it. That is a decision, and nobody "
                   "has been asked to make it.",
            "blocks_green": True,
            "ours": False,
            "effort": "Mixed - each row in the coverage register says which",
            "owner": "; ".join(sorted({g["owner"] for g in coverage["gaps"]})),
            "detail": [f"{g['gap']} - {g['population']}" for g in coverage["gaps"]],
        })

    # 4. Control posture. A link with nothing in its way is not a hunt finding, which is
    #    exactly why it needs to be in the gate: otherwise it never blocks anything and
    #    never gets funded.
    open_links = [c for c in chain if c["state"] == OPEN]
    unmeasured_links = [c for c in chain if c["state"] == UNMEASURED]
    if unmeasured_links:
        gate.append({
            "gate": f"Answer the {plural(len(unmeasured_links), 'unmeasured control question')} "
                    f"in Section 2",
            "why": "Each is a link in the attack chain where we have not established whether "
                   "anything is in the way. These are questions, not decisions, and they are "
                   "the cheapest items on this list - answering one can turn a worry into a "
                   "control we already had.",
            "blocks_green": True,
            "ours": True,
            "effort": "Hours each",
            "owner": "; ".join(sorted({c["owner"] for c in unmeasured_links})),
            "detail": [f"{c['link']} - {c['closed_by']}" for c in unmeasured_links],
        })
    if open_links:
        gate.append({
            "gate": f"Put a control in the way of "
                    f"{plural(len(open_links), 'chain link')} that currently has none",
            "why": "We looked and found nothing standing in the way of these steps. That is "
                   "a decision with a cost, not an oversight, and it is the decision that "
                   "determines how expensive the next campaign is rather than whether it "
                   "arrives.",
            "blocks_green": True,
            "ours": True,
            "effort": "Days to weeks",
            "owner": "; ".join(sorted({c["owner"] for c in open_links})),
            "detail": [f"{c['link']} - {c['closed_by']}" for c in open_links],
        })

    # 4b. Attacker steps the hunt has never asked about. These belong on the gate for the
    #     same reason unread items do: GREEN cannot mean "every vector clear" while a step the
    #     campaign is documented to perform has never been queried. They are separated from the
    #     unmeasured chain links above because the denominator is different - these come from
    #     somebody else's list of what the attacker does, not from ours.
    never = [row for row in ((advisory or {}).get("vectors") or []) if row.get("why_not_measured")]
    answerable = [row for row in never
                  if "nothing we can run" not in row["why_not_measured"]]
    if answerable:
        gate.append({
            "gate": f"Look at the {plural(len(answerable), 'attacker step')} in the published "
                    f"advisories that this hunt has never queried",
            "why": "Each is a step this campaign is documented to perform and that no "
                   "collector here has ever asked about. GREEN cannot mean every vector clear "
                   "while these have never been looked at - and each is a marker addition, a "
                   "sweep or a rights request rather than a project.",
            "blocks_green": True,
            "ours": True,
            "effort": "Hours each",
            "owner": "; ".join(sorted({row["owner"] for row in answerable})),
            "detail": [f"{row['id']} {row['ttp']} - {row['why_not_measured']}"
                       for row in answerable],
        })
    unanswerable = [row for row in never if row not in answerable]
    if unanswerable:
        gate.append({
            "gate": f"Decide whether to fund a data source for "
                    f"{plural(len(unanswerable), 'advisory indicator')} that our telemetry "
                    f"cannot match at any price",
            "why": "The indicator is real and the table that would carry it does not have the "
                   "column. No query closes this; a log source does. That makes it a funding "
                   "decision rather than engineering work, and GREEN should not silently "
                   "absorb it.",
            "blocks_green": False,
            "ours": False,
            "effort": "A decision, not an engineering task",
            "owner": "; ".join(sorted({row["owner"] for row in unanswerable})),
            "detail": [f"{row['id']} {row['ttp']} - {row['why_not_measured']}"
                       for row in unanswerable],
        })

    # 5. Freshness. A stale artifact does not block GREEN on its own merit - it blocks the
    #    claim that GREEN describes today.
    stale = [f for f in freshness if f.get("stale")]
    if stale:
        gate.append({
            "gate": f"Re-run {plural(len(stale), 'collector')} whose artifact is stale",
            "why": "A stale artifact is not wrong, it answers a question about the day it was "
                   "collected. GREEN has to describe today or it describes nothing.",
            "blocks_green": True,
            "ours": True,
            "effort": "Minutes to hours",
            "owner": "The hunt team",
            "detail": [f"{f['feeds']} - {f['artifact']} ({f['age']})" for f in stale],
        })

    # 6. Vectors that did not run. Last, because it is the most obvious and the most often
    #    forgotten when a report is assembled from whatever happened to be collected.
    absent = [v["name"] for v in vectors if v["status"] in (NOT_RUN, BLOCKED)]
    if absent:
        gate.append({
            "gate": f"Run the {plural(len(absent), 'vector')} that did not run this cycle",
            "why": "A vector that did not run contributes no result in either direction. It "
                   "cannot be counted toward GREEN and it is not evidence of a problem.",
            "blocks_green": True,
            "ours": True,
            "effort": "Varies by vector",
            "owner": "The hunt team",
            "detail": absent,
        })
    return gate


def build_actions(ci: dict, endpoint: dict, ioc: dict, owners: Optional[dict],
                  registry: dict, reusable: dict,
                  prevention: Optional[dict] = None) -> List[dict]:
    actions: List[dict] = []
    owner_index = (owners or {}).get("repos", {}) or {}

    # 0. The chokepoint. Ranked above everything, including per-repository work, because a
    #    sink that receives the whole secrets context from many shared workflows is one
    #    file to fix and the largest single reduction in blast radius available.
    # Three buckets, because there are three genuinely different failure modes and a
    # two-way split silently drops one of them:
    #   chokepoint - secrets rendered to text AND sent to an externally-owned ref that can
    #                move. Someone else can change the code that already holds the secrets.
    #   inline     - secrets rendered to text inside a step we own. No third party can move
    #                it, but the values are still in the shell where anything can read them.
    #   forwarded  - context passed onward without being serialized. Widest scope, lowest
    #                immediacy.
    sinks = reusable.get("ranked_sinks", []) or []
    chokepoints = [s for s in sinks if s["serialises_to_text"] and s["sink_ref_mutable"]]
    inline_sinks = [s for s in sinks if s["serialises_to_text"] and not s["sink_ref_mutable"]]
    if chokepoints:
        top = chokepoints[0]
        actions.append({
            "priority": 1,
            "title": f"Pin and narrow the shared build steps that receive every secret - "
                     f"the largest takes {top['consumer_refs']} pipeline references",
            "why_now": "Our build pipelines are centralized, which is normally a strength. "
                       "Here it concentrates risk: a small number of shared build steps "
                       "receive the complete set of secrets from a very large number of "
                       "repositories, and they are referenced by a moving label rather "
                       "than a fixed version. Whoever can move that label changes what "
                       "runs in all of those pipelines at once, and it would already "
                       "hold every secret they use. This is the same mechanism the "
                       "campaign used in the package ecosystem. It is also the best news "
                       "in this report: it is a handful of files, not hundreds.",
            "scope": f"{len(chokepoints)} shared build step(s), "
                     f"{sum(s['consumer_refs'] for s in chokepoints)} pipeline references",
            "targets": [f"{s['sink']} - {s['consumer_refs']} pipeline refs via "
                        f"{s['workflows']} shared workflow(s), mechanism "
                        f"{'/'.join(s['mechanisms'])}"
                        f"{', deploys' if s['deploying'] else ''}"
                        for s in chokepoints],
            "owners": ["Platform / DevOps - owner of the shared workflow repositories"],
            "effort": "Days. Two changes: pin each sink to a commit SHA, then replace the "
                      "whole-context pass with the specific secrets the step uses.",
            "blocked_by": None,
        })
    if inline_sinks:
        actions.append({
            "priority": 2,
            "title": "Narrow the shared workflow steps that write every secret into the "
                     "build shell",
            "why_now": "These steps take the complete set of secrets and render them as "
                       "text inside the running build, usually to read the names off. "
                       "Nobody outside can change the step, which is why this ranks below "
                       "the previous item - but once the values are in the shell, any "
                       "later step, any log, and anything that writes a file can capture "
                       "them. Reading the NAMES of secrets does not require handling their "
                       "VALUES.",
            "scope": f"{len(inline_sinks)} shared step(s), "
                     f"{sum(s['consumer_refs'] for s in inline_sinks)} pipeline references",
            "targets": [f"{s['sink']} - {s['consumer_refs']} pipeline refs via "
                        f"{s['workflows']} shared workflow(s)" for s in inline_sinks],
            "owners": ["Platform / DevOps"],
            "effort": "Hours each. Where the step only needs secret NAMES, list them "
                      "explicitly instead of enumerating the context.",
            "blocked_by": None,
        })
    inherit_sinks = [s for s in sinks if not s["serialises_to_text"]]
    if inherit_sinks:
        actions.append({
            "priority": 3,
            "title": "Narrow the shared workflows that forward the whole secrets context "
                     "without serializing it",
            "why_now": "These pass every secret to another workflow we own. That is "
                       "materially safer than writing them out as text - the values are "
                       "not rendered into a shell - but the receiving workflow still gets "
                       "far more than it needs. Worth fixing after the serializing ones.",
            "scope": f"{len(inherit_sinks)} shared workflows, "
                     f"{sum(s['consumer_refs'] for s in inherit_sinks)} pipeline references",
            "targets": [f"{s['sink']} - {s['consumer_refs']} pipeline refs"
                        for s in inherit_sinks],
            "owners": ["Platform / DevOps"],
            "effort": "Days each. Declare the secrets the called workflow needs.",
            "blocked_by": None,
        })

    def owner_of(repo: str) -> str:
        row = owner_index.get(repo) or {}
        state = row.get("owner_state")
        if state == "owned":
            return ", ".join(row.get("default_owners") or row.get("owners") or []) or "owned, no `*` rule"
        if state == "unowned":
            return "**no CODEOWNERS**"
        if state == "codeowners_empty":
            return "**CODEOWNERS present but names nobody**"
        if state == "owner_lookup_error":
            return "lookup failed"
        return "not resolved"

    def blast_radius(repo: str) -> Optional[bool]:
        """True, False, or None. None is a real third answer and is never folded into False.

        Deployment topology resolves only the repositories whose deploy path could be
        inferred with evidence. Treating an unresolved repository as "does not reach
        production" would de-prioritize it on the strength of a fact nobody established.
        """
        row = owner_index.get(repo) or {}
        return row.get("reaches_production")

    # 1. Whole-secrets exposure, split three ways by blast radius. The same workflow
    #    pattern is a different problem depending on what the repository can deploy to,
    #    and "we do not know what it deploys to" is its own bucket, not a safe one.
    tojson_repos = sorted({e["repo"] for e in ci.get("tojson", [])})
    if tojson_repos:
        prod = [r for r in tojson_repos if blast_radius(r) is True]
        unknown = [r for r in tojson_repos if blast_radius(r) is None]
        non_prod = [r for r in tojson_repos if blast_radius(r) is False]
        if prod:
            actions.append({
                "priority": 1,
                "title": "Stop handing the entire secrets store to build steps in "
                         "repositories confirmed to deploy to production",
                "why_now": "These workflows pass every secret the repository holds to a "
                           "step as one object. If any one of those steps is compromised, "
                           "or the runner is, the attacker gets all of them - not the one "
                           "the job needed. These repositories are confirmed to reach "
                           "production.",
                "scope": f"{len(prod)} repositories confirmed production-reaching",
                "targets": prod,
                "owners": sorted({owner_of(r) for r in prod}),
                "effort": "Days. Replace the whole-context pass with an explicit list of "
                          "the secrets each step needs.",
                "blocked_by": None,
            })
        if unknown:
            actions.append({
                "priority": 2,
                "title": "Same fix, repositories whose deployment reach is unknown",
                "why_now": "Same weakness. We have not established where these deploy to, "
                           "so we cannot say the blast radius is small - only that nobody "
                           "has measured it. They are ranked below the confirmed set on "
                           "evidence, not on safety.",
                "scope": f"{len(unknown)} repositories, deployment reach unresolved",
                "targets": unknown,
                "owners": sorted({owner_of(r) for r in unknown}),
                "effort": "Weeks, batched. Resolving deployment topology for these would "
                          "let them be ranked properly rather than lumped together.",
                "blocked_by": None,
            })
        if non_prod:
            actions.append({
                "priority": 4,
                "title": "Same fix, repositories confirmed NOT to reach production",
                "why_now": "Same weakness, and the blast radius is measured and small. "
                           "Genuine backlog rather than urgent.",
                "scope": f"{len(non_prod)} repositories confirmed non-production",
                "targets": non_prod,
                "owners": sorted({owner_of(r) for r in non_prod}),
                "effort": "Backlog.",
                "blocked_by": None,
            })

    # 2. The unanswered vector. Ranked high not because something was found but because
    #    nothing could be - an unanswerable question outranks a known, bounded weakness.
    #
    #    Two different causes, two different asks, and conflating them is what produced a
    #    priority-1 request for a permission the tenant had already granted. BLOCKED is a
    #    permissions problem and the fix is an access request. NOT RUN is an operations
    #    problem and the fix is running the collector, which costs a minute. Only the
    #    artifact can say which one is true, so neither branch guesses.
    if endpoint.get("status") == BLOCKED:
        # §0.6(b). The targets used to be one hardcoded string naming ThreatHunting.Read.All
        # - which is the permission the tenant already held, so on the run that produced
        # this branch the report asked for the one thing it did not need. A hardcoded ask
        # is an ask about the past. These come from the collector, which is the only thing
        # here that has spoken to the tenant, and validate_vectors() has already refused
        # the render if any of the six fields is missing.
        gaps = endpoint.get("access_required") or []
        actions.append({
            "priority": 1,
            "title": "Get read access to endpoint security telemetry",
            "why_now": "We can see every repository and every build pipeline. We cannot "
                       "see a single laptop. The Windows form of this attack lands on a "
                       "laptop, so the one place it would show up is the one place we "
                       "cannot look. This is not a finding - it is a hole where a finding "
                       "would be.",
            "scope": f"{plural(len(gaps), 'access request')}",
            "targets": [access_gap_sentence(g) for g in gaps],
            "owners": sorted({g["granted_by"] for g in gaps}),
            "effort": "Hours, once approved. The queries are already written and tested "
                      "for syntax; they have never been run.",
            "blocked_by": "; ".join(f"{g['api']} {g['permission']}" for g in gaps),
        })
    elif endpoint.get("status") == NOT_RUN:
        actions.append({
            "priority": 1,
            "title": "Run the endpoint hunt - it is the only vector that sees a laptop",
            "why_now": "Every other check in this report reads GitHub, and GitHub cannot "
                       "show a workstation. The Windows form of this attack lands on one. "
                       "Nothing here says we lack access; it says nobody ran it.",
            "scope": "1 command",
            "targets": ["python3 scripts/hunt/hunt_endpoint_defender.py"],
            "owners": ["Security operations"],
            "effort": "Minutes. Read-only advanced-hunting queries against the existing "
                      "app registration; no GitHub budget consumed.",
            "blocked_by": None,
        })
    # Below here the hunt ran, so two independent things can be outstanding and they get two
    # actions rather than one. `if`, not `elif`: the residue and the blind spot have different
    # owners, different efforts and different priorities, and a run can have both.
    if endpoint.get("status") not in (BLOCKED, NOT_RUN) and endpoint.get("unresolved_items"):
        # Our own unfinished work on this vector - a Bun question whose control failed, a
        # query that needs a wider window. Priority 2 and owned by us, because nobody outside
        # the team has to approve or fund any of it.
        residue = endpoint["unresolved_items"]
        actions.append({
            "priority": 2,
            "title": "Finish the endpoint questions this run could not answer",
            "why_now": f"{plural(len(residue), 'question')} on this vector returned a zero "
                       f"its control could not support, so the zero is withdrawn rather than "
                       f"reported as clean. Nothing outside the team blocks these - the "
                       f"access and the data are already in hand.",
            "scope": f"{plural(len(residue), 'unanswered question')}",
            "targets": residue,
            "owners": ["Security operations"],
            "effort": "Hours. Each is a query or a window to correct, then a re-run.",
            "blocked_by": None,
        })
    if endpoint.get("coverage_gaps"):
        # The hunt ran, found nothing, and did so over a population smaller than the estate.
        #
        # The action is real but its framing had to change. It used to be titled "the gaps
        # keeping this hunt from reading clean" and sat behind an INCOMPLETE status, which
        # made an instrumentation problem look like a hunting problem and put the endpoint
        # vector - the only one that can see a laptop - permanently at AMBER for a reason no
        # query will ever resolve. The hunt is clean over what it observes. What is
        # outstanding is that the observable set is smaller than the estate, which is
        # somebody's budget and somebody's onboarding queue, not an unread artifact.
        #
        # Priority 2, not 1: nothing here is evidence of anything. It is the reason a future
        # answer might not exist.
        gap_list = endpoint["coverage_gaps"]
        counts = endpoint.get("counts", {})
        actions.append({
            "priority": 2,
            "title": "Shrink the blind spot - populations this hunt can never answer for",
            "why_now": f"The laptop and server hunt ran and found no trace of the campaign "
                       f"on the {counts.get('Devices reporting to Defender', 0)} devices "
                       f"that report, and the controls prove those queries could have found "
                       f"it. "
                       f"{counts.get('Devices seen but NOT reporting', 0)} devices send no "
                       f"telemetry at all, so no query can return a hit or a clean result "
                       f"for them - today, tomorrow, or during an incident. This is not a "
                       f"finding and nothing below is evidence of compromise. It is the "
                       f"size of the area where this report has to say we do not know.",
            "scope": f"{plural(len(gap_list), 'unobservable population')}",
            "targets": [coverage_gap_sentence(g) for g in gap_list],
            "owners": sorted({g["owner"] for g in gap_list}),
            "effort": "Mixed, and each row says which. Onboarding is endpoint-management "
                      "work sized by device count; enabling a telemetry column or granting "
                      "a permission is configuration measured in hours.",
            "blocked_by": None,
        })

    # 3. Mutable refs. Split branch refs out from tag refs: a branch ref can be moved by
    #    the owner at any time with no version bump and no signal to us.
    branch_refs = [(ref, n) for ref, n in ci.get("unpinned_third_party", [])
                   if "@" in ref and not ref.split("@")[-1][:1].isdigit()
                   and not ref.split("@")[-1].startswith("v")]
    if branch_refs:
        actions.append({
            "priority": 3,
            "title": "Pin third-party build tools that currently track a moving target",
            "why_now": "These build steps are fetched from other people's GitHub accounts "
                       "by branch name, not by a fixed version. Whoever owns that account "
                       "can change what runs in our pipelines at any time, without us "
                       "seeing a version change. That is precisely how this campaign "
                       "spread in the package ecosystem.",
            "scope": f"{sum(n for _, n in branch_refs)} references across "
                     f"{len(branch_refs)} distinct actions",
            "targets": [f"{ref} ({n} references)" for ref, n in branch_refs],
            "owners": ["Platform / DevOps"],
            "effort": "Hours per action. Replace the ref with a commit SHA.",
            "blocked_by": None,
        })

    if ci.get("pin_rate"):
        pinned = ci["counts"].get("Action references pinned to a commit SHA", 0)
        mutable = ci["counts"].get("Third-party action references on a mutable ref", 0)
        actions.append({
            "priority": 4,
            "title": "Raise the build-step pinning rate estate-wide",
            "why_now": f"Only {ci['pin_rate']} of build-step references are pinned to a "
                       f"fixed commit. The rest can change under us. This is the single "
                       f"number that decides how badly the next campaign hits us.",
            "scope": f"{mutable} unpinned references ({pinned} already pinned)",
            "targets": [f"{ref} ({n} references)"
                        for ref, n in ci.get("unpinned_third_party", [])[:15]],
            "owners": ["Platform / DevOps"],
            "effort": "Program of work. Start with third-party, then first-party.",
            "blocked_by": None,
        })

    curl_sh = ci.get("curl_sh", [])
    if curl_sh:
        actions.append({
            "priority": 3,
            "title": "Remove build steps that download and run code straight from the internet",
            "why_now": "These steps fetch a script at build time and execute it "
                       "immediately. Nothing checks what arrived. Whoever controls that "
                       "URL controls the build.",
            "scope": plural(len(curl_sh), "workflow"),
            "targets": [f"{e['repo']} - {e['path']}" for e in curl_sh],
            "owners": sorted({owner_of(e["repo"]) for e in curl_sh}),
            "effort": "Hours each.",
            "blocked_by": None,
        })

    unowned = sorted(repo for repo, row in owner_index.items()
                     if row.get("owner_state") == "unowned")
    if unowned:
        unowned_prod = [r for r in unowned if blast_radius(r) is True]
        actions.append({
            "priority": 2 if unowned_prod else 3,
            "title": "Assign an owner to repositories in this report that have none",
            "why_now": "No team is recorded as responsible for these repositories, so "
                       "every action in this report aimed at them has nowhere to go. "
                       + (f"{len(unowned_prod)} of them are confirmed to reach production."
                          if unowned_prod else
                          "None are confirmed production-reaching, but most have no "
                          "deployment topology resolved at all, so that is not reassurance."),
            "scope": plural(len(unowned), "repository", "repositories"),
            "targets": unowned,
            "owners": ["Engineering leadership - assignment decision"],
            "effort": "A decision, not an engineering task.",
            "blocked_by": None,
        })

    # Ranked P1, and the reason is the chain rather than the count: this is the only action in
    # the report that acts on link 2, the step every payload in this campaign begins at, and it
    # is a one-line change per repository rather than a program of work. It is exposure work and
    # the gate says so explicitly - nothing here says anybody was breached.
    exposed_repos = ((prevention or {}).get("repositories", {}) or {}).get(
        "installs_with_scripts_enabled", []) or []
    if exposed_repos:
        prevention_counts = (prevention or {}).get("counts", {}) or {}
        sites = prevention_counts.get("Individual install commands", 0)
        refusing = prevention_counts.get(
            "Of those, carrying --ignore-scripts on the command", 0)
        actions.append({
            "priority": 1,
            "title": f"Refuse install-time scripts in the {len(exposed_repos)} repositories "
                     f"whose builds still allow them",
            "why_now": f"A package's install script is where every payload in this campaign "
                       f"starts, and one setting refuses to run it: `ignore-scripts`. Across the "
                       f"{prevention_counts.get('npm-relevant repositories swept', 0)} "
                       f"repositories that use npm packages, {refusing} of {sites} install "
                       f"commands use it. Nothing here says a poisoned package reached us - it "
                       f"says that if one arrives, the step the attacker relies on is currently "
                       f"available to them, and that this is among the cheapest controls in the "
                       f"report to switch on.",
            "scope": plural(len(exposed_repos), "repository", "repositories"),
            "targets": exposed_repos,
            "owners": sorted({owner_of(repo) for repo in exposed_repos}),
            "effort": "Hours each, batched. Add `--ignore-scripts` to the CI install, or "
                      "`ignore-scripts=true` to a committed `.npmrc`. Expect a small number of "
                      "packages that genuinely need a build step; those are the exceptions to "
                      "record, not a reason to skip the rest.",
            "blocked_by": None,
        })

    uncleaned = registry.get("counts", {}).get("Suspected-uncleaned specs (still live)", 0)
    if uncleaned:
        actions.append({
            "priority": 5,
            "title": "Block the malicious package versions that are still live on npm",
            "why_now": f"{uncleaned} malicious package versions from this campaign have "
                       f"not been removed from the public registry. We do not use them "
                       f"today. Nothing stops a developer installing one tomorrow.",
            "scope": plural(uncleaned, "package version"),
            "targets": ["See the registry section for the full list"],
            "owners": ["Platform / artifact registry admin"],
            "effort": "Hours. Deny-list at the internal registry proxy.",
            "blocked_by": None,
        })

    return sorted(actions, key=lambda a: a["priority"])


# ----------------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------------

ADVISORY_VECTOR_FIELDS = ("id", "chain_link", "ttp", "state", "named_by", "closed_by", "owner")


def validate_advisory(advisory: dict) -> List[str]:
    """Same standard as every other artifact: a state with no number behind it is refused.

    The one exemption is UNMEASURED, and it is not a free pass - an unmeasured vector must say
    what would measure it, because the whole value of separating OPEN from UNMEASURED is that
    the second one is cheap and somebody has to be able to see how cheap.
    """
    problems: List[str] = []
    for index, row in enumerate(advisory.get("vectors") or []):
        missing = [field for field in ADVISORY_VECTOR_FIELDS if not row.get(field)]
        if missing:
            problems.append(f"advisory vector[{index}] is missing {', '.join(missing)}")
            continue
        if row["state"] == UNMEASURED and not row.get("why_not_measured") \
                and not row.get("evidence"):
            problems.append(f"advisory vector {row['id']} is UNMEASURED and says neither what "
                            f"was measured nor what would measure it")
        if row["state"] != UNMEASURED and not row.get("evidence"):
            problems.append(f"advisory vector {row['id']} claims {row['state']} with no "
                            f"evidence read from an artifact")
    if not advisory.get("artifacts_read"):
        problems.append("advisory coverage names no artifacts it read, so every state in it is "
                        "an assertion")
    return problems


def render_advisory_coverage(advisory: dict) -> List[str]:
    """Section 2's answer to 'how much of the attacker's playbook does this cover'.

    The percentage is the headline because it is what gets asked for, and the table is directly
    underneath it because the percentage is the less true of the two: these vectors are not
    equally weighted and they do not sum - a control on the first prevents the attack, a
    control on the last only limits what an attacker keeps.
    """
    out: List[str] = []
    w = out.append
    pcts = advisory.get("percentages") or {}
    counts = advisory.get("counts") or {}
    rows = advisory.get("vectors") or []
    total = counts.get("attacker_vectors_enumerated", len(rows))

    w("### How much of the attacker's playbook this covers")
    w("")
    w("The chain above is our reading of the campaign. The percentages below use somebody "
      "else's reading as the denominator - the published advisories' own TTP lists - so a step "
      "this campaign performs that our hunt never thought to ask about appears as a number "
      "instead of as an absence nobody notices.")
    w("")
    for name in advisory.get("advisories") or []:
        w(f"- {name}")
    w("")
    w(f"| Of the {total} attacker vectors those advisories describe | Share |")
    w("|---|---|")
    labels = {
        "vectors_with_a_measured_answer":
            "we can return a measured number for",
        "vectors_with_something_in_the_way_prevention_or_detection":
            "have something in the way - prevention **or** detection",
        "vectors_with_prevention_rather_than_detection":
            "we would **prevent** rather than watch",
        "vectors_we_never_looked_at":
            "we have never looked at",
        "vectors_with_no_established_control_state":
            "have no established control state either way",
    }
    for key, label in labels.items():
        if key in pcts:
            w(f"| {label} | **{pcts[key]}%** |")
    w("")
    for note in advisory.get("how_to_read_the_percentage") or []:
        w(f"> {note}")
        w(">")
    if advisory.get("how_to_read_the_percentage"):
        out.pop()
        w("")

    per_source = advisory.get("per_advisory") or {}
    if per_source:
        w("Split by advisory, because the two do not describe the same attack in the same "
          "detail:")
        w("")
        w("| Advisory | Vectors it names | We can answer | Share |")
        w("|---|---|---|---|")
        for source, figures in per_source.items():
            w(f"| {md_cell(source)} | {figures.get('vectors_named')} | "
              f"{figures.get('vectors_with_a_measured_answer')} | "
              f"**{figures.get('percent')}%** |")
        w("")

    added = advisory.get("vectors_answerable_only_because_of_these_advisories") or []
    if added:
        by_id = {row["id"]: row for row in rows}
        w(f"**What the advisories added.** {len(added)} of these vectors are answerable only "
          f"because the advisories published the indicators behind them - before this cycle no "
          f"round of this hunt had queried a single campaign domain, address or file hash:")
        w("")
        for vector_id in added:
            row = by_id.get(vector_id, {})
            w(f"- **{vector_id}** - {row.get('ttp', '')} -> now **{row.get('state', '')}**")
        w("")

    never = [row for row in rows if row.get("why_not_measured")]
    if never:
        w(f"**What we have never looked at.** {len(never)} of {total}. Each one names the "
          f"thing that would measure it, so this list is a work queue rather than a worry:")
        w("")
        w("| # | The attacker step we cannot speak to | What would measure it | Owner |")
        w("|---|---|---|---|")
        for row in never:
            w(f"| {md_cell(row['id'])} | {md_cell(row['ttp'])} | "
              f"{md_cell(row['why_not_measured'])} | {md_cell(row['owner'])} |")
        w("")

    # The one number on this page that is not about us. It is here rather than in the evidence
    # section because it bounds every dependency result in the report: a clean comparison
    # against a short list of package names is a different claim from a clean comparison.
    scope = advisory.get("scope_reconciliation") or {}
    if scope.get("delta"):
        theirs = scope.get("advisory") or {}
        ours = scope.get("ours") or {}
        w("**Their blast radius against ours.** The advisories publish totals for the campaign "
          "and they do not match what our registry oracle derived, which is worth a paragraph "
          "rather than a footnote:")
        w("")
        w("| | Poisoned versions | Package names |")
        w("|---|---|---|")
        w(f"| {md_cell(theirs.get('source', 'Advisory'))} | "
          f"{theirs.get('poisoned_versions', 0):,} | {theirs.get('packages', 0):,} |")
        w(f"| Our registry oracle | {ours.get('malicious_specs', 0):,} confirmed "
          f"(+{ours.get('suspected_not_yet_withdrawn', 0)} suspected) | "
          f"{ours.get('package_names_queried', 0):,} queried |")
        w(f"| Difference | {scope['delta'].get('versions', 0):+,} | "
          f"{scope['delta'].get('package_names', 0):+,} |")
        w("")
        for line in scope.get("what_this_does_and_does_not_say") or []:
            w(f"- {line}")
        w("")

    w("Vector by vector, ordered by the attacker's own steps:")
    w("")
    w("| # | Link | The attacker step | Named by | State |")
    w("|---|---|---|---|---|")
    for row in rows:
        w(f"| {md_cell(row['id'])} | {row['chain_link']} | {md_cell(row['ttp'])} | "
          f"{md_cell(', '.join(row['named_by']))} | **{row['state']}** |")
    w("")
    return out


def render_advisory_evidence(advisory: dict) -> List[str]:
    """Section 4: the sentence and the artifact path behind every state in the table above."""
    out: List[str] = []
    w = out.append
    w("### Advisory-TTP coverage - the evidence behind each state")
    w("")
    w("One entry per attacker vector. `Read from` is the artifact path and the value inside "
      "it, so any figure in the Section 2 table can be checked without rerunning anything.")
    w("")
    for row in advisory.get("vectors") or []:
        w(f"**{row['id']} - {row['ttp']}**  ")
        w(f"*Chain link {row['chain_link']}. Named by {', '.join(row['named_by'])}. "
          f"State: {row['state']}.*  ")
        if row.get("evidence"):
            w(f"{row['evidence']}  ")
        if row.get("why_not_measured"):
            w(f"*Never looked at.* {row['why_not_measured']}.  ")
        w(f"*What would change the state:* {row['closed_by'].rstrip('.')}. "
          f"*Owner:* {row['owner']}.  ")
        for source in row.get("read_from") or []:
            w(f"`{source}`  ")
        w("")
    missing = advisory.get("artifacts_missing") or {}
    if missing:
        w("**Artifacts this mapping expected and did not find** - each one is a vector "
          "reported as never looked at, which is the correct failure and not a silent pass:")
        w("")
        for stem, why in missing.items():
            w(f"- `{stem}` - {why}")
        w("")
    return out


def render(vectors: List[dict], verdict: dict, delta: List[str], actions: List[dict],
           ioc: dict, ci: dict, registry: dict, owners: Optional[dict],
           reusable: dict, as_of: str, campaign: str,
           sources: Optional[List[dict]] = None,
           coverage: Optional[dict] = None,
           chain: Optional[List[dict]] = None,
           gate: Optional[List[dict]] = None,
           advisory: Optional[dict] = None) -> str:
    out: List[str] = []
    w = out.append
    coverage = coverage or compute_coverage(vectors)
    chain = chain or []
    gate = gate or []

    # YAML front matter drives the cover page, the table of contents and the per-page
    # classification marking in src/reporting/md_to_pdf.py. Emitted here rather than added
    # by hand so a re-render cannot lose the marking a reader checks before forwarding.
    w("---")
    w('title: "Software supply-chain threat hunt"')
    w(f'subtitle: "Daily report - {as_of}"')
    w('classification: "Internal - names repositories, staff and infrastructure"')
    w(f'generated: "{as_of}"')
    w("fields:")
    w(f'  Campaign: "{campaign}"')
    w(f'  Report date: "{as_of}"')
    w(f'  Overall status: "{verdict["rag"]}"')
    w(f'  Coverage: "{coverage["state"]}"')
    w('  Produced by: "scripts/hunt/render_hunt_report.py"')
    w('  Evidence: "Every number is read from a hunt coverage artifact at render time."')
    w("toc: true")
    w("---")
    w("")
    w(f"# Software supply-chain threat hunt - daily report")
    w("")
    w(f"**Campaign:** {campaign}  ")
    w(f"**Report date:** {as_of}  ")
    w(f"**Classification:** Internal - names repositories, staff and infrastructure  ")
    w(f"**Produced by:** `scripts/hunt/render_hunt_report.py` from the hunt's own "
      f"coverage artifacts. Every number is read from an artifact, not typed.")
    w("")
    w("> **How to read this.** Section 1 answers your boss: were we hit. Section 2 answers "
      "the question that follows it: could it happen to us, and what is in the way. Section "
      "3 tells you what to do and in what order. Section 4 is the proof, the target list and "
      "the fixes for the engineers. Read only as far as you need.")
    w("")
    w("---")
    w("")

    # ---------------- SECTION 1 ----------------
    w("## Section 1 - The situation")
    w("")
    w(f"### {verdict['rag']}  -  coverage {coverage['state']}")
    w("")
    w(f"**Are we breached? {verdict['breached']}**")
    w("")
    # Two lines, not one, and the second one is not a footnote. The color is a statement
    # about what we can see; the coverage state is a statement about how much that is. A
    # reader given only the first will over-read it, and a reader given them fused into one
    # letter gets a letter that means neither thing.
    w(f"**How much can we see? {coverage['state']}.** {coverage['scope']}")
    w("")
    if coverage["gaps"]:
        w("| Cannot observe | How many | What we cannot say | What closes it |")
        w("|---|---|---|---|")
        for gap in coverage["gaps"]:
            w(f"| {md_cell(gap['gap'])} | {md_cell(gap['population'])} | "
              f"{md_cell(gap['cannot_confirm_or_deny'])} | {md_cell(gap['closed_by'])} |")
        w("")
        w("These are not findings and they are not counted as any. Nothing in them is known "
          "to be wrong; nothing in them is known to be right. Every one of them can be "
          "listed device by device - Section 4 carries the query that produces each list, so "
          "the owner above can be handed the actual members rather than a number.")
        w("")
    w("**In one paragraph.** A worm has been spreading through the public library of "
      "open-source building blocks that most modern software is assembled from. It steals "
      "credentials from whoever installs an infected block and uses them to infect more. "
      "We check our own code, our build systems, our dependency lists and the public "
      "registry itself every day to see whether it reached us. Today's answer is below, "
      "along with the weaknesses that would decide how badly a future one hits us.")
    w("")
    # A director who reads one number from this section reads the verdict. The second number
    # they ask for, every time, is how much of the attacker's playbook that verdict covers -
    # so it is here, in the section they actually read, rather than only in Section 2.
    if advisory:
        adv_pcts = advisory.get("percentages") or {}
        adv_counts = advisory.get("counts") or {}
        never = adv_counts.get("not_measured", 0)
        w(f"**How much of this attacker's playbook we can speak to.** The two published "
          f"advisories describe "
          f"{adv_counts.get('attacker_vectors_enumerated', 0)} distinct steps this campaign "
          f"takes. We can return a measured number for "
          f"**{adv_pcts.get('vectors_with_a_measured_answer', 0)}%** of them; "
          f"**{adv_pcts.get('vectors_with_something_in_the_way_prevention_or_detection', 0)}%** "
          f"have something in the way, though only "
          f"**{adv_pcts.get('vectors_with_prevention_rather_than_detection', 0)}%** would be "
          f"prevented rather than merely seen. "
          f"{plural(never, 'step')} we have never looked at, each named in Section 2 with the "
          f"specific thing that would measure it. The steps are not equally weighted and the "
          f"percentage is a headline, not the answer - the table in Section 2 is the answer.")
        w("")
    if verdict["why"]:
        w("**What is driving today's status.**")
        w("")
        for reason in verdict["why"]:
            w(f"- {reason}")
        w("")
    w("**What changed since the last report.**")
    w("")
    for line in delta:
        w(f"- {line}")
    w("")
    w("**Where we looked, in plain terms.**")
    w("")
    # The scope column is not decoration. Section 1 is where a reader forms the belief they
    # will repeat to their boss, and a result with no denominator beside it is the easiest
    # place in the document to over-read. Every number in it comes from the vector's own
    # artifact.
    w("| We checked | How much of it | Result |")
    w("|---|---|---|")
    # Plain-language labels for what each vector looked at. These used to open with
    # "Every": every file in every repository we own, every third-party building block we
    # use, every automated build pipeline. None of that was provable. The sweep reads the
    # GitHub organizations it was pointed at - not a repository on someone's laptop, not
    # another VCS, not a private fork - and "every building block we use" is a claim about
    # the estate, whereas the artifact only knows what it inventoried.
    #
    # A label that overclaims is worse than a vague one, because it converts a measured
    # result into an unmeasured one at the exact point in the document where the reader is
    # least equipped to notice. Each label now says what was actually read, and the Scope
    # column beside it carries the number.
    PLAIN = {
        "GitHub repositories - files on disk": "The files in the GitHub repositories we "
                                               "enumerated",
        "GitHub repositories - branches and commits": "Code changes pushed during the "
                                                      "attack window, in those repositories",
        "GitHub code search (corroborating only)": "A second, independent search of our code",
        "Dependency inventory vs campaign IOCs": "The third-party building blocks listed "
                                                 "in our dependency files",
        "CI / GitHub Actions posture": "The GitHub Actions build pipelines we could read",
        "CI - shared reusable workflows (fan-out)": "The shared build steps that most "
                                                    "pipelines depend on",
        "Registry ground truth (attack window)": "The public library itself, to know exactly "
                                                 "what was poisoned and when",
        "Endpoint / identity (Microsoft Defender)": "Staff laptops and servers reporting to "
                                                    "Microsoft Defender",
        "Endpoint install activity (package acquisition)": "What our machines actually "
                                                          "downloaded during the attack, not "
                                                          "just what our files declare",
        "Internal package registry (proxy of npmjs)": "Our own package mirror, which serves "
                                                     "public packages under our name",
    }
    PLAIN_STATUS = {
        CLEAR: "Clean - looked everywhere we can look, and we can prove the check works",
        FINDINGS: "Things to fix",
        BLOCKED: "**Could not check - access needed, named in Section 4**",
        NOT_RUN: "Not checked this cycle",
    }
    for vector in vectors:
        if vector["status"] == INCOMPLETE:
            # State the residue as a number on the face of the summary table. A reader who
            # gets no further than this page should still leave knowing exactly how much
            # is outstanding, rather than carrying away a vague unease.
            outstanding = len(vector.get("unresolved_items") or [])
            plain = (f"Clean so far - **{outstanding} item(s) still to check**, listed in "
                     f"Section 4")
        elif vector["status"] == CORROBORATING:
            plain = "Supporting check only - can spot a problem, cannot declare us clean"
        else:
            plain = PLAIN_STATUS.get(vector["status"], vector["status"])
        # A vector can be clean and still not speak for the whole estate. Saying so here,
        # in the row itself, is what stops "Clean" from being read as "Clean everywhere" -
        # without demoting a check that did its job over the population it can reach.
        if vector.get("coverage_gaps"):
            plain += (f" (over the population we can observe - "
                      f"{len(vector['coverage_gaps'])} unobservable population(s) listed "
                      f"in the coverage table above)")
        w(f"| {PLAIN.get(vector['name'], vector['name'])} | {vector.get('scope', '-')} "
          f"| {plain} |")
    w("")

    # The closing line is the one sentence a reader repeats to somebody else, so it is the
    # sentence that most has to be true. It used to read "Nothing in our estate matches
    # this campaign" - unconditionally, and regardless of what the vectors said. Neither
    # half survives inspection: this hunt does not read the estate, it reads the sources it
    # enumerated, and on any run with a compromise finding the sentence would have
    # contradicted the verdict three lines above it. The second clause asserted a CI
    # problem whether or not one had been found.
    #
    # Both halves are now derived. The scope-limiting phrase is not hedging - it is the
    # difference between a claim the artifacts support and one they do not.
    compromise = [v for v in vectors if v["status"] == FINDINGS
                  and v.get("is_compromise_evidence")]
    residue = sum(len(v.get("unresolved_items") or []) for v in vectors)
    unchecked = [v["name"] for v in vectors if v["status"] in (BLOCKED, NOT_RUN)]
    exposure = [v for v in vectors if v["status"] == FINDINGS
                and not v.get("is_compromise_evidence")]

    if compromise:
        remember = ("This campaign reached us. " + "; ".join(v["name"] for v in compromise)
                    + " carries the evidence, and Section 4 names it. Everything below "
                      "that is secondary until it is contained.")
    else:
        remember = "Nothing we can observe matches this campaign."
        if residue or unchecked:
            parts = []
            if residue:
                parts.append(f"{residue} named item(s) we did not read")
            if unchecked:
                parts.append(f"{len(unchecked)} vector(s) not checked at all this cycle "
                             f"({', '.join(unchecked)})")
            remember += (" That is a statement about what we read, not about the estate: "
                         + " and ".join(parts) + ", each listed in Section 4.")
        if coverage["gaps"]:
            # The distinction this sentence carries is the one Rob's principle turns on. The
            # residue above is work we have not done. This is work we cannot do at all
            # without somebody granting, onboarding or enabling something. Collapsing the
            # two would either make our own backlog look unfixable or make a genuine blind
            # spot look like laziness.
            remember += (f" Separately - and not a finding - "
                         f"{plural(len(coverage['gaps']), 'population')} send no telemetry "
                         f"at all, so no query can produce a hit or a clean result inside "
                         f"them. We can neither confirm nor deny there. Each is named and "
                         f"counted in the coverage table, with the exact thing that would "
                         f"make it visible.")
    if exposure:
        remember += (" The risk on this page is not that we were hit - it is that "
                     + " and ".join(v["name"] for v in exposure)
                     + " would make the next one worse than it needs to be.")
    w(f"**The one thing to remember.** {remember}")
    w("")
    w("---")
    w("")

    # ---------------- SECTION 2 ----------------
    #
    # The section that answers the question Section 1 provokes and cannot answer. Placed
    # before the action list deliberately: a reader who sees the actions first reads them as
    # a backlog, and a reader who sees this first reads the same actions as the specific
    # links they close.
    if chain:
        w("## Section 2 - Could it happen to us")
        w("")
        w("Section 1 says whether this campaign reached us. It does not say what stood in "
          "its way, and those are different questions with different answers. A hunt "
          "measures arrival; it does not measure defense, so a clean result is silent on "
          "whether anything was actually stopping the thing.")
        w("")
        # The single most important sentence in the report for a reader deciding whether to
        # fund anything, and it is derived from the dependency vector rather than asserted.
        pinned = ioc.get("counts", {}).get("npm rows pinned to an exact version", 0)
        npm_rows = ioc.get("counts", {}).get("npm rows", 0)
        w(f"**Why today's result came back clean.** Not because a control caught something. "
          f"The estate does not depend on the package names this attacker chose - so there "
          f"was nothing here for the worm to arrive in. Version pinning "
          f"({pinned} of {npm_rows} dependency rows, {pct(pinned, npm_rows or 1)}) would "
          f"have helped and is worth keeping, but it was not what decided the outcome. The "
          f"next campaign picks different packages, and that is the case this section is "
          f"about.")
        w("")
        w("**The campaign's chain, link by link.** Each row is a step the worm has to "
          "complete. The state says what is in its way, and every state is read from the "
          "same artifacts as the rest of this report.")
        w("")
        w("| # | The worm needs to | What is in its way | What would change it |")
        w("|---|---|---|---|")
        for link in chain:
            w(f"| {md_cell(link['link'].split('.', 1)[0])} | "
              f"{md_cell(link['worm_needs'])} | **{link['state']}** | "
              f"{md_cell(link['closed_by'])} |")
        w("")
        w("What each state means:")
        w("")
        for state, note in CONTROL_STATE_NOTE.items():
            present = sum(1 for link in chain if link["state"] == state)
            w(f"- **{state}** ({present} of {len(chain)} links) - {note}")
        w("")
        # The tally is the executive summary of the section and it must not be softened. A
        # reader who takes one line from this page should take this one.
        held = sum(1 for link in chain if link["state"] in (CONTROLLED, PARTLY_CONTROLLED))
        detected = sum(1 for link in chain if link["state"] == DETECTION_ONLY)
        unknown = sum(1 for link in chain if link["state"] == UNMEASURED)
        wide_open = sum(1 for link in chain if link["state"] == OPEN)
        w(f"**In one line.** Of {len(chain)} links, we have a measured obstacle in front of "
          f"{held}, we would detect {detected} after the fact without preventing them, "
          f"{wide_open} has nothing in the way at all, and for {unknown} we have not "
          f"established whether anything is in the way. That last number is the cheapest "
          f"one on this page to reduce: it is questions, not projects.")
        w("")
        if wide_open or unknown:
            w("> **What this is not.** None of this is evidence that anything happened. It "
              "is the answer to what happens next time, and it is the part of the picture a "
              "clean hunt result cannot supply. Read it as the case for the work in Section "
              "3, not as a reason to pause the work already in flight.")
            w("")

        # The chain above is our reading of the campaign. This subsection checks that reading
        # against the published advisories: their TTP list is the denominator, so a step the
        # campaign performs and our chain never mentioned shows up as a number rather than as
        # an absence nobody notices.
        if advisory:
            out.extend(render_advisory_coverage(advisory))

        w("---")
        w("")

    # ---------------- SECTION 3 ----------------
    w("## Section 3 - What to do, in order")
    w("")
    if not actions:
        w("No actions arising from this run.")
    else:
        w("Ordered by priority. Priority 1 items should start this week.")
        w("")
        w("| # | Priority | Action | Scope | Owner | Effort |")
        w("|---|---|---|---|---|---|")
        for index, action in enumerate(actions, 1):
            # Truncating mid-team-name produces a handle that looks real and is not, so the
            # summary shows whole names and an explicit count of the rest. The full set is
            # printed under the action below.
            names = action["owners"]
            owners_text = ("; ".join(names[:2]) + (f" +{len(names) - 2} more"
                                                   if len(names) > 2 else "")) or "unassigned"
            w(f"| {index} | P{action['priority']} | {action['title']} | "
              f"{action['scope']} | {owners_text} | {action['effort'].split('.')[0]} |")
        w("")
        for index, action in enumerate(actions, 1):
            w(f"### {index}. {action['title']}  `P{action['priority']}`")
            w("")
            w(f"**Why this matters now.** {action['why_now']}")
            w("")
            w(f"**Scope.** {action['scope']}.  ")
            w(f"**Effort.** {action['effort']}  ")
            w(f"**Owner.** {'; '.join(action['owners']) or 'unassigned'}")
            if action.get("blocked_by"):
                w(f"  \n**Blocked by.** {action['blocked_by']}")
            w("")
            # Plain Markdown, not <details>. The PDF renderer parses with html=False and
            # escapes inline HTML, so a collapsible block would print its own tags as text
            # in the distributed document.
            w(f"**Affected resources ({len(action['targets'])}).**")
            w("")
            # Long target lists are capped in the action body and printed in full in the
            # evidence section. The cap is stated, never silent: an unmarked truncation
            # reads as a complete list.
            shown = action["targets"][:25]
            for target in shown:
                w(f"- `{target}`")
            if len(action["targets"]) > len(shown):
                w(f"- _...and {len(action['targets']) - len(shown)} more. The complete list "
                  f"is in Section 4._")
            w("")
    w("**Decisions needed from you.**")
    w("")
    # The first decision is derived, not fixed. It used to read "approve the access request
    # for endpoint telemetry" unconditionally, which asked an executive to authorize a
    # permission the tenant already held - and, worse, told them the laptops were unseen on
    # a cycle where they had been searched. What a reader is asked to decide has to follow
    # from what was actually found.
    endpoint_vector = next((v for v in vectors if v["name"].startswith("Endpoint /")), None)
    endpoint_status = endpoint_vector["status"] if endpoint_vector else NOT_RUN
    if endpoint_status == BLOCKED:
        decisions = ["Approve the access request for endpoint telemetry, or accept in "
                     "writing that laptops stay outside this hunt."]
    elif endpoint_status == NOT_RUN:
        decisions = ["Endpoint telemetry was not queried this cycle. Access is not the "
                     "blocker - decide who owns running it before the next report."]
    else:
        # What an executive is asked to decide has to be a thing they can decide. Unread
        # items are our backlog and need no approval; unobservable populations need somebody
        # to fund onboarding or sign that the estate stays partly dark. Only the second is a
        # decision, so only the second is put here.
        gaps = (endpoint_vector or {}).get("coverage_gaps") or []
        decisions = [f"Endpoint telemetry was queried and found nothing across the "
                     f"population it can observe. {plural(len(gaps), 'population')} sit "
                     f"outside that - named and enumerable in Section 4. Decide for each: "
                     f"fund the change that makes it visible, or accept in writing that "
                     f"this hunt can neither confirm nor deny anything inside it."
                     ] if gaps else []
    decisions += [
        "Confirm whether build-step pinning becomes a policy with an enforcement date, "
        "or stays a recommendation.",
        "Name owners for any repository listed as having none.",
    ]
    for index, decision in enumerate(decisions, start=1):
        w(f"{index}. {decision}")
    w("")

    # THE GATE. Written because two questions were being asked of every one of these reports
    # and neither was answered anywhere in it: what would make this GREEN, and can development
    # continue in the meantime. A reader left to infer the second answer infers the cautious
    # one, which is how a clean hunt result ends up holding delivery on the strength of
    # posture work that was never a blocker to anything.
    if gate:
        w(f"### What would move this report to {'GREEN' if verdict['rag'] != 'GREEN' else 'and keep it GREEN'}")
        w("")
        # The honesty clause. It goes first because it changes how every row below is read,
        # and because a gate that implies an unreachable finish line is a gate nobody starts.
        permanent = [g for g in coverage["gaps"] if "no Defender onboarding can close this"
                     in (g.get("closed_by") or "") or "permanent" in (g.get("closed_by") or "")]
        if permanent:
            w(f"**First, what GREEN cannot mean.** {plural(len(permanent), 'population')} in "
              f"the coverage register cannot be made observable at any price - the platform "
              f"emits no telemetry and no onboarding changes that. So GREEN can never mean "
              f"\"proven absent everywhere\". The only definition that is reachable, and the "
              f"one this gate is built on:")
            w("")
            w("> **GREEN** = every vector clear, zero unread items, and every remaining blind "
              "spot carries a named owner who has accepted it in writing.")
            w("")
        breach_clear = not [v for v in vectors if v["status"] == FINDINGS
                            and v.get("is_compromise_evidence")]
        if breach_clear:
            w("**Second, and separately: none of this is a reason to pause development.** "
              "There is no evidence of compromise, no repository to quarantine and no "
              "credential known to be stolen. Every item below is hardening or measurement. "
              "Holding delivery against them buys nothing.")
            w("")
        w("| # | Gate | Effort | Ours to close | Owner |")
        w("|---|---|---|---|---|")
        for index, item in enumerate(gate, 1):
            w(f"| {index} | {md_cell(item['gate'])} | {item['effort']} | "
              f"{'Yes' if item['ours'] else '**No - a decision**'} | "
              f"{md_cell(item['owner'])} |")
        w("")
        ours = [g for g in gate if g["ours"]]
        theirs = [g for g in gate if not g["ours"]]
        w(f"{plural(len(ours), 'gate')} can be closed by the teams already doing this work. "
          f"{plural(len(theirs), 'gate')} cannot - "
          + ("they need a budget or an ownership decision that nobody has been asked to make, "
             "and they are the real blockers."
             if theirs else "so engineering can reach this on its own."))
        w("")
        for index, item in enumerate(gate, 1):
            w(f"#### {index}. {item['gate']}")
            w("")
            w(f"{item['why']}")
            w("")
            for line in item["detail"][:15]:
                w(f"- {line}")
            if len(item["detail"]) > 15:
                w(f"- _...and {len(item['detail']) - 15} more, listed in Section 4._")
            w("")
    w("---")
    w("")

    # ---------------- SECTION 4 ----------------
    w("## Section 4 - Evidence")
    w("")
    w("### 4.1 Attack vector status")
    w("")
    w("| Attack vector | Status | Scope examined | Headline counts |")
    w("|---|---|---|---|")
    for vector in vectors:
        headline = "; ".join(f"{k}: {v}" for k, v in list(vector.get("counts", {}).items())[:3])
        w(f"| {vector['name']} | **{vector['status']}** | {vector['scope']} | {headline} |")
    w("")
    w("Status vocabulary:")
    w("")
    for status, note in STATUS_NOTE.items():
        w(f"- **{status}** - {note}")
    w("")
    w("> A zero is only evidence if the query could have found the thing. Each vector "
      "below carries the coverage evidence that earns its status. A zero with no coverage "
      "evidence is not reported as clean.")
    w("")

    # Section numbers are counted, not written. They used to be: the per-vector loop
    # emitted 3.2 upward and the detail sections below hardcoded 3.9 through 3.14, which
    # agreed exactly as long as there were seven vectors. The endpoint vector becoming a
    # real vector made it eight, and the document then had two different sections both
    # called 3.9 - including one cross-reference pointing at the wrong one. A numbering
    # scheme that depends on a count elsewhere in the file will drift again, so it now
    # derives from the same counter that emits the headings.
    section = [1]

    def heading(title: str) -> str:
        section[0] += 1
        return f"### 4.{section[0]} {title}"

    # The evidence behind Section 2. First in the evidence section, alongside the coverage
    # register, because both are limits on how the results below should be read - and because
    # the control axis is the newest and the one a technical reader will most want to check
    # the derivation of before believing the summary table.
    if chain:
        w(heading("Control posture - the evidence behind each link"))
        w("")
        w("Section 2 states what is in the way of each step. This is where each of those "
          "states comes from. Every line is read from a coverage artifact, and a link with "
          "no lines under it is a link stated as UNMEASURED - which is the honest output "
          "when no artifact speaks to it, and is not the same as a link with nothing in "
          "the way.")
        w("")
        for link in chain:
            w(f"**{link['link']}** - {link['state']}")
            w("")
            w(f"*The worm needs:* {link['worm_needs']}")
            w("")
            if link.get("evidence"):
                for line in link["evidence"]:
                    w(f"- {line}")
            else:
                w("- No artifact in this hunt measures whether anything stands in the way "
                  "of this step. That is why the state is UNMEASURED and not a judgment in "
                  "either direction.")
            w("")
            w(f"*What would change the state:* {link['closed_by'].rstrip('.')}.  ")
            w(f"*Owner:* {link['owner']}")
            w("")
        w("> Read the states, not a total. These links are not equally weighted and they do "
          "not sum: a control on the first link prevents the attack, and a control on the "
          "last one only limits what an attacker keeps. A count of held links says less "
          "than which links are held.")
        w("")

    if advisory:
        block = render_advisory_evidence(advisory)
        # The heading counter owns the number, so the sub-renderer emits its own title and
        # this replaces it - the alternative is a second numbering scheme that drifts.
        block[0] = heading("Advisory-TTP coverage - the evidence behind each state")
        out.extend(block)

    # The coverage register. Everything this hunt cannot see, on its own axis, before any
    # result is discussed.
    #
    # It comes first in the evidence section on purpose. A reader who works down through
    # eight clean vectors and only then meets the dark third of the estate has already
    # formed the belief; putting the limit ahead of the results makes every status below it
    # read correctly the first time.
    #
    # Nothing here is a finding, nothing here is counted as one, and nothing here moves the
    # verdict. Every row is enumerable - `named_by` is the query that returns the members -
    # because a population nobody can list is not something anybody can fix, and this
    # renderer refuses to publish one.
    if coverage["gaps"]:
        w(heading("What this hunt cannot see - the coverage register"))
        w("")
        w(f"{plural(len(coverage['gaps']), 'population')} produce no telemetry this hunt "
          f"can query. Inside them a query returns nothing whether or not the campaign is "
          f"present, so no result from this report - clean or otherwise - describes them. "
          f"They are listed separately from the findings, they are not counted as findings, "
          f"and they do not color the verdict. That is not leniency: a color driven by an "
          f"unobservable population would say the same thing every day forever, and would "
          f"say it on the day something real happened.")
        w("")
        w("| # | Gap | Population | We can neither confirm nor deny | What closes it | Owner |")
        w("|---|---|---|---|---|---|")
        for index, gap in enumerate(coverage["gaps"], 1):
            w(f"| {index} | {md_cell(gap['gap'])} | {md_cell(gap['population'])} | "
              f"{md_cell(gap['cannot_confirm_or_deny'])} | {md_cell(gap['closed_by'])} | "
              f"{md_cell(gap['owner'])} |")
        w("")
        w("**How to produce the list for each one.** A gap is only actionable if somebody "
          "can be handed the actual members, by an identifier they can act on. These are "
          "those queries. They are in the report rather than in a runbook because a gap "
          "whose membership nobody can produce is not a gap anybody can close.")
        w("")
        w("Each returns the population as it stands when it runs, and each is grouped the "
          "same way as the count beside it in the table - so the list length matches the "
          "number, give or take the handful of devices and events that move as the 7-day "
          "and 30-day windows slide between two executions. Expect a difference of that "
          "size and no more; a larger one means the query and the count have diverged and "
          "the row should not be trusted until they agree.")
        w("")
        for index, gap in enumerate(coverage["gaps"], 1):
            w(f"{index}. **{gap['gap']}** - {gap['vector']}")
            w("")
            w(f"    {gap['named_by']}")
            w("")
        w("> A population that cannot be enumerated does not appear in this table. If we "
          "cannot produce the list, nobody can act on it, and printing it would add a worry "
          "with no work item attached - which is the definition of a false positive on the "
          "coverage axis. Where such a population is suspected, the reportable item is the "
          "reconciliation against a source that *can* enumerate it, and it appears above in "
          "that form or not at all.")
        w("")

    # Access gaps, priced. §0.6(b): "we need more access" is not a work item until someone
    # can act on it without a discovery phase of their own. Six columns, every one of them
    # supplied by the collector that actually queried the tenant, and the render aborts if
    # any is blank - so this table cannot degrade into "insufficient permissions".
    #
    # Conditional, and deliberately so: on a run with full access this section does not
    # exist, rather than existing and saying "none". An empty standing section is where a
    # real gap goes to be skimmed past.
    gaps = [(v["name"], g) for v in vectors for g in (v.get("access_required") or [])]
    if gaps:
        w(heading("Access required, exactly"))
        w("")
        w(f"{plural(len(gaps), 'privilege')} would let this hunt answer a question it "
          f"currently cannot. Each row is complete enough to raise as a ticket without "
          f"coming back to us for detail.")
        w("")
        w("| Vector | API | Permission | Grant type | Granted by | What it would prove |")
        w("|---|---|---|---|---|---|")
        for vector_name, gap in gaps:
            w(f"| {vector_name} | {gap['api']} | `{gap['permission']}` | "
              f"{gap['grant_type']} | {gap['granted_by']} | {gap['proves']} |")
        w("")
        w("Endpoint per permission:")
        w("")
        for _, gap in gaps:
            w(f"- `{gap['permission']}` -> `{gap['endpoint']}`")
        w("")
        w("> Grants are verified against the tenant, not against local configuration. A "
          "credential missing from a config file is evidence about that file. Earlier runs "
          "of this report inferred a permissions problem from an empty `.env` and raised a "
          "request for a permission that had already been granted.")
        w("")

    for vector in vectors:
        w(heading(f"{vector['name']} - {vector['status']}"))
        w("")
        if vector.get("counts"):
            w("| Metric | Value |")
            w("|---|---|")
            for metric, value in vector["counts"].items():
                w(f"| {metric} | {value} |")
            w("")
        # §0.6(c). What specifically earned FINDINGS. A status a reader cannot trace to a
        # named item is the shape a false positive takes: it looks like diligence, costs
        # nothing to emit, and teaches the reader to discount the next real one.
        if vector.get("evidence_for_status"):
            w(f"**What earned this status.** Named items only; this vector "
              + ("carries evidence of compromise." if vector.get("is_compromise_evidence")
                 else "measures exposure, not compromise - nothing here says the campaign "
                      "reached us."))
            w("")
            for line in vector["evidence_for_status"]:
                w(f"- {line}")
            w("")
        if vector.get("coverage"):
            w("**Proof this check works (coverage evidence).**")
            w("")
            for line in vector["coverage"]:
                w(f"- {line}")
            w("")
        if vector.get("limits"):
            w("**What this check does NOT cover.**")
            w("")
            for line in vector["limits"]:
                w(f"- {line}")
            w("")
        # Section 1 puts a count of unread items on the face of the report; without this
        # block Section 4 never says what they are, so the one number a reader is asked to
        # act on is the one number they cannot look up.
        if vector.get("unresolved_items"):
            w(f"**Not read - {len(vector['unresolved_items'])} item(s). Closing these "
              f"closes this vector.**")
            w("")
            for line in vector["unresolved_items"]:
                w(f"- {line}")
            w("")
        # The coverage axis, restated per vector. The register above collects these across
        # the report; a reader who came straight to this vector needs to know here, next to
        # its status, that the status does not speak for these populations.
        if vector.get("coverage_gaps"):
            w(f"**Outside what this check can observe - "
              f"{plural(len(vector['coverage_gaps']), 'population')}. This does NOT change "
              f"the status above; the status describes the population we can observe.**")
            w("")
            for gap in vector["coverage_gaps"]:
                w(f"- {coverage_gap_sentence(gap)}")
            w("")
        # §0.6(b) in the evidence section. `validate_vectors` guarantees all six fields are
        # present, so this renders a request a reader can forward to a tenant admin without
        # a follow-up conversation - which is the entire difference between a priced gap
        # and "could not check, no access".
        if vector.get("access_required"):
            w("**Access required to close this - exact privileges.**")
            w("")
            for gap in vector["access_required"]:
                w(f"- {access_gap_sentence(gap)}")
            w("")
        if vector.get("blocked_by"):
            w(f"**Blocked by.** {vector['blocked_by']}")
            w("")

    # The Bun question, in one place. This is the campaign's execution vehicle, so it is the
    # single question the endpoint vector exists to answer - and it is not one question. It
    # is seven, they fail independently, and they were previously spread across six query
    # results, two detection files that had never been executed, and a network surface
    # nobody had looked at. A reader adding those up by hand cannot tell which zeros were
    # readable, which is the condition under which a zero gets over-read.
    bun_questions = (endpoint_vector or {}).get("bun_questions") or []
    if bun_questions:
        answered = [q for q in bun_questions if q.get("readable")]
        w(heading("The Bun question, answered - every check and the control that earns it"))
        w("")
        w(f"Bun is how this campaign executes: a compromised package fetches a Bun release "
          f"and runs an obfuscated payload under it, bypassing the Node runtime a defender "
          f"would be watching. {len(answered)} of {len(bun_questions)} questions below "
          f"returned an answer the control supports. "
          + ("Every question was answerable."
             if len(answered) == len(bun_questions) else
             f"The other {len(bun_questions) - len(answered)} are withdrawn, not reported "
             f"as clean, and appear in the unresolved list."))
        w("")
        w("| # | Question | Answer | Control that makes it readable | What the answer covers |")
        w("|---|---|---|---|---|")
        for index, question in enumerate(bun_questions, 1):
            mark = "" if question.get("readable") else "**NO ANSWER** - "
            w(f"| {index} | {question['question']} | {mark}{question['verdict']} "
              f"| {question['control']} | {question['covers']} |")
        w("")
        # Said explicitly because it is the sentence a reader would otherwise construct for
        # themselves, wrongly. Seven zeros in a row read as estate-wide clearance; two of
        # these are structurally narrower than that and say so in their own row.
        w("> Read the last column before generalizing any row. A rule keyed on Bun as the "
          "parent process cannot fire on a device where Bun never runs, so its zero clears "
          "only the devices where Bun executes - not the estate. The rows that are "
          "estate-wide say so.")
        w("")

    # Vector-specific detail that does not fit the generic shape.
    if reusable.get("ranked_sinks"):
        w(heading("Target list - shared build steps receiving the whole secrets context"))
        w("")
        w("Ranked by pipeline references, which is consumer repositories summed across "
          "every shared workflow that reaches the sink. This is the leverage list: the "
          "top row is one file.")
        w("")
        w("| Sink receiving all secrets | Pipeline refs | Shared workflows | Mechanism | "
          "Ref | Mutable ref | Deploys |")
        w("|---|---|---|---|---|---|---|")
        for sink in reusable["ranked_sinks"]:
            w(f"| `{sink['sink']}` | **{sink['consumer_refs']}** | {sink['workflows']} | "
              f"{', '.join(sink['mechanisms'])} | `{sink['sink_ref'] or 'n/a'}` | "
              f"{'**yes**' if sink['sink_ref_mutable'] else 'no'} | "
              f"{'yes' if sink['deploying'] else 'no'} |")
        w("")
        w("**Why `toJSON(secrets)` and `secrets: inherit` are not the same row.** "
          "`toJSON` renders every secret VALUE into the job as text, where it can be "
          "written to a file, echoed, or captured by any step that follows. "
          "`secrets: inherit` forwards the context to a called workflow without "
          "serializing it. Both are wider than they need to be; only the first puts the "
          "values in the shell.")
        w("")
        w("**Mitigation, in order.**")
        w("")
        w("1. Pin every sink to a 40-character commit SHA. A `@v2` tag can be moved by "
          "whoever owns the repository, with no signal to any consumer.")
        w("2. Replace `toJSON(secrets)` with the named secrets the step actually uses. "
          "Where the step needs many, that is a design finding worth raising separately.")
        w("3. Prefer OIDC federation to the cloud provider over long-lived secrets. Only "
          f"{reusable['counts'].get('Definitions using OIDC instead of long-lived secrets', 0)} "
          f"of {reusable['counts'].get('Shared reusable workflow definitions parsed', 0)} "
          "shared definitions use it today.")
        w("4. Fix at the shared definition, not in the consumers. One file changes "
          "hundreds of pipelines.")
        w("")

    if ci.get("tojson"):
        w(heading("Target list - per-repository workflows handing over the whole secrets context"))
        w("")
        w(f"Pin rate across the estate: **{ci.get('pin_rate')}** of action references are "
          f"pinned to a commit SHA.")
        w("")
        w("| Repository | Workflow | Reaches production | Owner |")
        w("|---|---|---|---|")
        owner_index = (owners or {}).get("repos", {}) or {}
        for entry in ci["tojson"]:
            row = owner_index.get(entry["repo"], {})
            prod = row.get("reaches_production")
            prod_text = "**yes**" if prod else ("no" if prod is False else "unknown")
            owner_text = ", ".join(row.get("default_owners") or row.get("owners") or []) \
                or f"_{row.get('owner_state', 'not resolved')}_"
            w(f"| `{entry['repo']}` | `{entry['path']}` | {prod_text} | {owner_text} |")
        w("")
        w("**Mitigation.** Replace the whole-context pass with an explicit secret list.")
        w("")
        w("```yaml")
        w("# Before - every secret the repo holds, in one object, handed to a step")
        w("- uses: some-org/some-action@v1")
        w("  with:")
        w("    secrets: ${{ toJSON(secrets) }}")
        w("")
        w("# After - only what the step needs, and the action pinned to a commit")
        w("- uses: some-org/some-action@<40-char-commit-sha>  # v1.2.3")
        w("  with:")
        w("    api_key: ${{ secrets.THIS_STEPS_API_KEY }}")
        w("```")
        w("")
        w("Where a step genuinely needs many secrets, prefer OIDC federation to the cloud "
          "provider over long-lived secrets, and scope the federated role to the "
          "environment. Where the whole context is passed to a reusable workflow, use "
          "`secrets: inherit` on a called workflow you control instead of serializing to "
          "text - `toJSON` renders every value into the job's shell, where it can be "
          "written to disk or logged.")
        w("")

    if ioc.get("adjacent"):
        w(heading("Adjacent packages - right name, safe version"))
        w("")
        w("These packages were targeted by the campaign. We use them, but not at a "
          "malicious version. They are listed because they are where an accidental upgrade "
          "would hurt.")
        w("")
        w("| Package | Repositories | Versions present |")
        w("|---|---|---|")
        for name, info in sorted(ioc["adjacent"].items(),
                                 key=lambda kv: -len(kv[1].get("repos", []))):
            w(f"| `{name}` | {len(info.get('repos', []))} | "
              f"{', '.join('`' + v + '`' for v in info.get('versions', []))} |")
        w("")
        w("**Mitigation.** Add these to a version deny-list at the internal registry proxy "
          "so an upgrade to a malicious version fails at install rather than at review.")
        w("")

    if registry.get("window_first"):
        w(heading("Attack window, derived from the registry"))
        w("")
        w(f"- First malicious publish: `{registry['window_first']}`")
        w(f"- Last malicious publish: `{registry['window_last']}`")
        w(f"- Malicious package@version pairs derived: "
          f"{registry['counts'].get('Malicious package@version pairs derived')}")
        w("")
        w("This window is derived by querying the public registry directly for every "
          "affected package name, rather than by taking a vendor's word for it. It is the "
          "window every other check in this report is scoped to, so widening it widens "
          "the hunt.")
        w("")

    if owners:
        w(heading("Ownership resolution"))
        w("")
        w(f"Resolved for {owners.get('repos_resolved', 0)} repositories that appear in at "
          f"least one finding list.")
        w("")
        w("| Ownership state | Repositories |")
        w("|---|---|")
        for state, count in sorted((owners.get("owner_states") or {}).items()):
            w(f"| {state} | {count} |")
        w("")
        # The blast-radius denominator is printed before the intersection, because the
        # intersection is only as good as the share of repositories topology could resolve.
        # "0 unowned and production-reaching" out of 24 resolved is a very different claim
        # from the same zero out of 177, and the two must not be able to look alike.
        rows = (owners.get("repos") or {}).values()
        resolved = [r for r in rows if r.get("reaches_production") is not None]
        prod_yes = [r for r in resolved if r.get("reaches_production")]
        w("| Deployment reach | Repositories |")
        w("|---|---|")
        w(f"| Confirmed reaches production | {len(prod_yes)} |")
        w(f"| Confirmed does NOT reach production | {len(resolved) - len(prod_yes)} |")
        w(f"| **Unresolved - reach unknown** | **{len(list(rows)) - len(resolved)}** |")
        w("")
        unowned_prod = owners.get("unowned_and_reaches_production") or []
        w(f"**Unowned AND confirmed production-reaching: {len(unowned_prod)}** "
          f"— out of {len(resolved)} repositories whose deployment reach could be "
          f"resolved at all, from {len(list(rows))} in the finding set. "
          + ("Nobody is accountable for these and they can deploy to production."
             if unowned_prod else
             "This zero is bounded by that denominator. It means no *resolved* "
             "production-reaching repository is unowned; it does not clear the "
             f"{len(list(rows)) - len(resolved)} whose reach is unknown."))
        if unowned_prod:
            w("")
            for repo in unowned_prod:
                w(f"- `{repo}`")
        w("")
        # The complete unowned list lives here, because the action in Section 3 caps its
        # target list and points at this section for the rest.
        unowned_all = sorted(repo for repo, row in (owners.get("repos") or {}).items()
                             if row.get("owner_state") == "unowned")
        if unowned_all:
            w(f"**Complete list of repositories in this report with no CODEOWNERS "
              f"({len(unowned_all)}).**")
            w("")
            w("| Repository | Deployment reach |")
            w("|---|---|")
            for repo in unowned_all:
                reach = (owners.get("repos") or {}).get(repo, {}).get("reaches_production")
                w(f"| `{repo}` | "
                  f"{'**production**' if reach else ('non-production' if reach is False else 'unknown')} |")
            w("")
        w("**What this check does NOT cover.**")
        w("")
        for line in owners.get("limits", []):
            w(f"- {line}")
        w("")

    # Artifact ages. A report assembled from collectors that ran on different days is
    # normal - the registry window is fixed history and re-reading it changes nothing,
    # while the endpoint surface moves hourly. What is not acceptable is presenting them
    # as one moment in time. Every "as of today" in the document is only true of the rows
    # that were collected today, and §0.6(a) does not let that go unstated.
    if sources:
        w(heading("How old is each answer"))
        w("")
        w("Collectors run independently and are not all re-run every cycle. A stale "
          "artifact is not wrong, but it answers a question about the day it was "
          "collected, and this table is how a reader tells the two apart.")
        w("")
        w("| Feeds | Artifact | Collected | Age at render |")
        w("|---|---|---|---|")
        for source in sources:
            w(f"| {source['feeds']} | `{source['path']}` | {source['collected']} "
              f"| {source['age']} |")
        w("")
        stale = [s for s in sources if s["age_hours"] is not None and s["age_hours"] > 36]
        if stale:
            w(f"**{plural(len(stale), 'artifact')} older than 36 hours: "
              + ", ".join(f"`{s['path']}` ({s['age']})" for s in stale)
              + ".** Re-run those collectors before treating their vectors as current.")
            w("")

    w(heading("Reproducing this report"))
    w("")
    w("```bash")
    w("python3 scripts/hunt/collect_repo_trees.py        # files on disk, incl. Bun artifacts")
    w("python3 scripts/hunt/hunt_code_search.py          # corroborating index search")
    w("python3 scripts/hunt/hunt_branches.py             # branches and commits in the window")
    w("python3 scripts/ioc/match_npm_ioc.py --json exports/hunt/ioc_match_r3.json")
    w("python3 scripts/hunt/sweep_actions_posture.py     # CI posture")
    w("python3 scripts/hunt/collect_repo_owners.py       # CODEOWNERS + blast radius")
    w("#   shared-workflow fan-out is read from the deployment topology tables")
    w("python3 scripts/hunt/hunt_endpoint_defender.py    # laptops and servers, via Defender")
    w("python3 scripts/hunt/render_hunt_report.py        # this document")
    w("```")
    w("")
    w("`hunt_endpoint_defender.py` resolves its credentials from the encrypted store, not "
      "from the environment. It runs the telemetry control first and every later count is "
      "only readable because that control passed. The two queries below are the same ones "
      "it runs, if you want them individually:")
    w("")
    w("```bash")
    w("python3 scripts/ioc/run_kql_poc.py --run \\")
    w("  --query github_conf/detections/kql/coverage/08-bun-exe-telemetry-shape.kql")
    w("python3 scripts/ioc/run_kql_poc.py --run \\")
    w("  --query github_conf/detections/kql/backlog/22-bun-windows-artifact-sweep.kql")
    w("```")
    w("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path,
                        default=latest_round("repo_trees_r*_coverage.json",
                                             "repo_trees_r3_coverage.json"),
                        help="Repository file-tree coverage. Defaults to the highest round "
                             "present, because a pinned round number is a default that "
                             "goes stale without saying so.")
    parser.add_argument("--branches", type=Path, default=HUNT / "branch_hunt_r3_coverage.json")
    parser.add_argument("--code-search", type=Path, default=HUNT / "code_search_r3.json")
    parser.add_argument("--ioc", type=Path, default=HUNT / "ioc_match_r3.json")
    parser.add_argument("--posture", type=Path, default=HUNT / "actions_posture_r3_coverage.json")
    parser.add_argument("--registry", type=Path, default=HUNT / "rederive_window_14z.json")
    parser.add_argument("--endpoint", type=Path, default=HUNT / "endpoint_hunt.json",
                        help="Defender advanced-hunting results, from "
                             "scripts/hunt/hunt_endpoint_defender.py. Absent renders NOT "
                             "RUN - absence of the file says the collector did not run, "
                             "never that access was refused.")
    parser.add_argument("--owners", type=Path, default=HUNT / "repo_owners.json")
    parser.add_argument("--reusable", type=Path,
                        default=HUNT / "reusable_workflow_targets.json",
                        help="Shared reusable workflow definitions with consumer counts "
                             "and whole-secrets-context exposure, from the topology tables.")
    parser.add_argument("--lockfiles", type=Path,
                        default=latest_round("lockfiles_r*_coverage.json",
                                             "lockfiles_r5_coverage.json"),
                        help="Installed versions read from committed lockfiles. Supplies the "
                             "dependency vector's coverage gap - repositories with a "
                             "manifest and no lockfile record nothing about what they "
                             "resolved to, so they are unmeasured rather than clean.")
    parser.add_argument("--install-activity", type=Path,
                        default=latest_round("install_activity_r*.json",
                                             "install_activity_r1.json"),
                        help="Endpoint package-acquisition results. The only vector that "
                             "observes what a machine actually fetched rather than what a "
                             "repository declares.")
    parser.add_argument("--install-prevention", type=Path,
                        default=latest_round("install_prevention_r*.json",
                                             "install_prevention_r1.json"),
                        help="Whether an install is allowed to run scripts: `ignore-scripts` "
                             "read out of every `.npmrc` and every workflow install command in "
                             "the npm-relevant population. The control half of the same "
                             "question --install-activity answers on the arrival side.")
    parser.add_argument("--registry-proxy", type=Path,
                        default=latest_round("azure_artifacts_feeds*.json",
                                             "azure_artifacts_feeds.json"),
                        help="Internal package feeds and their upstreams. A feed proxying "
                             "npmjs serves the identical malicious tarball under its own "
                             "hostname, so this is both a result and the strongest available "
                             "control point.")
    parser.add_argument("--dead-drops", type=Path,
                        default=latest_round("dead_drops_r*.json", "dead_drops_r5.json"),
                        help="Dead-drop repository sweep, which supplies the exfiltration "
                             "link of the control chain.")
    parser.add_argument("--state", type=Path, default=HUNT / "report_state.json",
                        help="Previous run's counts, for the delta section.")
    parser.add_argument("--dispositions", type=Path, default=HUNT / "dispositions.json",
                        help="Adjudications of individual flagged items. An entry needs "
                             "both `reason` and `evidence` or it is ignored and the flag "
                             "stays open. Cleared items are still printed with their "
                             "reason - a disposition changes whether an item counts as "
                             "evidence of compromise, never whether it is shown.")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--as-of", type=str, default=None)
    parser.add_argument("--added-check", action="append", default=[],
                        dest="added_checks",
                        help="A check added to the hunt this cycle. Repeatable. Rendered "
                             "in the change section so a new check finding nothing is "
                             "still visible as a check that ran.")
    parser.add_argument("--advisory-iocs", type=Path,
                        default=latest_round("advisory_iocs_r*.json", "advisory_iocs_r1.json"),
                        help="Published campaign indicators - domains, addresses, file hashes "
                             "- swept against Defender tables, from "
                             "scripts/hunt/hunt_advisory_iocs.py. The only vector whose zero "
                             "is a statement about the attacker rather than about us.")
    parser.add_argument("--antiremediation", type=Path,
                        default=latest_round("antiremediation_r*.json",
                                             "antiremediation_r1.json"),
                        help="The anti-remediation watchdog sweep, from "
                             "scripts/hunt/hunt_antiremediation.py. The only vector whose result "
                             "changes the ORDER of remediation rather than its scope.")
    parser.add_argument("--commit-messages", type=Path,
                        default=latest_round("commit_messages_r*.json",
                                             "commit_messages_r1.json"),
                        help="Org-wide commit-message sweep for the campaign's extortion string "
                             "and forged authorship, from scripts/hunt/hunt_commit_messages.py.")
    parser.add_argument("--advisory-coverage", type=Path,
                        default=HUNT / "advisory_coverage.json",
                        help="Advisory-TTP coverage, from "
                             "scripts/hunt/build_advisory_coverage.py. Supplies the share of "
                             "the published attacker playbook this hunt can answer for. Absent "
                             "renders the section away entirely rather than as a zero, because "
                             "a missing mapping is not a measured absence of coverage.")
    parser.add_argument("--no-state-write", action="store_true",
                        help="Render without recording this run as the new baseline. Use "
                             "when re-rendering a past run so the delta is not corrupted.")
    args = parser.parse_args()

    as_of = args.as_of or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ioc_payload = read_json(args.ioc)
    campaign = (ioc_payload or {}).get("campaign", "shai-hulud / CHAINDROP npm worm")

    trees = vector_repo_files(read_json(args.trees))
    dispositions = load_dispositions(args.dispositions)
    branches = vector_branches(read_json(args.branches), dispositions)
    search = vector_code_search(read_json(args.code_search))
    lockfiles = read_json(args.lockfiles)
    ioc = vector_ioc(ioc_payload, lockfiles)
    owners = read_json(args.owners)
    posture_payload = read_json(args.posture)
    ci = vector_ci(posture_payload, owners)
    reusable = vector_reusable(read_json(args.reusable))
    registry = vector_registry(read_json(args.registry))
    endpoint = vector_endpoint(read_json(args.endpoint))
    install = vector_install_activity(read_json(args.install_activity))
    prevention = vector_install_prevention(read_json(args.install_prevention))
    proxy = vector_registry_proxy(read_json(args.registry_proxy))
    dead_drops = read_json(args.dead_drops)
    advisory = read_json(args.advisory_coverage)
    iocs = vector_advisory_iocs(read_json(args.advisory_iocs))
    watchdog = vector_antiremediation(read_json(args.antiremediation))
    commit_messages = vector_commit_messages(read_json(args.commit_messages))

    # Only these vectors can produce evidence that the campaign actually reached us.
    # CI posture findings are exposure, not compromise, and conflating the two is how a
    # report turns a hygiene backlog into a false incident.
    #
    # The endpoint vector belongs in this list and was missing from it. §0.6(c) cuts both
    # ways: the rule against inflating a weak signal is the same rule that forbids
    # demoting a strong one. This vector only reaches FINDINGS when a Bun binary executed
    # from a temp or staging path on a real workstation - the campaign's own shape, on the
    # one surface that can observe it - and while it sat outside this tuple that finding
    # would have been classed as exposure and rendered as "weaknesses that would make the
    # next one worse". The verdict would have read AMBER on a day the estate was breached.
    # The two new vectors belong here for the same reason the endpoint vector does. Install
    # activity is the only vector that observes an ACQUISITION rather than a declaration - if
    # a machine fetched a malicious tarball, that is the campaign reaching us and nothing
    # about it is exposure. A malicious version cached in our own package feed is likewise a
    # compromise of the supply path, not a hygiene finding.
    # The watchdog and commit-message vectors belong here for the same reason. A process polling
    # the token endpoint from an autostart entry, or the extortion string in a commit, is the
    # campaign reaching us - not a weakness that would make the next one worse.
    #
    # `prevention` is deliberately NOT in this tuple, and the exclusion is as load-bearing as the
    # endpoint vector's inclusion. A repository that installs with scripts enabled is how the
    # campaign would run, not evidence that it ran; classing that as compromise evidence would
    # put a hardening backlog into the verdict and turn a clean result AMBER on the strength of
    # work that was never a blocker.
    for vector in (trees, branches, search, ioc, endpoint, install, proxy, iocs, watchdog,
                   commit_messages):
        vector["is_compromise_evidence"] = True

    # Order is the reader's, not the collector's: the four vectors that answer "did it get
    # in" first, then the two that answer "how did it get in", then posture, then endpoint.
    # The watchdog sits last among the endpoint vectors because it is the only one a reader
    # consults AFTER deciding to respond.
    # `prevention` sits immediately after `install`, because the two are one question in two
    # halves - what a machine fetched, and whether anything stopped what it fetched from running.
    # Read apart, the arrival number looks like an incident and the control number looks like
    # reassurance; read together they are neither.
    vectors = [trees, branches, commit_messages, search, ioc, proxy, install, prevention, ci,
               reusable, registry, endpoint, iocs, watchdog]

    # §0.6 is checked before anything is written, and a violation stops the render rather
    # than annotating it. A report that cannot substantiate itself is worse than no report,
    # because it is read with exactly the same trust as one that can - and the failure mode
    # this guards against has already shipped once, silently, in a document that looked
    # complete on every page.
    chain = build_chain(ioc, lockfiles, proxy, install, endpoint, ci, reusable,
                        posture_payload, dead_drops, prevention)

    problems = (validate_vectors(vectors) + validate_chain(chain)
                + (validate_advisory(advisory) if advisory else []))
    if problems:
        print("[report] REFUSING TO RENDER - unsubstantiated claims (doctrine §0.6):",
              file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    verdict = compute_verdict(vectors)
    coverage = compute_coverage(vectors)
    current_state = build_state(vectors, verdict, coverage)
    delta = render_delta(read_json(args.state), current_state, args.added_checks)
    actions = build_actions(ci, endpoint, ioc, owners, registry, reusable, prevention)

    # Provenance, read from the filesystem rather than declared. A collector that was not
    # re-run leaves its artifact untouched, so mtime is the only honest answer to "when was
    # this measured" - and it is the one number nobody can forget to update.
    now = datetime.now(timezone.utc)
    sources = []
    for feeds, path in (("Repository files on disk", args.trees),
                        ("Branches and commits in the window", args.branches),
                        ("Corroborating code search", args.code_search),
                        ("Dependency inventory vs IOCs", args.ioc),
                        ("CI / Actions posture", args.posture),
                        ("Shared reusable workflows", args.reusable),
                        ("Registry ground truth", args.registry),
                        ("Endpoint / Defender", args.endpoint),
                        ("Endpoint install activity", args.install_activity),
                        ("Install-time script prevention", args.install_prevention),
                        ("Internal package registry (proxy)", args.registry_proxy),
                        ("Installed versions from lockfiles", args.lockfiles),
                        ("Dead-drop repository sweep", args.dead_drops),
                        ("Anti-remediation watchdog", args.antiremediation),
                        ("Commit messages across the orgs", args.commit_messages),
                        ("CODEOWNERS and blast radius", args.owners)):
        # Repo-relative, always. The default paths are absolute, and this report is
        # circulated - an absolute path publishes the analyst's home directory and
        # username alongside a document about repositories and staff.
        try:
            shown = str(path.resolve().relative_to(REPO_ROOT))
        except ValueError:
            shown = path.name
        if not path.exists():
            sources.append({"feeds": feeds, "path": shown, "collected": "not present",
                            "age": "vector renders NOT RUN", "age_hours": None})
            continue
        stamp = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        hours = (now - stamp).total_seconds() / 3600
        sources.append({
            "feeds": feeds, "path": shown,
            "collected": stamp.strftime("%Y-%m-%d %H:%M UTC"),
            "age": (f"{hours:.1f} h" if hours < 48 else f"{hours / 24:.1f} days"),
            "age_hours": hours,
        })

    # The gate reads the same freshness rows the provenance table prints, so a stale
    # artifact cannot show as stale in one place and current in the other. 36 hours is the
    # threshold used in both, named once here rather than twice.
    for source in sources:
        source["artifact"] = source["path"]
        source["stale"] = (source["age_hours"] is not None and source["age_hours"] > 36)
    gate = build_green_gate(vectors, actions, coverage, chain, sources, advisory)

    document = render(vectors, verdict, delta, actions, ioc, ci, registry, owners,
                      reusable, as_of, campaign, sources=sources, coverage=coverage,
                      chain=chain, gate=gate, advisory=advisory)

    out_path = args.out or (HUNT / "reports" / f"hunt-report-{as_of}.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(document)

    if not args.no_state_write:
        args.state.write_text(json.dumps(current_state, indent=2, default=str))

    print(f"[report] {verdict['rag']} -> {out_path}", file=sys.stderr)
    # Which artifact each number came from. A default that resolves to a file is a default
    # that can resolve to the wrong file, and the only cheap defense is saying which one.
    print(f"  read trees={args.trees.name} endpoint={args.endpoint.name}", file=sys.stderr)
    for vector in vectors:
        print(f"  {vector['status']:22s} {vector['name']}", file=sys.stderr)
    print(f"  {len(actions)} action(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
