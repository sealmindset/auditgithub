"""
Tests for the cross-scanner rule-merge decision.

The rule is stated in `src/api/services/rule_equivalence.py`: an AI proposes
that two scanners' rules describe one defect, a person approves it, and only
then does filing group them together. These tests pin the parts that decide
whether a wrong answer can become a merge.

Everything here is a pure function or a stub provider -- no database, no AI
call. The blocking query is exercised against real data separately; it is
measured at 478 candidate pairs within the Critical/High/Medium filing floor
and 834 across all severities (2026-09-16).

The asymmetry these tests enforce: a missed merge files a visible duplicate
that a person can close, while a wrong merge permanently claims a GRC issue
covers a finding it does not describe -- AuditBoard issues cannot be deleted
and their descriptions cannot be edited after create. So every failure path
must land on "not merged", never on "merged".
"""

import asyncio

import pytest

from src.api.services.finding_groups import Identity
from src.api.services.rule_equivalence import (
    MIN_CONFIDENCE,
    REVIEW_APPROVED,
    REVIEW_REJECTED,
    VERDICT_DISTINCT,
    VERDICT_EQUIVALENT,
    CandidatePair,
    Proposal,
    RuleSample,
    ask_provider,
    ask_provider_batch,
    build_prompt,
    canonical_pair,
    pair_key,
    parse_verdict,
)

GRYPE = Identity("grype", "GHSA-M7JM-9GC2-MPF2")
TRIVY = Identity("trivy-fs", "CVE-2024-21538")


def _candidate(**overrides) -> CandidatePair:
    defaults = dict(
        identity_a=GRYPE,
        identity_b=TRIVY,
        shared_repos=13,
        shared_locations=38,
        sample_paths=["app/package-lock.json"],
        samples_a=[
            RuleSample(
                title="cross-spawn 7.0.3 vulnerable",
                description="Regular Expression Denial of Service in cross-spawn",
                severity="high",
                file_path="app/package-lock.json",
            )
        ],
        samples_b=[
            RuleSample(
                title="cross-spawn: ReDoS",
                description="cross-spawn before 7.0.5 allows ReDoS",
                severity="high",
                file_path="app/package-lock.json",
            )
        ],
    )
    defaults.update(overrides)
    return CandidatePair(**defaults)


# ---------------------------------------------------------------------------
# Canonical ordering
#
# Without it, (grype, trivy) and (trivy, grype) are two rows that can hold
# opposite verdicts, and which one wins depends on query order.
# ---------------------------------------------------------------------------

def test_a_pair_has_one_stored_order():
    assert canonical_pair(GRYPE, TRIVY) == canonical_pair(TRIVY, GRYPE)


def test_the_key_does_not_depend_on_argument_order():
    assert pair_key(GRYPE, TRIVY) == pair_key(TRIVY, GRYPE)


def test_the_key_names_both_rules():
    key = pair_key(GRYPE, TRIVY)
    assert GRYPE.key in key and TRIVY.key in key


# ---------------------------------------------------------------------------
# The question
# ---------------------------------------------------------------------------

def test_the_prompt_names_both_scanners_and_both_rules():
    prompt = build_prompt(_candidate())
    for value in ("grype", "GHSA-M7JM-9GC2-MPF2", "trivy-fs", "CVE-2024-21538"):
        assert value in prompt


def test_the_prompt_is_the_same_whichever_side_the_caller_put_first():
    """Otherwise the same pair gets two different questions and can disagree."""
    forward = build_prompt(_candidate(identity_a=GRYPE, identity_b=TRIVY))
    reverse = build_prompt(
        _candidate(
            identity_a=TRIVY,
            identity_b=GRYPE,
            samples_a=_candidate().samples_b,
            samples_b=_candidate().samples_a,
        )
    )
    assert forward == reverse


def test_the_prompt_says_co_location_is_not_evidence():
    """The blocking query selects on co-location, so the model must discount it."""
    prompt = build_prompt(_candidate())
    assert "not evidence" in prompt


def test_the_prompt_asks_for_the_cheap_error():
    prompt = build_prompt(_candidate()).lower()
    assert "bias toward \"distinct\"" in prompt


def test_the_prompt_carries_no_code_snippet():
    """A snippet is not needed to compare two rules, and for the secret-scanner
    family the snippet is the credential itself."""
    candidate = _candidate()
    prompt = build_prompt(candidate)
    assert "code_snippet" not in prompt
    assert "snippet" not in prompt.lower()


def test_a_pair_with_no_examples_still_produces_a_prompt():
    prompt = build_prompt(_candidate(samples_a=[], samples_b=[]))
    assert "no examples available" in prompt


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------

def test_a_confident_equivalent_verdict_is_read_as_a_merge():
    raw = '{"verdict": "equivalent", "confidence": 0.95, "rationale": "Same advisory."}'
    proposal = parse_verdict(raw)
    assert proposal.verdict == VERDICT_EQUIVALENT
    assert proposal.confidence == pytest.approx(0.95)
    assert proposal.downgraded_from is None


def test_a_distinct_verdict_is_read_as_separate():
    proposal = parse_verdict('{"verdict": "distinct", "confidence": 0.4}')
    assert proposal.verdict == VERDICT_DISTINCT


def test_json_wrapped_in_prose_is_still_read():
    """Models preface answers; refusing the answer would cost a call for nothing."""
    raw = 'Here is my answer:\n{"verdict": "distinct", "confidence": 0.9}\nHope that helps.'
    assert parse_verdict(raw).verdict == VERDICT_DISTINCT


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "   ",
        "I cannot determine this.",
        "{not json at all",
        '{"verdict": "maybe", "confidence": 0.9}',
        '["equivalent"]',
        '{"confidence": 0.99}',
    ],
)
def test_an_unusable_answer_is_no_answer(raw):
    """None means nothing is recorded: the pair stays a candidate, scanners stay
    separate, and a later run can ask again. It is never read as a merge, and
    never as a rejection either -- a rejection is a claim too."""
    assert parse_verdict(raw) is None


def test_a_low_confidence_merge_is_downgraded_not_accepted():
    proposal = parse_verdict(
        '{"verdict": "equivalent", "confidence": 0.5, "rationale": "Possibly related."}'
    )
    assert proposal.verdict == VERDICT_DISTINCT
    assert proposal.downgraded_from == VERDICT_EQUIVALENT
    # The rationale survives, so a reviewer can still approve it by hand.
    assert proposal.rationale == "Possibly related."


def test_a_merge_with_no_confidence_is_treated_as_unsure():
    proposal = parse_verdict('{"verdict": "equivalent"}')
    assert proposal.verdict == VERDICT_DISTINCT
    assert proposal.downgraded_from == VERDICT_EQUIVALENT


def test_a_merge_with_an_unreadable_confidence_is_treated_as_unsure():
    proposal = parse_verdict('{"verdict": "equivalent", "confidence": "very"}')
    assert proposal.verdict == VERDICT_DISTINCT


def test_the_confidence_floor_is_exactly_at_the_boundary():
    at_floor = parse_verdict(
        '{"verdict": "equivalent", "confidence": %s}' % MIN_CONFIDENCE
    )
    assert at_floor.verdict == VERDICT_EQUIVALENT
    below = parse_verdict(
        '{"verdict": "equivalent", "confidence": %s}' % (MIN_CONFIDENCE - 0.01)
    )
    assert below.verdict == VERDICT_DISTINCT


def test_confidence_outside_the_range_is_clamped():
    """A model claiming 1.4 is not more certain than one claiming 1.0, and a
    stored value outside 0-1 breaks every comparison against it."""
    assert parse_verdict('{"verdict": "equivalent", "confidence": 1.4}').confidence == 1.0
    assert parse_verdict('{"verdict": "distinct", "confidence": -3}').confidence == 0.0


def test_a_low_confidence_distinct_verdict_is_left_alone():
    """The floor protects against wrong merges, not against wrong separations."""
    proposal = parse_verdict('{"verdict": "distinct", "confidence": 0.1}')
    assert proposal.verdict == VERDICT_DISTINCT
    assert proposal.downgraded_from is None


# ---------------------------------------------------------------------------
# Asking a provider
# ---------------------------------------------------------------------------

class _StubProvider:
    def __init__(self, reply=None, raises=None, delay=0.0):
        self.reply = reply
        self.raises = raises
        self.delay = delay
        self.calls = 0
        self.max_concurrent = 0
        self._active = 0

    async def execute_prompt(self, prompt: str) -> str:
        self.calls += 1
        self._active += 1
        self.max_concurrent = max(self.max_concurrent, self._active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.raises:
                raise self.raises
            return self.reply
        finally:
            self._active -= 1


def test_a_provider_answer_becomes_a_proposal():
    provider = _StubProvider('{"verdict": "equivalent", "confidence": 0.93}')
    proposal = asyncio.run(ask_provider(provider, _candidate()))
    assert proposal.verdict == VERDICT_EQUIVALENT
    assert provider.calls == 1


def test_a_provider_error_is_no_answer():
    """Every failure mode has the same right consequence: not merged."""
    provider = _StubProvider(raises=RuntimeError("502 from the deployment"))
    assert asyncio.run(ask_provider(provider, _candidate())) is None


def test_a_timeout_is_not_a_verdict():
    provider = _StubProvider('{"verdict": "equivalent", "confidence": 1.0}', delay=0.2)
    proposal = asyncio.run(ask_provider(provider, _candidate(), timeout_seconds=0.01))
    assert proposal is None


def test_a_batch_keeps_the_order_it_was_given():
    """A run has to be reproducible when read back, not ordered by whichever
    call finished first."""
    provider = _StubProvider('{"verdict": "distinct", "confidence": 0.9}')
    candidates = [
        _candidate(identity_a=Identity("s%d" % i, "r%d" % i)) for i in range(5)
    ]
    results = asyncio.run(ask_provider_batch(provider, candidates, concurrency=4))
    assert [c for c, _ in results] == candidates


def test_a_batch_respects_its_concurrency_cap():
    """The AI deployment is shared with triage and architecture analysis; an
    unbounded fan-out over 478 pairs would rate-limit those too."""
    provider = _StubProvider('{"verdict": "distinct", "confidence": 0.9}', delay=0.05)
    candidates = [
        _candidate(identity_a=Identity("s%d" % i, "r%d" % i)) for i in range(8)
    ]
    asyncio.run(ask_provider_batch(provider, candidates, concurrency=2))
    assert provider.max_concurrent <= 2


def test_an_empty_batch_asks_nothing():
    provider = _StubProvider('{"verdict": "distinct"}')
    assert asyncio.run(ask_provider_batch(provider, [])) == []
    assert provider.calls == 0


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def test_evidence_records_what_the_verdict_was_based_on():
    """A verdict with no record of its inputs cannot be re-examined when a
    model is replaced, which makes both worthless."""
    evidence = _candidate().evidence()
    assert evidence["shared_repos"] == 13
    assert evidence["shared_locations"] == 38
    assert evidence["sample_paths"] == ["app/package-lock.json"]
    assert "blocking" in evidence


def test_evidence_carries_no_code_snippet():
    evidence = _candidate().evidence()
    flat = repr(evidence)
    assert "code_snippet" not in flat
    for side in ("samples_a", "samples_b"):
        for sample in evidence[side]:
            assert set(sample) == {"title", "description", "severity", "file_path"}


# ---------------------------------------------------------------------------
# Review vocabulary
# ---------------------------------------------------------------------------

def test_only_approved_equivalent_can_change_grouping():
    """Stated here so the two words that matter are pinned: `load_equivalence_map`
    filters on exactly this pair of values."""
    assert REVIEW_APPROVED == "approved"
    assert REVIEW_REJECTED == "rejected"
    assert VERDICT_EQUIVALENT == "equivalent"


def test_a_proposal_defaults_to_no_downgrade():
    assert Proposal(verdict=VERDICT_DISTINCT, confidence=None, rationale=None).downgraded_from is None
