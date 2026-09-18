"""
Tests for the scanner-specific exception-rule generators.

A generated rule gets pasted into a repository and committed. That makes two
failure modes worse than producing nothing at all:

*   **A rule keyed on a path that no longer exists.** Several scanners record
    the path inside a throwaway clone (``/tmp/repo_scan_<random>/<repo>/...``).
    Committing that suppresses nothing, and the finding reappears on the next
    scan with a config file in the repository that looks like it should have
    stopped it.
*   **A rule keyed on the wrong identifier.** Terrascan skips on rule id and
    Nuclei excludes on template id, but what the ingest stores for both is a
    human-readable *name*. A rule built on the name is silently inert.

Neither is detectable by reading the generated text -- it looks like a valid
rule either way. So these tests pin the two properties that make the output
trustworthy: paths are repo-relative, and any identifier that cannot be trusted
as a suppression key is shipped with a visible VERIFY warning.

Pure functions only -- no database, no scanners.
"""

import json

import pytest

from src.api.routers.findings import (
    generate_generic_rule,
    generate_grype_rule,
    generate_horusec_rule,
    generate_nuclei_rule,
    generate_retirejs_rule,
    generate_terrascan_rule,
    generate_trivy_rule,
    repo_relative_path,
)


class _Finding:
    """Just the attributes the generators read."""

    def __init__(self, **kwargs):
        self.scanner_name = kwargs.get("scanner_name")
        self.rule_id = kwargs.get("rule_id")
        self.cve_id = kwargs.get("cve_id")
        self.ghsa_id = kwargs.get("ghsa_id")
        self.file_path = kwargs.get("file_path")
        self.line_start = kwargs.get("line_start")
        self.title = kwargs.get("title")
        self.package_name = kwargs.get("package_name")
        self.package_version = kwargs.get("package_version")
        self.code_snippet = kwargs.get("code_snippet")
        self.finding_type = kwargs.get("finding_type")


# ---------------------------------------------------------------------------
# The ephemeral-path problem
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stored,expected,ephemeral",
    [
        ("/tmp/repo_scan_bu37lxx7/coveo-search/dist/app.js", "dist/app.js", True),
        ("/tmp/repo_scan_a1/repo/a/b/c.py", "a/b/c.py", True),
        # Nothing below the clone directory: there is no in-repo path at all.
        ("/tmp/repo_scan_heu_4rk9/asrd-capability", None, True),
        # Already repo-relative, left alone.
        ("src/ipblocker/event.json", "src/ipblocker/event.json", False),
        (None, None, False),
    ],
)
def test_scan_clone_prefixes_are_stripped(stored, expected, ephemeral):
    assert repo_relative_path(stored) == (expected, ephemeral)


def test_a_bare_clone_directory_yields_no_path_rather_than_a_dead_one():
    """The defect this guards against.

    Returning the raw ``/tmp/repo_scan_.../repo`` string would put a path into a
    committed config file that names a directory deleted when the scan ended.
    """
    path, ephemeral = repo_relative_path("/tmp/repo_scan_xyz/some-repo")
    assert path is None
    assert ephemeral is True


def test_no_generated_rule_ever_contains_a_scan_clone_path():
    findings = [
        _Finding(scanner_name="retirejs", rule_id="DOMPurify", package_name="DOMPurify",
                 package_version="2.4.0", file_path="/tmp/repo_scan_a1/repo/dist/x.js"),
        _Finding(scanner_name="trivy-fs", rule_id="### Summary prose",
                 file_path="/tmp/repo_scan_a1/repo/package-lock.json"),
        _Finding(scanner_name="nuclei", rule_id="CAA Record",
                 file_path="/tmp/repo_scan_a1/repo"),
        _Finding(scanner_name="horusec", rule_id="Hard-coded password",
                 file_path="/tmp/repo_scan_a1/repo/README.md"),
    ]
    generators = [generate_retirejs_rule, generate_trivy_rule,
                  generate_nuclei_rule, generate_generic_rule]
    for finding, generate in zip(findings, generators):
        for scope in ("specific", "global"):
            rendered = generate(finding, scope)["rule_content"]
            assert "/tmp/repo_scan" not in rendered


# ---------------------------------------------------------------------------
# Grype -- the one scanner whose stored data supports a truly precise rule
# ---------------------------------------------------------------------------


def _grype():
    return _Finding(scanner_name="grype", rule_id="CVE-2002-2439",
                    file_path="bin/gcc", title="CVE-2002-2439")


def test_grype_specific_names_the_vulnerability_and_the_location():
    rule = generate_grype_rule(_grype(), "specific")
    assert "vulnerability: CVE-2002-2439" in rule["rule_content"]
    assert 'location: "bin/gcc"' in rule["rule_content"]


def test_grype_global_drops_the_location_and_says_so():
    rule = generate_grype_rule(_grype(), "global")
    assert "vulnerability: CVE-2002-2439" in rule["rule_content"]
    assert "location" not in rule["rule_content"]
    # The widening has to be stated, because it is invisible in the YAML.
    assert "everywhere" in rule["instruction"]


def test_grype_refuses_rather_than_emitting_a_rule_with_no_vulnerability():
    rule = generate_grype_rule(_Finding(scanner_name="grype", file_path="bin/gcc"), "specific")
    assert "ignore:" not in rule["rule_content"]
    assert "Cannot generate" in rule["instruction"]


# ---------------------------------------------------------------------------
# Retire.js -- keys on component, so the ephemeral path is irrelevant
# ---------------------------------------------------------------------------


def test_retirejs_emits_valid_json_keyed_on_component_and_version():
    finding = _Finding(scanner_name="retirejs", package_name="DOMPurify",
                       package_version="2.4.0", title="Vulnerable JS Library",
                       file_path="/tmp/repo_scan_a1/repo/dist/x.js")
    parsed = json.loads(generate_retirejs_rule(finding, "specific")["rule_content"])
    assert isinstance(parsed, list) and len(parsed) == 1
    assert parsed[0]["component"] == "DOMPurify"
    assert parsed[0]["version"] == "2.4.0"


def test_retirejs_without_a_version_says_it_covers_every_version():
    finding = _Finding(scanner_name="retirejs", package_name="DOMPurify")
    rule = generate_retirejs_rule(finding, "specific")
    assert "version" not in json.loads(rule["rule_content"])[0]
    assert "every version" in rule["instruction"]


# ---------------------------------------------------------------------------
# Trivy -- the ingest defect, reported rather than hidden
# ---------------------------------------------------------------------------


def test_trivy_prose_rule_id_falls_back_to_a_path_skip_and_names_the_reason():
    finding = _Finding(scanner_name="trivy-fs",
                       rule_id="### Summary\n`qs.stringify` throws TypeError",
                       file_path="package-lock.json")
    rule = generate_trivy_rule(finding, "specific")
    assert "skip-files" in rule["rule_content"]
    # The prose must not be emitted as though it were an advisory id.
    assert "### Summary" not in rule["rule_content"]
    assert "no advisory identifier is stored" in rule["instruction"]


def test_trivy_uses_trivyignore_when_a_real_advisory_id_is_present():
    finding = _Finding(scanner_name="trivy-fs", rule_id="CVE-2021-1234",
                       file_path="package-lock.json")
    rule = generate_trivy_rule(finding, "specific")
    assert "CVE-2021-1234" in rule["rule_content"]
    assert "skip-files" not in rule["rule_content"]


# ---------------------------------------------------------------------------
# Terrascan and Nuclei -- stored name is not the suppression key
# ---------------------------------------------------------------------------


def test_terrascan_warns_when_the_stored_value_is_a_check_name_not_a_rule_id():
    finding = _Finding(scanner_name="terrascan", rule_id="CpuRequestsCheck",
                       file_path="env/prod/app.yaml")
    rule = generate_terrascan_rule(finding, "global")
    assert "VERIFY BEFORE COMMITTING" in rule["rule_content"]
    assert "CpuRequestsCheck" in rule["rule_content"]


def test_terrascan_omits_the_warning_for_a_genuine_rule_id():
    # The control: a real id needs no verification, and a warning on every rule
    # is a warning nobody reads.
    finding = _Finding(scanner_name="terrascan", rule_id="AC_K8S_0064",
                       file_path="env/prod/app.yaml")
    rule = generate_terrascan_rule(finding, "global")
    assert "VERIFY BEFORE COMMITTING" not in rule["rule_content"]


def test_nuclei_slugifies_the_template_name_but_flags_it_as_unverified():
    finding = _Finding(scanner_name="nuclei", rule_id="CAA Record")
    rule = generate_nuclei_rule(finding, "global")
    assert "caa-record" in rule["rule_content"]
    assert "VERIFY BEFORE COMMITTING" in rule["rule_content"]


# ---------------------------------------------------------------------------
# Horusec -- where a misspelled key fails completely silently
# ---------------------------------------------------------------------------


def _horusec():
    return _Finding(scanner_name="horusec", rule_id="Potential Hard-coded credential",
                    file_path="src/ipblocker/event.json",
                    title="Possible vulnerability detected: AWS Manager ID")


def test_horusec_uses_the_key_name_that_actually_exists():
    """The defect this test exists for.

    Horusec ignores unrecognised configuration keys without complaint, so a
    config file using ``horusecCmsiFilesOrPathsToIgnore`` -- a plausible-looking
    name that appears in circulating documentation -- parses, commits, scans and
    suppresses nothing. The failure is invisible until the finding reappears.

    Verified against ZupIT/horusec's own horusec-config.json: the prefix on
    every key is ``horusecCli``.
    """
    parsed = json.loads(generate_horusec_rule(_horusec(), "specific")["rule_content"])

    assert "horusecCliFilesOrPathsToIgnore" in parsed
    # The misspellings that must never be emitted.
    assert "horusecCmsiFilesOrPathsToIgnore" not in parsed
    assert not any(key.startswith("horusecCmsi") for key in parsed)


def test_horusec_output_is_parseable_json():
    """horusec-config.json is strict JSON, which has no comment syntax.

    Every other generator here emits YAML or TOML, where a `#` caveat above the
    rule is legal. Putting one in this block would make the config file fail to
    parse for anyone who pasted it whole, so the caveats belong in the
    instruction instead.
    """
    for scope in ("specific", "global"):
        content = generate_horusec_rule(_horusec(), scope)["rule_content"]
        json.loads(content)  # raises if a comment crept back in
        assert "//" not in content
        assert not content.lstrip().startswith("#")


def test_horusec_specific_scope_names_the_exact_file():
    rule = generate_horusec_rule(_horusec(), "specific")
    patterns = json.loads(rule["rule_content"])["horusecCliFilesOrPathsToIgnore"]
    assert patterns == ["src/ipblocker/event.json"]


def test_horusec_global_scope_widens_to_a_glob_and_says_so():
    rule = generate_horusec_rule(_horusec(), "global")
    patterns = json.loads(rule["rule_content"])["horusecCliFilesOrPathsToIgnore"]
    assert patterns == ["**/event.json"]
    assert "every file named event.json" in rule["instruction"]


def test_horusec_states_that_it_silences_the_whole_file():
    # The rule is a path ignore, not a per-finding suppression. Leaving that
    # unsaid is how someone silences a file expecting to silence one finding.
    instruction = generate_horusec_rule(_horusec(), "specific")["instruction"]
    assert "not this one finding" in instruction
    assert "horusecCliFalsePositiveHashes" in instruction


# ---------------------------------------------------------------------------
# The fallback
# ---------------------------------------------------------------------------


def test_the_fallback_says_it_is_not_a_rule():
    """The defect this replaced.

    The previous fallback ended with "Add to your scanner's ignore/allowlist
    configuration", which reads as an instruction to paste inert comments into
    a config file.
    """
    finding = _Finding(scanner_name="horusec", rule_id="Hard-coded password",
                       file_path="src/x.py", title="Possible vulnerability")
    rule = generate_generic_rule(finding, "specific")
    assert rule["rule_type"] == "none"
    assert "NOT a rule" in rule["rule_content"]
    assert "suppresses nothing" in rule["rule_content"]
    assert "No rule was generated" in rule["instruction"]


def test_the_fallback_still_reports_the_finding_details_for_hand_writing():
    finding = _Finding(scanner_name="horusec", rule_id="Hard-coded password",
                       file_path="src/x.py", line_start=12, title="T")
    content = generate_generic_rule(finding, "specific")["rule_content"]
    assert "horusec" in content
    assert "src/x.py" in content
    assert "Hard-coded password" in content
    assert "12" in content
