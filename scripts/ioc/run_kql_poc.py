#!/usr/bin/env python3
"""
Run the Shai-Hulud KQL proof-of-concept library against Defender XDR advanced hunting.

    python3 scripts/ioc/run_kql_poc.py                      # lint + list, no credentials
    python3 scripts/ioc/run_kql_poc.py --run                # execute everything runnable
    python3 scripts/ioc/run_kql_poc.py --run --group coverage
    python3 scripts/ioc/run_kql_poc.py --run --file coverage/02-device-groups-for-scoping.kql
    python3 scripts/ioc/run_kql_poc.py --run --json exports/kql-poc-results.json

Two things this deliberately does NOT do.

1. It does not deploy anything and cannot arm a response action. Hunting is a read; the
   only permission it needs is ThreatHunting.Read.All, which the existing app registration
   already carries. Deployment lives in deploy_detection_rules.py, behind a separate
   permission the automation account does not yet have.

2. It does not run the parameterized IR queries by default. ir/50-53 carry placeholder
   device names and anchor timestamps; running them unedited would send a query for a
   device called "REPLACE-WITH-DEVICE-NAME" and report zero rows, which is worse than
   refusing, because zero rows reads as "nothing found". Pass --params to supply real
   values, or --include-parameterized to send them as-is anyway.

Every query is linted with the repo's own lint_kql() before it is sent. KQL cannot be
syntax-checked without a tenant, so the lint is not a correctness guarantee — it catches
the constructs that return plausible wrong answers rather than errors ($table,
`order by ... asc | take N`, missing time predicate, missing row limit).

Credentials
-----------
Reads GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET from the environment and hands
them to the read-only GraphClient in src/api/integrations/msgraph.py, which enforces the
POST allowlist, the 15-requests-per-minute hunting throttle and the role precheck.

Federated credentials are supported for rule DEPLOYMENT (deploy_detection_rules.py) but
not here: GraphClient takes a client secret. That is a deliberate limit rather than an
oversight — hunting is read-only and low-risk, and widening the read-only client to mint
tokens from assertions is a change to make when the tenant is federation-only, not
speculatively. Until then, run this locally with the existing hunting credential.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
KQL_ROOT = REPO_ROOT / "github_conf" / "detections" / "kql"
MSGRAPH_PATH = REPO_ROOT / "src" / "api" / "integrations" / "msgraph.py"

# Ordered so the output reads as an argument: prove coverage, then sweep the backlog, then
# the rules themselves, then that they fire, then the false-positive baseline, then IR.
GROUP_ORDER = ["coverage", "backlog", "detections", "poc", "baseline", "ir", "prevention"]

# Markers that mean "this file needs editing before it can return a meaningful result".
PLACEHOLDER_PATTERNS = [
    re.compile(r"REPLACE-WITH-[A-Z-]+"),
    re.compile(r"<paste the sha256 here>"),
]


# =============================================================================
# Load the repo's Graph client by path
# =============================================================================

def load_msgraph():
    """
    Import src/api/integrations/msgraph.py without importing the api package.

    Same approach deploy_detection_rules.py uses: the module only needs `requests` at
    import time, and going through `src.api` would drag in the FastAPI app and the
    database session for a script that needs neither.
    """
    if not MSGRAPH_PATH.exists():
        sys.exit(f"error: cannot find {MSGRAPH_PATH}")
    spec = importlib.util.spec_from_file_location("_msgraph_poc", MSGRAPH_PATH)
    if spec is None or spec.loader is None:
        sys.exit(f"error: cannot load {MSGRAPH_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["_msgraph_poc"] = module
    spec.loader.exec_module(module)
    return module


# =============================================================================
# Query discovery
# =============================================================================

class AzCliHuntingClient:
    """Run advanced hunting as the signed-in az CLI user, with no app registration.

    Exists because the app-only path asks someone to create an app registration, mint a
    secret, grant an application role and get admin consent - four steps, all of which
    were unnecessary. The Azure CLI's own first-party client already obtains a token that
    api.security.microsoft.com accepts; what is missing is a Defender XDR role on the
    account. Removing three of those four steps is the difference between an access
    request that lands this week and one that does not.

    Delegated, so every query is attributable to a named human in the tenant's audit log
    rather than to a shared service principal. For a read-only hunt that is the better
    default, not a compromise.
    """

    RESOURCE = "https://api.security.microsoft.com"
    ENDPOINT = f"{RESOURCE}/api/advancedhunting/run"

    def __init__(self) -> None:
        self._token: Optional[str] = None

    def _get_token(self) -> str:
        if self._token:
            return self._token
        import subprocess
        result = subprocess.run(
            ["az", "account", "get-access-token", "--resource", self.RESOURCE,
             "--query", "accessToken", "-o", "tsv"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "az CLI could not issue a token for the Defender API. Run `az login` "
                f"first. stderr: {result.stderr.strip()[:200]}")
        self._token = result.stdout.strip()
        return self._token

    def probe(self):
        """Confirm the tenant will answer before running the whole set.

        Returns (ok, detail). A permission failure here is reported verbatim from the API,
        because the API names the exact permissions it wants and a paraphrase of that is
        what produced an access request for the wrong role the first time round.
        """
        try:
            rows, error = self._post("DeviceInfo | project DeviceId | limit 1")
        except Exception as exc:  # noqa: BLE001 - the message is the useful artifact
            return False, str(exc)
        return (True, "ok") if error is None else (False, error)

    def _post(self, query: str):
        import urllib.error
        import urllib.request
        request = urllib.request.Request(
            self.ENDPOINT,
            data=json.dumps({"Query": query}).encode(),
            headers={"Authorization": f"Bearer {self._get_token()}",
                     "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return json.loads(response.read()).get("Results", []), None
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            try:
                message = json.loads(body).get("error", {}).get("message", body)
            except Exception:  # noqa: BLE001
                message = body
            return None, f"HTTP {exc.code}: {message[:400]}"

    def run_hunting_query(self, text: str, strict_lint: bool = True):
        rows, error = self._post(text)
        if error is not None:
            raise RuntimeError(error)
        # Shaped to match GraphClient's result object so the caller does not branch.
        return type("Result", (), {
            "rows": rows, "count": len(rows),
            # The Defender API caps a result set at 100k rows and does not flag it, so
            # a run that lands exactly on the cap is reported as truncated rather than
            # silently presented as the whole answer.
            "truncated": len(rows) >= 100000,
            "duration_ms": None, "warnings": [],
        })()


@dataclass
class Query:
    path: Path
    group: str
    rel: str
    text: str
    title: str
    placeholders: List[str] = field(default_factory=list)

    # populated by run()
    lint_warnings: List[str] = field(default_factory=list)
    lint_error: Optional[str] = None
    status: str = "pending"      # linted | skipped | ok | error
    row_count: Optional[int] = None
    verdicts: List[str] = field(default_factory=list)
    truncated: bool = False
    duration_ms: Optional[int] = None
    error: Optional[str] = None

    @property
    def parameterized(self) -> bool:
        return bool(self.placeholders)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.rel,
            "group": self.group,
            "title": self.title,
            "status": self.status,
            "parameterized": self.parameterized,
            "placeholders": self.placeholders,
            "lint_error": self.lint_error,
            "lint_warnings": self.lint_warnings,
            "row_count": self.row_count,
            "verdicts": self.verdicts,
            "truncated": self.truncated,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


def strip_comments(text: str) -> str:
    """
    Drop whole-line `//` comments.

    Used for placeholder detection only, NOT for linting. Several files document a Form B
    trigger in comments, including its placeholders; a placeholder inside a comment does
    not affect what Graph evaluates, so treating those files as parameterized would skip a
    perfectly runnable Form A query.

    Only full-line comments are removed. Stripping trailing comments would need to know
    which `//` are inside string literals, and getting that wrong silently changes the
    query — the exact class of failure this library exists to avoid. Linting deliberately
    still sees the literal text that gets sent, so it stays consistent with the check
    GraphClient re-runs on the way out.
    """
    return "\n".join(
        line for line in text.splitlines()
        if not line.lstrip().startswith("//")
    )


def find_placeholders(text: str) -> List[str]:
    body = strip_comments(text)
    return sorted({
        m.group(0)
        for pattern in PLACEHOLDER_PATTERNS
        for m in pattern.finditer(body)
    })


def first_title(text: str) -> str:
    """The `// NN — description` line each file opens with."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            body = stripped.lstrip("/").strip()
            if body:
                return body
        elif stripped:
            break
    return ""


def discover(root: Path = KQL_ROOT) -> List[Query]:
    if not root.exists():
        sys.exit(f"error: no KQL library at {root}")

    found: List[Query] = []
    for path in sorted(root.rglob("*.kql")):
        text = path.read_text()
        rel = path.relative_to(root).as_posix()
        group = rel.split("/")[0] if "/" in rel else "root"
        placeholders = find_placeholders(text)
        found.append(Query(
            path=path,
            group=group,
            rel=rel,
            text=text,
            title=first_title(text),
            placeholders=placeholders,
        ))

    def sort_key(q: Query):
        try:
            group_rank = GROUP_ORDER.index(q.group)
        except ValueError:
            group_rank = len(GROUP_ORDER)
        return (group_rank, q.rel)

    return sorted(found, key=sort_key)


def apply_params(text: str, params: Dict[str, str]) -> str:
    """
    Substitute placeholder values.

    --params device=WS-1234 replaces REPLACE-WITH-DEVICE-NAME. Matching is on the
    placeholder's own words so a typo in the key fails loudly instead of leaving the
    placeholder in place and querying for a device that does not exist.
    """
    for key, value in params.items():
        token = f"REPLACE-WITH-{key.upper().replace('_', '-')}"
        if token not in text:
            continue
        text = text.replace(token, value)
    return text


def unused_params(queries: List["Query"], params: Dict[str, str]) -> List[str]:
    """
    Report --params keys that matched no placeholder anywhere.

    Silently ignoring a typo'd key would leave the placeholder in place, and a query for a
    device named REPLACE-WITH-DEVICE-NAME returns zero rows — which reads as "device is
    clean" rather than "query never ran properly".
    """
    unused = []
    for key in params:
        token = f"REPLACE-WITH-{key.upper().replace('_', '-')}"
        if not any(token in q.text for q in queries):
            unused.append(key)
    return unused


# =============================================================================
# Reporting
# =============================================================================

def extract_verdicts(rows: List[Dict[str, Any]]) -> List[str]:
    """
    Pull the Verdict column the PoC shape proofs compute.

    Those queries end in a case() that reports PASS / WARN / FAIL, so the answer to
    "did this prove anything" is one string rather than a table the operator has to read.
    """
    out: List[str] = []
    for row in rows[:10]:
        for key, value in row.items():
            if key.lower() == "verdict" and value:
                out.append(str(value))
    return out


def print_plan(queries: List[Query], run: bool, include_param: bool) -> None:
    print(f"KQL proof-of-concept library: {KQL_ROOT.relative_to(REPO_ROOT)}")
    print(f"{len(queries)} quer{'y' if len(queries) == 1 else 'ies'} discovered\n")

    current_group = None
    for q in queries:
        if q.group != current_group:
            current_group = q.group
            print(f"  [{current_group}]")
        flag = ""
        if q.lint_error:
            flag = "  LINT FAIL"
        elif q.parameterized and not include_param:
            flag = "  needs --params" if run else "  parameterized"
        elif q.lint_warnings:
            flag = f"  {len(q.lint_warnings)} lint warning(s)"
        print(f"    {q.rel:<48}{flag}")
        for warning in q.lint_warnings:
            print(f"        warn: {warning}")
        if q.lint_error:
            print(f"        error: {q.lint_error}")
    print()


def print_result(q: Query) -> None:
    if q.status == "skipped":
        print(f"  SKIP  {q.rel}")
        print(f"        placeholders unresolved: {', '.join(q.placeholders)}")
        return
    if q.status == "error":
        print(f"  ERROR {q.rel}")
        print(f"        {q.error}")
        return

    rows = q.row_count if q.row_count is not None else 0
    trunc = "  (TRUNCATED at the advanced-hunting ceiling)" if q.truncated else ""
    print(f"  OK    {q.rel}  rows={rows}  {q.duration_ms}ms{trunc}")
    for verdict in q.verdicts:
        marker = "!!" if verdict.startswith(("FAIL", "WARN")) else "  "
        print(f"     {marker} {verdict}")
    if rows == 0 and not q.verdicts:
        print("        0 rows. Confirm coverage/01, 06 and 07 passed before reading this "
              "as a clean result.")


# =============================================================================
# Main
# =============================================================================

def write_json(path_str: str, queries: List[Query], tenant_id: Optional[str]) -> None:
    out_path = Path(path_str)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(
        {
            "library": str(KQL_ROOT.relative_to(REPO_ROOT)),
            # Prefix only. The full tenant id is not a secret, but there is no reason for a
            # results file to be the place it leaks from.
            "tenant_id_prefix": tenant_id[:8] if tenant_id else None,
            "executed": any(q.status in ("ok", "error") and q.row_count is not None
                            for q in queries),
            "queries": [q.to_dict() for q in queries],
        },
        indent=2,
    ) + "\n")
    print(f"\nWrote {out_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lint and run the Shai-Hulud KQL proof-of-concept library.",
    )
    parser.add_argument("--run", action="store_true",
                        help="execute the queries (default is lint and list only)")
    parser.add_argument("--group", action="append", choices=GROUP_ORDER,
                        help="restrict to one group; repeatable")
    parser.add_argument("--file", action="append", metavar="REL_PATH",
                        help="run one file by its path relative to the kql/ directory")
    parser.add_argument("--params", action="append", default=[], metavar="KEY=VALUE",
                        help="fill a placeholder, e.g. --params device=WS-1234 "
                             "(fills REPLACE-WITH-DEVICE-NAME)")
    parser.add_argument("--include-parameterized", action="store_true",
                        help="send parameterized queries with placeholders still in them. "
                             "They will return zero rows; only useful for syntax checking.")
    parser.add_argument("--az-cli", action="store_true",
                        help="Authenticate as the signed-in az CLI user (delegated) "
                             "instead of an app registration. Needs Defender XDR RBAC on "
                             "that account, not a client secret.")
    parser.add_argument("--json", metavar="PATH",
                        help="write the full result set as JSON")
    parser.add_argument("--no-strict-lint", action="store_true",
                        help="downgrade lint traps to warnings instead of refusing to send")
    args = parser.parse_args()

    params: Dict[str, str] = {}
    for item in args.params:
        if "=" not in item:
            parser.error(f"--params expects KEY=VALUE, got {item!r}")
        key, value = item.split("=", 1)
        params[key.strip()] = value.strip()

    msgraph = load_msgraph()

    queries = discover()
    if args.group:
        queries = [q for q in queries if q.group in set(args.group)]
    if args.file:
        wanted = {f.lstrip("./") for f in args.file}
        queries = [q for q in queries if q.rel in wanted]
        missing = wanted - {q.rel for q in queries}
        if missing:
            parser.error(f"no such query file(s): {', '.join(sorted(missing))}")
    if not queries:
        print("Nothing selected.")
        return 0

    stale = unused_params(queries, params)
    if stale:
        parser.error(
            "--params key(s) matched no placeholder in the selected queries: "
            + ", ".join(sorted(stale))
            + ". Known placeholders: "
            + ", ".join(sorted({p for q in queries for p in q.placeholders}) or ["none"])
        )

    # ---- lint everything first, before any credential is touched ----------------
    lint_failed = False
    for q in queries:
        text = apply_params(q.text, params) if params else q.text
        q.placeholders = find_placeholders(text)
        try:
            q.lint_warnings = msgraph.lint_kql(text, strict=not args.no_strict_lint)
            q.status = "linted"
        except msgraph.KqlLintError as exc:
            q.lint_error = str(exc)
            q.status = "error"
            q.error = f"lint: {exc}"
            lint_failed = True

    print_plan(queries, run=args.run, include_param=args.include_parameterised)

    if lint_failed:
        print("Lint failures above. Fix them before running: every construct the linter")
        print("rejects returns a plausible wrong answer rather than an error.")
        return 2

    if not args.run:
        print("Lint only. Add --run to execute against the tenant.")
        print()
        print("Two ways to authenticate:")
        print("  --az-cli   delegated, as the signed-in az CLI user. No app registration,")
        print("             no client secret. Needs Defender XDR RBAC on that account.")
        print("  (default)  app-only, via GRAPH_TENANT_ID / GRAPH_CLIENT_ID /")
        print("             GRAPH_CLIENT_SECRET.")
        print()
        print("Permissions, as reported by the API itself on 2026-08-07 rather than as")
        print("read off the documentation:")
        print("  graph.microsoft.com/v1.0/security/runHuntingQuery")
        print("      -> SecurityData.Read, TvmData.Read")
        print("  api.security.microsoft.com/api/advancedhunting/run")
        print("      -> SecurityData.Read, SecurityData.Hunting.Read")
        if args.json:
            write_json(args.json, queries, None)
        return 0

    # ---- credentials -----------------------------------------------------------
    # Delegated first, because it is the path that needs nothing created. The 403 this
    # script was written against turned out not to be a missing app registration at all:
    # an az CLI token is ACCEPTED by the hunting API, and the refusal is "user permissions:
    # ." - an empty Defender RBAC assignment on the signed-in account. That is a role
    # grant, not an onboarding project, and asking for the wrong one costs weeks.
    if args.az_cli:
        client = AzCliHuntingClient()
        ok, detail = client.probe()
        if not ok:
            print(f"error: {detail}", file=sys.stderr)
            print("       The token was obtained; the tenant refused the query. This is an",
                  file=sys.stderr)
            print("       RBAC assignment on the signed-in user, not a credential problem.",
                  file=sys.stderr)
            return 1
    else:
        tenant_id = os.environ.get("GRAPH_TENANT_ID")
        client_id = os.environ.get("GRAPH_CLIENT_ID")
        client_secret = os.environ.get("GRAPH_CLIENT_SECRET")
        if not (tenant_id and client_id and client_secret):
            print("error: --run needs GRAPH_TENANT_ID, GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET,",
                  file=sys.stderr)
            print("       or --az-cli to run as the signed-in az CLI user instead.",
                  file=sys.stderr)
            print("       Hunting is read-only; this is the existing hunting credential, not the",
                  file=sys.stderr)
            print("       detection-deployment identity.", file=sys.stderr)
            return 1

        client = msgraph.GraphClient(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            provenance={"source": "run_kql_poc.py"},
        )

    # Fail on a missing role rather than reporting zero rows for every query: an app-only
    # token without ThreatHunting.Read.All returns an empty result that is indistinguishable
    # from a clean estate.
    if not args.az_cli:
        try:
            client.require_role("runHuntingQuery")
        except Exception as exc:                  # GraphPermissionError, GraphError
            print(f"error: {exc}", file=sys.stderr)
            return 1

    print("Running. Advanced hunting is throttled to 15 requests/minute; the client")
    print("self-paces, so a full run takes a few minutes.\n")

    executed = 0
    failures = 0
    verdict_failures = 0

    for q in queries:
        text = apply_params(q.text, params) if params else q.text

        if q.parameterized and not args.include_parameterised:
            q.status = "skipped"
            print_result(q)
            continue

        try:
            result = client.run_hunting_query(text, strict_lint=not args.no_strict_lint)
            q.status = "ok"
            q.row_count = result.count
            q.truncated = result.truncated
            q.duration_ms = result.duration_ms
            q.verdicts = extract_verdicts(result.rows)
            for warning in result.warnings:
                if warning not in q.lint_warnings:
                    q.lint_warnings.append(warning)
            executed += 1
            if any(v.startswith("FAIL") for v in q.verdicts):
                verdict_failures += 1
        except Exception as exc:
            q.status = "error"
            # Column-name errors land here. That is the good failure mode: a wrong column
            # errors loudly instead of returning a wrong answer.
            q.error = f"{type(exc).__name__}: {exc}"
            failures += 1

        print_result(q)

    print()
    print(f"{executed} executed, {failures} errored, "
          f"{sum(1 for q in queries if q.status == 'skipped')} skipped")
    if verdict_failures:
        print(f"!! {verdict_failures} PoC shape proof(s) returned a FAIL verdict. Those rules")
        print("   cannot fire as deployed. Do not record them as coverage, and do not arm them.")

    if args.json:
        write_json(args.json, queries, tenant_id)

    if failures:
        return 1
    if verdict_failures:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
