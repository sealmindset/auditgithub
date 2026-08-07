# PoC shape proofs — read this before running any trigger

## What a shape proof is

Each file here takes one deployed rule and replaces only the malicious-specific predicate
with a benign marker, keeping the table, the joins, the `project` list and the entity
columns identical. If the PoC returns a row, the rule's plumbing works: the table is
populated, the columns exist and are non-empty, and the entity mapping has something to
map. If the PoC returns nothing, the rule would also have returned nothing against real
malware — and you have found that out without an incident.

This matters because the alternative is unfalsifiable. A rule that deploys cleanly and
reports zero looks the same whether it is working perfectly or reading an empty table.

## Safety

> **Do not run any trigger command on a machine anyone depends on.**
>
> Several triggers below are indistinguishable from the real thing as far as the rules are
> concerned. `poc/31` creates a file named `setup.mjs` and executes it with node — that is
> a literal match for `npm-shaihulud-loader-exec`, which ships **armed for selective
> isolation**. Running it on a developer workstation will isolate that workstation.
>
> Before running any trigger:
>
> 1. Use a dedicated, expendable, onboarded test device. Not a laptop in use, not a CI
>    runner.
> 2. Confirm the rules are not armed:
>    ```
>    python3 scripts/ioc/deploy_detection_rules.py --kill-switch-status
>    ```
>    Every rule you are about to trigger must show no automated action. If any is armed,
>    disarm first:
>    ```
>    python3 scripts/ioc/deploy_detection_rules.py --disarm --apply
>    ```
> 3. Prefer validating with **hunts** rather than triggers. Files `30`–`35` are written so
>    that the benign-marker query can be run against *existing* telemetry — most of them
>    need no trigger at all. Only run a trigger if the hunt returns nothing and you need
>    to distinguish "no such activity" from "table not populated".
> 4. Record what you did, where, and when. A synthetic trigger that is later found in a
>    backlog sweep and treated as a real infection wastes an IR cycle.

## Recommended order

| File | Proves |
|---|---|
| `30-payload-hash-shape.kql` | SHA-256 matching on `DeviceFileEvents` works; entity columns non-empty |
| `31-loader-exec-shape.kql` | Process + command-line matching works (**highest-risk trigger**) |
| `32-bun-from-node-shape.kql` | Parent/child process pairing is recorded at all |
| `33-agent-hook-drop-shape.kql` | `.vscode` / `.claude` path matching + `SHA1` for quarantine |
| `34-c2-contact-shape.kql` | `RemoteUrl` is populated for a node process — the big unknown |
| `35-exfil-artifacts-shape.kql` | Filename + initiating-process pairing on file writes |
| `36-alert-and-action-verification.kql` | The rules actually produced alerts, with evidence |

## Interpreting a failure

| PoC result | Meaning | Action |
|---|---|---|
| Rows, all entity columns populated | Rule plumbing is sound | Proceed to deploy/arm decision |
| Rows, but `DeviceId` empty on some | Entity mapping and every automated action break on those rows | Do not arm; investigate agent health on those devices |
| Rows, but `SHA1` empty (rule 13) | `stopAndQuarantineFiles` will no-op while still alerting | Keep detect-only on that platform |
| No rows, hunt variant | Table not populated for this activity on this platform | Fix telemetry before trusting any zero |
| No rows after a trigger | Rule cannot fire, full stop | Treat the rule as non-functional, not as coverage |
