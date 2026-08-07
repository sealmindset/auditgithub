# KQL proof-of-concept library — Shai-Hulud npm worm

Every query needed to **prove** the Layer 2 detection design works in this tenant, in the
order you would actually run them. All of them run today with the already-granted
`ThreatHunting.Read.All` — none needs `CustomDetection.ReadWrite.All`.

Run one at a time in `security.microsoft.com → Hunting → Advanced hunting`, or run the
whole library:

```bash
python3 scripts/ioc/run_kql_poc.py                    # list what would run
python3 scripts/ioc/run_kql_poc.py --run              # execute, print row counts
python3 scripts/ioc/run_kql_poc.py --run --group coverage
python3 scripts/ioc/run_kql_poc.py --run --json exports/kql-poc-results.json
```

## Why this exists

A detection rule that deploys cleanly and returns nothing looks identical to a clean
estate. Three of the six rules depend on telemetry that may not be populated here at all
(`RemoteUrl` needs Network Protection; `SHA1` is not always present outside Windows), and
two of the automated actions silently no-op if their target column is empty.

So the order below is deliberate: **prove the telemetry exists before believing any zero,
and prove the action has a target before arming it.**

## Order of operations

### 1. `coverage/` — run first, always

Establishes what the estate can actually see. Interpret nothing until these pass.

| File | Question it answers |
|---|---|
| `01-defender-onboarding-coverage.kql` | How many devices report, by platform and onboarding state |
| `02-device-groups-for-scoping.kql` | **Which device groups exist** — the input to `--scope` |
| `03-ci-runner-identification.kql` | Which group the self-hosted runners are in (§7 Decision 1) |
| `04-network-protection-config.kql` | Is Network Protection *configured* — prerequisite for rule 14 |
| `05-network-protection-live-events.kql` | Is Network Protection *actually firing* |
| `06-dev-toolchain-visibility.kql` | Can we see node/npm/bun at all, per platform |
| `07-file-hash-column-coverage.kql` | **Is `SHA1` populated** — if not, `stopAndQuarantineFiles` no-ops |

### 2. `backlog/` — run second

Custom detections are **not retroactive**. They evaluate from their first scheduled run
forward, so anything already on disk is invisible to them. This is the only pass that
covers the existing 30-day window.

| File | Purpose |
|---|---|
| `20-backlog-sweep-all-signals.kql` | All six detection signals, 30 days, one result set |
| `21-adjacent-package-hosts.kql` | Which *devices* hold the affected package trees on disk — the endpoint-level view of the 81 repos Layer 1 flagged as adjacent. Exposure surface, not compromise. |

Run `20` **before** deploying the rules. Once a rule is armed, a three-week-old artifact
can isolate a machine that has been clean for weeks.

### 3. `detections/` — the six rules, verbatim

Identical KQL to `../npm_supply_chain_rules.json`, one file each, with the 30-day backlog
variant in a comment. Run each as a hunt before deploying it as a rule: a rule whose query
errors fails at create time, but a rule whose query is *valid and wrong* deploys fine.

### 4. `poc/` — prove each rule fires

Shape proofs. Each one substitutes a benign marker for the malicious predicate, so the
table, columns and entity mappings are exercised **without malware and without triggering
containment**.

> **Run these only while the corresponding rule is unarmed or disabled.** Several of the
> synthetic triggers below match live rules. `poc/31` creates a file literally named
> `setup.mjs` and runs it under node — if `npm-shaihulud-loader-exec` is armed, that
> isolates the device. Use a dedicated expendable test device.

### 5. `baseline/` — false-positive rates before arming

`40` is the gate on arming `npm-shaihulud-bun-from-node`, the only medium-confidence rule
in the set. If it returns hits from a team that legitimately drives Bun from node, scope
the rule rather than deleting it.

### 6. `ir/` — after something fires

Device timeline, credential-exposure scoping, persistence sweep, spread check.

`50` and `51` carry a `REPLACE-WITH-DEVICE-NAME` placeholder, and the runner **refuses to
send them** without `--params device=<name>`. A query for a device by that literal name
returns zero rows, and zero rows reads as "the device is clean".

```bash
python3 scripts/ioc/run_kql_poc.py --run --group ir --params device=WS-1234
```

`51` is ordered deliberately: rotate credentials **before** eradicating. Reimaging does not
invalidate a token the worm already exfiltrated, and it destroys the evidence of which
tokens were exposed.

### 7. `prevention/` — after Layer 3 indicators are published

Proves the indicator blocks are firing rather than merely existing.

## Conventions

Every query in this directory:

- states its window explicitly with `ago()` — advanced hunting retains 30 days, and a
  query with no time predicate implies coverage it does not have;
- carries an explicit `limit`, `top` or `summarize`, because advanced hunting truncates
  silently at 100,000 rows;
- avoids `$table` (not available via Graph — use `union withsource=`) and
  `order by ... asc | take N` (keeps the oldest rows, discarding the recent tail).

Those three are enforced by `lint_kql` in `src/api/integrations/msgraph.py`, which
`run_kql_poc.py` applies before sending anything.

## Honest limits

- **Not syntax-checked against a live tenant.** These are linted for the traps above and
  reviewed against the Microsoft table schemas, but no query here has been executed —
  there are no hunting credentials in this environment. Expect to fix a column name or
  two on first run; a wrong column name errors loudly rather than returning a wrong
  answer, which is the failure mode that matters.
- **`DeviceTvmSecureConfigurationAssessment` coverage is strongest on Windows.** A missing
  row for a macOS or Linux device means "not assessed", not "not compliant".
- **Automated action outcomes are not in advanced hunting.** Isolation and quarantine
  results live in the Action center and `POST /api/machineactions`. `poc/36` discovers
  what the `DeviceEvents` ActionType vocabulary actually contains in this tenant rather
  than asserting names that may not exist.
