# npm supply-chain IDS/IPS — Microsoft Graph + Defender XDR

Detection and prevention for npm worm campaigns, built against **Shai-Hulud: Here We Go
Again** (2026-08-04, [JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)), also
tracked as **CHAINDROP** ([Elastic](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain),
[StepSecurity](https://www.stepsecurity.io/blog/chaindrop-npm-worm)).

| Artefact | Path |
|---|---|
| IOC bundle | `github_conf/ioc/shai_hulud_2026_08.json` |
| Source file — Elastic Security Labs | `github_conf/ioc/chaindrop_elastic_2026_08.json` |
| Source file — StepSecurity | `github_conf/ioc/chaindrop_stepsecurity_2026_08.json` |
| Source arbitration (which claim won, and why) | `docs/playbooks/supply-chain-hunt-ttp.md` §1.1–§1.3 |
| Malicious package@version list (443 pkgs / 2235 pairs) | `github_conf/ioc/keyv-packages-wiz.csv` |
| Layer 1 — inventory matcher | `scripts/ioc/match_npm_ioc.py` |
| Layer 2 — detection rules as code | `github_conf/detections/npm_supply_chain_rules.json` |
| Layer 2 — deployer | `scripts/ioc/deploy_detection_rules.py` |
| Layer 2 — deploy workflow (two-person control) | `.github/workflows/deploy-detection-rules.yml` |
| Layer 2 — proof-of-concept KQL library (30 queries) | `github_conf/detections/kql/` |
| Layer 2 — PoC lint/run harness | `scripts/ioc/run_kql_poc.py` |
| Prior hunt (this campaign, clean) | `exports/graph-hunt-mini-shai-hulud-RESULTS.md` |
| **Tenant rollout / Global Admin approval packet** | `docs/playbooks/npm-supply-chain-rollout-handover.md` |

---

## 1. The requested design, and where it breaks

The ask was: **trigger when npm is used → inspect what packages it is getting → compare
to a blacklist → alert.** That is the right shape. Three things about it do not survive
contact with the telemetry, and each one is a silent-failure mode rather than an error —
you would get a working-looking rule that reports clean forever.

**a) "Trigger when npm is used" misses the actual vector.**
`npm >= 12` does not run `preinstall` lifecycle hooks by default, so on current npm the
primary chain never fires. Those environments stay exposed through the *secondary* chain:
an autostart hook dropped in `.vscode/tasks.json` or `.claude/settings.json` that executes
on repo open — **with no npm process anywhere**. A trigger keyed on npm execution is blind
to it. Rule `npm-shaihulud-agent-hook-drop` exists specifically for that path.

**b) "Inspect what packages it is getting" is not visible to EDR.**
`DeviceProcessEvents` records what the developer typed (`npm ci`), not what npm resolved.
`node_modules` paths carry a package name with no version. The resolved `name@version` pair
exists in exactly two places: **lockfiles** and **registry logs**. The one endpoint signal
that carries a version is the registry URL path (`<pkg>/-/<pkg>-<version>.tgz`), and that
requires Network Protection to populate `RemoteUrl` — see `hunting_queries` in the rules
file, kept as a hunt rather than a rule for that reason.

**c) "Compare to a blacklist" only works with versions attached.**
`keyv`, `cacheable`, `cacheable-request`, `flat-cache` and `file-entry-cache` are among the
most-installed packages on npm. Name-only matching alerts on every normal install in the
org. Confirmed against our own inventory: **81 repos** carry these packages legitimately.
Only `name@version` is actionable.

So the honest architecture splits the request across three layers, each doing the part it
can actually do.

---

## 2. Architecture

```
Layer 1  VERSION-PRECISE MATCHING          where versions exist
         lockfiles -> dependencies table -> 2235 name@version IOC pairs
         scripts/ioc/match_npm_ioc.py                        [IDS, authoritative]

Layer 2  BEHAVIOUR + HASH DETECTION        where versions do not exist
         Defender XDR custom detection rules over Device* tables
         + armed kill switch: isolate / quarantine / collect
         github_conf/detections/npm_supply_chain_rules.json   [IDS + auto-containment]

Layer 3  PREVENTION                        stop execution, not just observe it
         MDE indicator blocks + ignore-scripts + registry allowlist
                                                             [IPS]
```

Layer 1 answers *"are we running a malicious version"*. Layer 2 answers *"did a payload
execute"* and is version-independent, which matters because the worm republishes
continuously with incremented patch versions — every version list is stale on arrival.
Neither layer subsumes the other.

---

## 3. Layer 1 — version-precise matching (working, current result)

```bash
docker compose --profile scan run --rm --entrypoint python \
  -e POSTGRES_DB=security_portal scanner \
  scripts/ioc/match_npm_ioc.py --target sleepnumberinc \
  --report exports/reports/ioc-match-shai-hulud.md \
  --json exports/ioc-match-shai-hulud.json
```

Exit `0` = no exact match, `2` = exact match (wire this into CI), `1` = error.

**Current result (2026-08-05):** 0 exact matches over 46,231 dependency rows / 467 repos
(36,697 npm rows, 36,634 version-pinned). All npm versions in the inventory are exact
pins, so string comparison is sound — there is no semver-range blind spot.

Adjacent blast radius — IOC packages present at *non-malicious* versions. **Not findings.**
These are the repos an unpinned upgrade would walk into:

| Package | Repos | Versions present | Malicious version |
|---|---|---|---|
| `keyv` | 77 | 4.0.3, 4.3.0, 4.5.2, 4.5.3, 4.5.4 | 6.0.0 |
| `cacheable-request` | 76 | 7.0.2, 7.0.4, 12.0.1 | 13.0.20 |
| `file-entry-cache` | 12 | 5.0.1, 6.0.1, 8.0.0 | 11.1.6 |
| `flat-cache` | 12 | 2.0.1, 3.0.4, 3.2.0, 4.0.1 | 6.1.24 |

**What that zero is and is not.** It is only as current as (i) the IOC list — the worm
republishes constantly, re-pull before relying on it — and (ii) the last scan of each repo.
A lockfile changed after its scan is not represented.

Scan backing it: full force-rescan of `sleepnumberinc` completed 2026-08-05 00:13 CDT,
exit 0, **1,890 repos processed with 6 timeouts** (`vulnerability_reports/stuck_repos_summary.md`:
`android-keyattestation-vendored`, `Cold-Fusion-Sales-Portal`, `CXDEVOPS-OPENUIFILE`,
`EBS-7019_OIC_FINAL_LIVECHAT`, `EBS-7009-XLA_DATA_FIX`, `EBS-7018_APEX_STORE_BANK_MAPPING`
— all hit the 15-minute scanner cap). Those 6 are unmeasured, not clean. The 467-repo
figure above is the subset that actually declares npm dependencies.

---

## 4. Layer 2 — Defender custom detection rules

### 4.1 The rules

Nine rules, all version-independent. None of them mentions a package name.

| Rule id | Signal | Severity | Status |
|---|---|---|---|
| `npm-shaihulud-payload-hash` | SHA-256 of any of 7 published payload/loader/hook artefacts on disk | high | deployed |
| `npm-shaihulud-loader-exec` | node/bun executing `setup.mjs`, `math_init.js`, `Math_Symbol.js` | high | deployed |
| `npm-shaihulud-bun-from-node` | Bun spawned **by node or npm** — the loader fetches Bun 1.3.13 to run outside the project's Node runtime | medium | deployed, **unarmed** |
| `npm-shaihulud-agent-hook-drop` | loader or known-bad hook config written into `.claude/` or `.vscode/` — **the npm-12 path** | high | deployed |
| `npm-shaihulud-c2-contact` | dev-toolchain process reaching C2 domains or the Ethereum RPC providers | high | deployed |
| `npm-shaihulud-exfil-artifacts` | node/bun writing `format-results.txt` or `codeql_analysis.yml` | high | deployed |
| `npm-shaihulud-token-monitor` | token-revocation watchdog dropped — `gh-token-monitor` script, config dir, systemd unit or launchd label | high | **new 2026-08-06, not deployed** |
| `npm-shaihulud-bun-fetch` | dev-toolchain process fetching a Bun 1.3.13 release asset from the GitHub release CDN | medium | **new 2026-08-06, not deployed** |
| `npm-shaihulud-runner-mem-scrape` | `python3` under `sudo` reading `/proc/<pid>/mem` from a runner work directory | high | **new 2026-08-06, not deployed** |

The Ethereum RPC providers matter more than the C2 domains: the payload resolves its live
C2 address from an on-chain read (contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103`,
selector `0x53ed5143`), so taking down one domain does not sever control. The RPC providers
are the chokepoint — but StepSecurity puts the fallback list at **75 endpoints tried in
sequence**, so the three domains we hold are a telemetry source, not a chokepoint either.
That is what `npm-shaihulud-bun-fetch` is for: see below.

**The three new rules, and why each earns its place.** Rule text is in
`github_conf/detections/npm_supply_chain_rules.json`; all three ship **unarmed** and none has
been deployed or tenant-verified.

* **`npm-shaihulud-token-monitor`** — the watchdog (`~/.local/bin/gh-token-monitor.sh`,
  `~/.config/gh-token-monitor/`, `gh-token-monitor.service`, `com.user.gh-token-monitor`)
  polls `api.github.com/user` every 60 s for 24 h and **fires the payload when the token stops
  authenticating**. It is the *only* artefact that survives deleting `setup.mjs`,
  `math_init.js`, `.claude/` and `.vscode/` — so without this rule a host cleaned by §7 step 3
  reads as eradicated while still armed. `DeviceFileEvents` on those four names is a narrow,
  low-noise match: nothing legitimate ships a file called `gh-token-monitor.sh`.
* **`npm-shaihulud-bun-fetch`** — the dropper carries no payload. It fetches Bun from
  `github.com/oven-sh/bun/releases/download/bun-v1.3.13/` and stage 2 only runs under Bun.
  One origin, no on-chain indirection, and it happens **before any credential is read** — the
  earliest network detection in the chain, and earlier than `npm-shaihulud-c2-contact` by the
  whole collection phase. Caveat, and it is the same one as rule 5: it matches on `RemoteUrl`,
  so **it is dead without Network Protection**. Shipped `medium` and unarmed because a
  developer legitimately installing Bun matches it; the discriminator is the *initiating
  process* being node/npm, not a shell.
* **`npm-shaihulud-runner-mem-scrape`** — a `sudo python3` helper reads
  `/proc/<Runner.Worker pid>/mem` and greps `"isSecret":true`, which takes **every secret the
  runner handled in that job**, not only those the compromised step referenced. No file is
  written and no network connection is made, so this is invisible to rules 1, 5 and 6.
  **Scope it to the six self-hosted runners** — GitHub-hosted runners have no agent, and on a
  developer workstation `python3` reading `/proc` has benign explanations that do not exist on
  a build agent. Deploy with `--scope` on the CI device group, not tenant-wide.

### 4.2 API facts, including the ones that cost time

* Endpoint: `POST https://graph.microsoft.com/beta/security/rules/detectionRules`.
* **beta only.** There is no v1.0 path as of 2026-08-05, and the Graph SDKs default to
  v1.0 — SDK examples silently target a path that 404s unless you opt into beta.
* **Global cloud only.** Not available in US Gov L4/L5 or 21Vianet.
* `id` is **client-provided and required**, which makes deployment idempotent: re-applying
  the same file PATCHes in place rather than creating duplicates.
* Use `status` (`enabled`/`disabled`), **not** `isEnabled`. Use `schedule.frequency` (ISO-8601
  duration), **not** `schedule.period`. `isEnabled`, `detectorId`, `lastRunDetails`,
  `schedule.period` and `schedule.nextRunDateTime` are all **removed 2026-10-01**. Every
  blog example still shows the old shape.
* `frequency` is documented only as "ISO-8601 duration" with no enum. The accepted set maps
  from the deprecated `period` values: `PT0S` (continuous), `PT1H`, `PT3H`, `PT12H`, `P1D`.
* The query must return `Timestamp` and `ReportId`, **plus every column named by an
  `entityMappings` entry**. A mapping pointing at an unprojected column fails at create
  time with an unhelpful 400 — the deployer checks this locally first.
* MITRE mapping goes in `detectionAction.alertTemplate.tactics[]` with nested
  `techniques[]`, not a flat `mitreTechniques` list.
* Custom detections are **not retroactive**. They evaluate from first scheduled run
  forward. Cover the 30-day backlog once with the hunting queries.

### 4.3 Permission — not yet granted

`CustomDetection.ReadWrite.All` (application), admin consent required.

Currently granted on app `ca38f5b8` ("Microsoft Graph - RobV"): `ThreatHunting.Read.All`,
`SecurityAlert.Read.All`, `SecurityIncident.Read.All`. **`CustomDetection.ReadWrite.All` is
absent**, so `--apply` will exit 3 without sending anything.

For delegated use instead, the signed-in account needs Defender XDR Unified RBAC
**Detection tuning (Manage)**, or the Entra **Security Administrator** role.

### 4.4 Deploying

```bash
# 1. Validate. Default mode — nothing leaves the machine.
python3 scripts/ioc/deploy_detection_rules.py

# 2. Inspect the exact JSON that would be POSTed.
python3 scripts/ioc/deploy_detection_rules.py --show npm-shaihulud-c2-contact

# 3. Credentials (app-only). Federation first; the secret is a warned-about fallback.
export GRAPH_TENANT_ID=<tenant id>
export GRAPH_CLIENT_ID=<svc-defender-detection-as-code app id>
#    In CI, nothing else is needed: GitHub Actions OIDC is detected automatically from
#    ACTIONS_ID_TOKEN_REQUEST_URL when the job declares `permissions: id-token: write`.
#    Other options, in precedence order: AZURE_FEDERATED_TOKEN_FILE, GRAPH_CLIENT_ASSERTION,
#    then GRAPH_CLIENT_SECRET (works, warns).

# 4. Stage disabled first, review in the portal, then enable.
python3 scripts/ioc/deploy_detection_rules.py --apply --status disabled
python3 scripts/ioc/deploy_detection_rules.py --list
python3 scripts/ioc/deploy_detection_rules.py --apply          # status from the file

# One rule at a time while tuning:
python3 scripts/ioc/deploy_detection_rules.py --apply --only npm-shaihulud-bun-from-node
```

Prefer the workflow — `.github/workflows/deploy-detection-rules.yml`, `workflow_dispatch`
only, gated on the protected `defender-prod` environment. Deploying through it means no
credential ever exists on a workstation and a second person approves every tenant change.

The deployer validates before any network call and fails all-or-nothing: it checks the
token's `roles` claim up front so a missing permission cannot leave half the rules
deployed. Verified locally — a rule with a mistyped entity-mapping column, a missing
`ReportId`, `isEnabled`, and `schedule.period` produces 6 errors and exit 4 with nothing
sent.

**`npm-shaihulud-bun-from-node` is the one rule to baseline before enabling.** If a team
here legitimately drives Bun from node scripts, scope the rule to exclude their devices
rather than deleting it.

### 4.6 Kill switch — automated response

Auto-containment is enabled and armed on 5 of the 9 rules — the original six less
`bun-from-node`, plus none of the three added on 2026-08-06. The trade is deliberate: this
campaign exfiltrates credentials **before** it does anything else and republishes from the
stolen tokens within hours, so the window where human triage helps is shorter than the
window where it spreads. An isolated developer is a recoverable cost; a leaked npm publish
token that reaches the org's 467 npm repos is not.

**Two keys, both required.** Neither alone does anything:

| Key | Where | Purpose |
|---|---|---|
| 1 | `killSwitch.armed: true` in the rules file | reviewed in a PR, attributable in git |
| 2 | `--arm` on the deploy command | deliberate operator intent, typed `ARM` confirmation, audit record |

A plain `--apply` strips `automatedActions` and reports that it did.

| Rule | Tier | Actions | Armed |
|---|---|---|---|
| `npm-shaihulud-payload-hash` | isolate-full | isolate (full) + quarantine file + forensic package | ✅ |
| `npm-shaihulud-c2-contact` | isolate-full | isolate (full) + forensic package | ✅ |
| `npm-shaihulud-loader-exec` | isolate-selective | isolate (selective) + forensic package + AV scan | ✅ |
| `npm-shaihulud-exfil-artifacts` | isolate-selective | isolate (selective) + quarantine file + forensic package | ✅ |
| `npm-shaihulud-agent-hook-drop` | quarantine-only | quarantine file + forensic package + AV scan | ✅ |
| `npm-shaihulud-bun-from-node` | isolate-selective | isolate (selective) + forensic package | ❌ `requiresForce` |

Three judgment calls behind that table:

* **`selective` where the responder needs the human.** Selective isolation still severs
  git, npm and registry access — there is no isolation mode that keeps a build working. It
  only preserves Outlook/Teams/Skype so you can reach the developer whose tokens are being
  rotated. Full isolation is reserved for the two rules that cannot fire benignly.
* **No file quarantine on process-event rules.** `stopAndQuarantineFiles` acts on the file
  the query returns. On `DeviceProcessEvents` that file is `node.exe` or `bun.exe`, so
  quarantining it bricks the toolchain and leaves the payload — a script — untouched. File
  actions attach only to file-event rules, where the returned hash *is* the artefact.
* **`bun-from-node` ships unarmed.** It is the one medium-confidence rule; isolating a
  developer whose toolchain legitimately spawns Bun is the false positive that gets
  automated response switched off org-wide. Its actions are defined and validated, waiting
  on a baseline. Note `--force` does **not** override `armed: false` — that would collapse
  the two-key control into one.

The deployer refuses to arm a disruptive action on a non-`high`-severity rule unless the
rule is explicitly marked `requiresForce`, and it rejects any action whose target column
the query does not project — an action pointing at a missing column deploys cleanly, fires,
and does nothing, which is invisible in the portal.

Only six action types are accepted: `isolateDevices`, `restrictAppExecutions`,
`stopAndQuarantineFiles`, `collectInvestigationPackages`, `initiateInvestigations`,
`runAntivirusScans`. `automatedActionSet` also exposes `blockFiles`, `disableUsers`,
`forceUserPasswordResets`, `markUsersAsCompromised` and six email actions, but their nested
column-property names are unverified here, so the deployer rejects them rather than guessing
a payload shape. Verify the resource doc, then extend `AUTOMATED_ACTIONS`.

```bash
# See exactly what arming would do — still sends nothing.
python3 scripts/ioc/deploy_detection_rules.py --arm

# Arm a pilot device group. Prints the blast radius, then requires you to type ARM.
python3 scripts/ioc/deploy_detection_rules.py --apply --arm --scope "Dev Workstations"

# Tenant-wide, after the pilot runs clean.
python3 scripts/ioc/deploy_detection_rules.py --apply --arm --scope-all-devices

# Truth from the tenant, not from the file. Reports actions AND scope.
python3 scripts/ioc/deploy_detection_rules.py --kill-switch-status

# EMERGENCY ROLLBACK. No confirmation — it only ever reduces capability.
python3 scripts/ioc/deploy_detection_rules.py --disarm --apply
```

**Scope is half the blast radius.** An unscoped armed rule reaches every onboarded device,
including the six self-hosted runners `cxdkrprdapp12–17.comfort.com` — which run package
installs constantly and are exactly what this worm targets. Isolating one stops builds
org-wide. `--scope` emits `detectionAction.organizationalScope`
(`{"scopeType": "deviceGroup", "scopeNames": [...]}`), and the confirmation prompt names
every armed disruptive rule that carries no scope before it accepts `ARM`.

Scope narrows implicitly and widens explicitly: omitting `--scope` on a re-apply leaves the
deployed scope alone, because PATCH does not clear an omitted complex property, so a piloted
rule cannot silently go tenant-wide. `--scope-all-devices` sends `null` to widen deliberately.
Graph accepts a device-group name matching nothing, and the rule then matches nothing — read
the names the deployer echoes back against the portal's device groups.

Every arm and disarm appends an attributable record to `exports/kill-switch-audit.jsonl`
(timestamp, actor, tenant, credential kind, rules, scope, whether forced, whether unattended).

**Releasing an isolated device is manual and out of band** — nothing here un-isolates.
Use the Defender portal, or `POST /api/machines/{id}/unisolate` on
`api.securitycenter.microsoft.com` (`Machine.Isolate` scope). Rotate credentials and
confirm eradication *first*: a device released with the loader still on disk re-isolates on
the next hourly run.

Two caveats about `--disarm`: PATCH semantics on a complex property are not documented
clearly enough to assume that clearing works, so it sends `automatedActions: null`
explicitly and tells you to verify with `--kill-switch-status`. And disarming stops
*future* actions only — it does not release devices already isolated.

### 4.7 Proof of concept — proving the rules can fire before believing they work

`github_conf/detections/kql/` holds 30 query files and `scripts/ioc/run_kql_poc.py` lints
and runs them. Everything in it is a read against `ThreatHunting.Read.All`, which is
already granted, so none of it waits on the permission request in §4.3.

```bash
python3 scripts/ioc/run_kql_poc.py                  # lint all 30, no tenant contact
python3 scripts/ioc/run_kql_poc.py --run --group coverage
```

The problem this solves is that **a rule returning zero is indistinguishable from a clean
estate**, and four of the nine rules depend on telemetry that may not be populated here
(`c2-contact` and the new `bun-fetch` need `RemoteUrl`; `token-monitor`'s quarantine needs
`SHA1`; `runner-mem-scrape` needs the CI device group to exist and be named correctly):

| Group | Purpose |
|---|---|
| `coverage/` (7) | onboarding by platform · **device-group names for `--scope`** · CI-runner group · Network Protection configured and firing · is node/npm visible · **is `SHA1` populated** |
| `backlog/` (2) | the original six signals over the full 30-day window · devices holding the adjacent package trees |
| `detections/` (6) | six of the nine rule queries, verbatim, each with its backlog variant |
| `poc/` (7) | one shape proof per *original* rule, returning a computed `PASS`/`WARN`/`FAIL` · alert and entity verification |
| `baseline/` (3) | **arming gate for `bun-from-node`** · the two hunting queries from the rules file |
| `ir/` (4) | timeline · credential-rotation scope · persistence sweep · spread check |
| `prevention/` (1) | are the Layer 3 indicator blocks firing, or merely existing |

A *shape proof* takes one rule and replaces only the malicious-specific predicate with a
benign marker, keeping the table, joins, `project` list and entity columns identical. If it
returns a fully populated row, the rule's plumbing works. If it returns nothing, the rule
would also have returned nothing against real malware — established without an incident.
Most need no trigger at all; they read existing telemetry.

**The library has not been extended to the three rules added on 2026-08-06.** There is no
`detections/`, `backlog/` or `poc/` file for `token-monitor`, `bun-fetch` or
`runner-mem-scrape`, so for those three the 30-day history is unexamined rather than clean,
and their plumbing is unproven in exactly the way this library exists to prevent. Do not
report them as coverage until their shape proofs exist and pass.

Two findings the library is built to surface, because both fail silently:

* **`stopAndQuarantineFiles` needs a populated `SHA1`.** If it is empty on the matched rows,
  `npm-shaihulud-agent-hook-drop` alerts and does *not* quarantine — which reads as handled.
  `coverage/07` measures it per platform; `poc/33` checks it on the exact rows the rule
  matches.
* **`npm-shaihulud-c2-contact` may be dead on arrival.** `poc/34` asks the only question
  that matters: does a node process's outbound connection arrive with `RemoteUrl` attached?
  It reports `FAIL - RULE 14 IS DEAD HERE` when it does not.

Runner controls worth knowing: every query is linted with this repo's own `lint_kql()`
before any credential is touched (all 30 pass clean); `require_role("runHuntingQuery")` runs
before the first query so a missing role fails loudly instead of returning zero rows; the
four `ir/` queries are **refused** unless `--params device=<name>` replaces their
placeholders, because a query for a device named `REPLACE-WITH-DEVICE-NAME` returns zero
rows and reads as "clean"; exit `3` means at least one shape proof returned `FAIL`.

No query in the library has been executed — there are no hunting credentials in this
environment. They are linted and schema-reviewed, not tenant-verified. A wrong column name
errors loudly rather than returning a wrong answer, which is why that is an acceptable
place to stop.

### 4.5 Why the deployer is a separate client

`src/api/integrations/msgraph.py` is read-only by construction: its `_POST_ALLOWLIST`
permits exactly one POST (`runHuntingQuery`) and `_request()` refuses everything else.
That guard is load-bearing — the whole platform imports that client. Widening it to allow
rule creation would grant write capability to every caller in the codebase. The deployer
therefore carries its own client with a one-path allowlist (`/security/rules/detectionRules`)
and reuses only the pure validation helper `lint_kql`.

---

## 5. Layer 3 — prevention (the "IPS" half)

### 5.1 `tiIndicators` is dead — use the MDE Indicators API

Graph's `security/tiIndicators` is deprecated with removal by April 2026. It is gone. IOC
blocking now goes through Microsoft Defender for Endpoint directly:

```
POST https://api.securitycenter.microsoft.com/api/indicators
Permission: Ti.ReadWrite.All (application) / Ti.ReadWrite (delegated)
Limit:      15,000 active indicators per tenant
```

```json
{
  "indicatorValue": "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc",
  "indicatorType": "FileSha256",
  "action": "BlockAndRemediate",
  "title": "Shai-Hulud npm worm payload (Aug 2026)",
  "severity": "High",
  "description": "math_init.js payload. JFrog research 2026-08-04.",
  "generateAlert": true
}
```

Recommended actions per indicator class — the distinction is not cosmetic:

| Indicator | Type | Action | Why |
|---|---|---|---|
| 7 payload SHA-256 hashes | `FileSha256` | `BlockAndRemediate` | Confirmed-malicious files. No false-positive risk. |
| `npm-cache.com`, `js-mirror.com`, `pypi-get.com` | `DomainName` | `Block` | Attacker-controlled. Requires Network Protection. |
| **`awqhnjewqjkl.icu`** | `DomainName` | **`Block`** | Attacker-controlled (Elastic). **This was missing.** It sat in `github_conf/ioc/chaindrop_elastic_2026_08.json` from ingest while every rule and this list omitted it — a known C2 domain we were not blocking. Ingesting a source file is not acting on it. |
| `eth-mainnet.nodereal.io`, `go.getblock.io`, `eth.llamarpc.com` | `DomainName` | **`Audit`** | Legitimate public infrastructure. Blocking breaks real blockchain work. Audit gives the telemetry without the outage. |
| `104.21.35.216` | — | **do not create** | Cloudflare shared address. Blocking it takes out unrelated sites behind the same edge. Hunting pivot only. |
| `github.com/oven-sh/bun/releases/…` | — | **do not create** | The Bun fetch is the best *detection* point in the chain (see `npm-shaihulud-bun-fetch`) and the best *prevention* point, but prevention belongs in the CI egress allowlist (§5.2 #5), not in a tenant-wide URL block on a legitimate GitHub origin. |

**Do not read this table as complete because the indicator count matches the hash count.** The
gap above was found by diffing the source files in `github_conf/ioc/` against this list and
against the deployed rules — not by reading either one. That diff is now step 2 of adding a
campaign (§7).

### 5.2 Controls that actually stop this chain

1. **`npm config set ignore-scripts true`** on developer machines and CI. This kills the
   primary chain outright. It breaks packages with legitimate native builds, so pilot it —
   but it is the single highest-value control here. Note it does **nothing** against the
   `.claude`/`.vscode` autostart path.
2. **Registry allowlist / proxy** (Artifactory, Verdaccio) with a quarantine window on new
   versions. The worm's whole propagation model is publish-then-spread within hours; a
   24-hour hold on new releases converts an incident into a non-event. This is also the only
   place the org gets a **complete, version-accurate** record of what was fetched — the thing
   EDR structurally cannot provide.
3. **Package-manager-native release-age gate — the no-Artifactory path.** Control 2 needs a
   proxy and a project to stand it up. Every major package manager now ships the quarantine
   window as a config flag, which gets most of control 2's protective value this week rather
   than next quarter:

   | Tool | Setting | Minimum version |
   |---|---|---|
   | npm | `min-release-age` | 11.10 |
   | pnpm | `minimumReleaseAge` | 10.16 |
   | Yarn | `npmMinimalAgeGate` | 4.10 |
   | Bun | `minimumReleaseAge` | 1.3 |
   | Dependabot | `cooldown` | n/a (config block) |

   Set it to 24–72 h. **Every malicious version in this campaign was unpublished within hours**,
   so a gate at 24 h would have made the entire 2 h 40 m publish window unreachable — no rule,
   no indicator, no hash needed. It does not replace control 2: it gives no fetch record, and it
   does nothing for a version that stays up. It is a floor, and it is nearly free.
4. **Pin and commit lockfiles**, `npm ci` in CI, never `npm install`. In CI use
   `npm ci --ignore-scripts` — it composes control 1 with this one, and CI is where breaking a
   native build is cheapest to discover. The 81 adjacent repos in §3 are exactly the population
   where this pays.
5. **Egress allowlist on build agents — the missing chokepoint.** The dropper carries no
   payload: it fetches Bun from `github.com/oven-sh/bun/releases/download/bun-v1.3.13/` and
   stage 2 only executes under Bun. An allowlist that does not include the GitHub release CDN
   **stops the chain at its first hop** — stage 2 never runs and no credential is ever read.
   This is strictly better than blocking C2: it is one origin rather than 75 RPC endpoints plus
   three fallback channels, and it acts before collection rather than after. The ask is not
   blocking `github.com` wholesale; it is that build agents fetch release binaries through a
   controlled mirror.
6. **Provenance is not a defense in this campaign** — and it fails **twice**, which is worth
   stating separately because the two failures need different answers.
   * The attacker **self-mints** attestations from the stolen publisher context, via
     `fulcio.sigstore.dev` and `rekor.sigstore.dev`, after repacking the tarball with
     recomputed SHA-512/SHA-1.
   * Worse, `keyv@6.0.0` was published by **the project's own legitimate release workflow** and
     carries genuine, valid SLSA provenance attesting a real build from a real commit in
     `jaredwray/keyv`. It does. The commit was malicious. Provenance attests the build, not the
     source, so a provenance-verifying control **passes** this package.

   The mechanism is the reusable part: commit `ee2681a` edited `scripts/release-publish.ts` to
   read `latestMajor` from the repository's own `package.json` instead of a protected CI
   variable — moving the `latest`-channel decision into state the attacker already controlled.
   Nothing in the pipeline was compromised; it did what its configuration said.
   **This is the one part of the campaign with a review-time control**: flag any diff to release
   or publish tooling that relocates a version, channel or `latest`-tag decision from CI
   configuration into repository-controlled state. It is upstream of every indicator in this
   playbook, and it applies to us as a publisher, not only as a consumer.

---

## 6. Coverage and blind spots

Onboarding measured via `DeviceInfo` (see prior hunt for method):

| Surface | Layer 2 coverage |
|---|---|
| Windows clients + servers | 2,974 + 192 — covered |
| macOS | 106 — covered (Jamf is MDM authority; irrelevant to EDR onboarding) |
| Linux | 312 — covered |
| Self-hosted Actions runners `cxdkrprdapp12–17.comfort.com` | 6 — covered |
| **GitHub-hosted ephemeral runners** | **not covered at all.** No agent, no telemetry. Layer 1 + Actions log scanning only. |
| Developer machines not Defender-onboarded | not covered — enumerate before trusting a zero |

Three structural gaps to state plainly:

* **`RemoteUrl` depends on Network Protection.** Without it in block or audit mode, Defender
  records only the remote IP, because node performs its own TLS. `npm-shaihulud-c2-contact`
  and the registry-tarball hunt both go quiet — and a quiet rule looks identical to a clean
  estate. Verify Network Protection coverage before reading a zero from either —
  `kql/coverage/04`, `kql/coverage/05` and `kql/poc/34` are written for exactly this.
* **Ephemeral CI is where this worm propagates.** The exfil stage runs as a GitHub Actions
  workflow. Layer 2 cannot see GitHub-hosted runners at all; that surface belongs to Layer 1
  and to Actions log review.
* **The malware declines to run on some hosts, and those hosts look clean.** CHAINDROP reads
  `LANG` and exits without executing if it indicates a Russian locale (StepSecurity). On such a
  host the dropper is on disk and would have executed, but every *behavioural* rule returns
  nothing — no Bun spawn (rule 3), no loader exec (rule 2), no C2 (rule 5), no exfil artefact
  (rule 6). Only the file-hash rules (1, 4, and the new 7) fire.

  This is not exotic; it is the general shape of the problem. A rule set weighted towards
  behaviour has a false-negative surface equal to the malware's own evasion logic. Two
  consequences: **enumerate estate locales before reading a behavioural zero as clean**, and
  keep file-hash and file-write telemetry as the primary surface wherever the payload has a
  known hash — that surface is indifferent to whether the code ran.

---

## 7. Runbook

**Standing (weekly):** re-pull the IOC package list, re-run Layer 1, treat exit 2 as an
incident.

**On a Layer 2 alert — rotate before you eradicate.** The payload exfiltrates first, so
deleting files first only destroys evidence while the credentials stay live.

If the kill switch is armed, containment has already happened: the device is isolated and
the artefact quarantined before you read the alert. Step 0 is therefore to tell the
developer why their machine went offline — then work the list. Do not release the device
until step 2 is done.

1. Capture the file and its parent directory. A forensic package was collected
   automatically; pull it from the device page rather than re-collecting.

1.5. **Remove the token-revocation monitor before you revoke anything.** Read this step in full;
   getting the order wrong makes the incident worse.

   The payload installs a watchdog that polls `https://api.github.com/user` every 60 seconds for
   24 hours and **fires the payload when the token stops authenticating**. Revocation is its
   trigger condition, not its remedy: it responds by re-collecting and re-exfiltrating from
   whatever credentials are still live on the host.

   On the isolated device, remove all four artefacts and confirm the service is gone:

   ```bash
   # Linux
   systemctl --user disable --now gh-token-monitor.service 2>/dev/null
   rm -f  ~/.local/bin/gh-token-monitor.sh
   rm -rf ~/.config/gh-token-monitor/
   rm -f  ~/.config/systemd/user/gh-token-monitor.service
   systemctl --user daemon-reload
   systemctl --user list-units --all | grep -i gh-token-monitor   # expect no output

   # macOS
   launchctl bootout gui/$(id -u)/com.user.gh-token-monitor 2>/dev/null
   rm -f  ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
   rm -f  ~/.local/bin/gh-token-monitor.sh
   rm -rf ~/.config/gh-token-monitor/
   launchctl list | grep -i gh-token-monitor                     # expect no output
   ```

   Then confirm no watchdog process survives: `pgrep -af gh-token-monitor` — expect no output.

   **This does not reverse "rotate before you eradicate."** The payload still exfiltrates first,
   so a full clean-up before rotation still destroys evidence while credentials stay live. The
   order is: *sweep and remove the monitor* → *rotate* → *eradicate the rest*. Step 1.5 is a
   narrow carve-out for the one artefact whose removal must precede rotation, and it is also the
   only artefact that survives step 3 — a host cleaned by step 3 alone is still armed. If the
   device is fully isolated and the monitor cannot reach `api.github.com`, it cannot observe the
   revocation; do not rely on that, because `selective` isolation and any pre-isolation window
   both leave it live.

2. Revoke everything reachable from that user context — and scope it wider than GitHub and npm.
   The collector matches 300+ patterns across ~140 hotspot paths:
   * npm publish tokens (**especially any with `bypass_2fa: true`** — the collector prefers
     these), GitHub PATs, Actions tokens, JWT/session tokens
   * **AI tooling credentials**, new in this campaign and present on this estate's workstations:
     `.claude/credentials.json`, `.codex/auth.json`, `.cursor/credentials.json`,
     `.openai/auth.json`, `.anthropic/auth.json`, `.gemini/.env`
   * cloud: AWS/GCP/Azure/Alibaba keys, plus anything reachable from **IMDSv2 or ECS task
     metadata** on that host. Check CloudTrail for `sts:GetCallerIdentity`,
     `secretsmanager:ListSecrets`, `secretsmanager:GetSecretValue` and `ssm:GetParameters` from
     the harvested principal **across all 16 regions** — the collector sweeps regions, so a
     single-region check under-scopes.
   * HashiCorp Vault tokens (k8s and IAM auth), SSH private keys, Kubernetes service-account
     tokens and any kubeconfig on the host
   * anything exported in the shell

   **If the host reached `npm-cache.com`, scope it as code execution, not credential theft.**
   The exfil envelope is bidirectional: a response containing a `code` field is passed to
   `eval()`. Rotation scope is everything reachable from that host, not a list of file paths.

   **If the host is a self-hosted runner** (`cxdkrprdapp12–17.comfort.com`), rotate **every
   secret any workflow on that runner consumed in the window**, not just the triggering repo's.
   The memory scrape reads `/proc/<Runner.Worker pid>/mem` for `"isSecret":true`, which takes
   masked secrets the compromised step never referenced.
3. Grep the whole working tree for `setup.mjs`, `math_init.js`, `Math_Symbol.js`,
   `.claude/`, `.vscode/`, `.github/workflows/codeql_analysis.yml`. Match `setup.mjs` **by
   hash** where possible — there are two malicious variants (29,918 B and 11,017 B) and
   legitimate `setup.mjs` files exist. Also check `$TMPDIR` for `bun-dl-*` staging directories
   and `tmp.dpkg_<pid>.lock` beacons.
4. Check GitHub: branch `dependabot/github_actions/format/setup-formatter`, commits titled
   `chore: update config`, forged trailer `Co-authored-by: claude
   <claude@users.noreply.github.com>`, workflow author `github-advanced-security[bot]`, repos
   described `Shai-Hulud: Here We Go Again` or named from Dune vocabulary. Two extensions:
   * **Enumerate all branches, not just the default.** Where a GitHub App token is stolen the
     worm commits to up to 50 branches per accessible repository, so a default-branch check
     reads a compromised repo as clean.
   * **Search the exfil-workflow primitive, not its filename.** Two variants are documented —
     `codeql_analysis.yml` and a workflow named `Run Copilot` on `push`. Both write
     `${{ toJSON(secrets) }}` to a file and upload it. Grep every workflow added or modified by
     a non-human identity for `toJSON(secrets)`; keying on either filename misses the other.
5. Delete any `format-results` artefact from Actions — it contains the stolen credentials. Also
   look for staging repositories under the victim account holding `results-*.json`.
6. Run Layer 1 against the affected repo to identify the delivering `name@version`.

**On adding a new campaign — three steps, not one:**

1. Add each source as **its own file** in `github_conf/ioc/` (see
   `chaindrop_elastic_2026_08.json`, `chaindrop_stepsecurity_2026_08.json`), with a
   `_relationship_to_*` block recording confirms / does_not_mention / contradicts. Never merge a
   source into the shared bundle — that destroys the provenance §1.2 arbitration needs.
2. **Diff the new source file against §5.1's indicator list and the deployed rules, and record
   the diff.** This step exists because it was skipped: `awqhnjewqjkl.icu` sat in an ingested
   source file while every rule and the indicator list omitted it. Ingesting a source file
   creates the *appearance* of coverage.
3. Add hashes and domains to the IOC bundle and the package CSV, add or edit rules in
   `npm_supply_chain_rules.json`, re-run the deployer. The rules key on behaviour, so a new
   variant of the same family usually needs only new hashes.
