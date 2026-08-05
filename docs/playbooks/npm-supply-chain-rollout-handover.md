# Handover: Shai-Hulud npm Supply-Chain Detection & Containment — Tenant Rollout

**For review and approval by:** Global Administrator / Security Administrator, Microsoft 365 tenant `ed8aabd5…`
**Prepared by:** Rob Vance
**Date:** 2026-08-05
**Threat:** Shai-Hulud "Here We Go Again" — active npm worm, first observed 2026-08-04T10:53Z ([JFrog Security Research](https://research.jfrog.com/post/shai-hulud-is-back-august/))
**Source of truth for this document:** `github_conf/detections/npm_supply_chain_rules.json`, `github_conf/ioc/shai_hulud_2026_08.json`, `scripts/ioc/deploy_detection_rules.py`

---

## 1. Decision requested

Three approvals. They are independent — approving 1 and 2 delivers detection without any containment risk.

| # | Approval | Risk if approved | Risk if declined |
|---|---|---|---|
| 1 | Create a dedicated enterprise service principal (§3) and grant it `CustomDetection.ReadWrite.All` | Non-human identity can create/modify custom detection rules | Rules must be hand-built in the portal; no version control, no reviewable change history |
| 2 | Grant the same principal `Ti.ReadWrite.All` (WindowsDefenderATP) | Non-human identity can publish IOC block indicators | No preventive blocking; detection only |
| 3 | Authorise **automated device isolation** on 5 of 6 rules (§7) | A false positive isolates a developer or a CI runner mid-build | Containment waits on human triage; this worm exfiltrates credentials in seconds and republishes within hours |

Approval 3 is the one that needs real scrutiny. §7 documents the blast radius honestly, including the two decisions it forces: which device group to pilot on, and whether the self-hosted CI runners are eventually included.

---

## 2. What this is, in one page

The worm's chain:

```
npm install
  └─ package.json preinstall hook  ──▶  node setup.mjs
                                          └─ downloads Bun 1.3.13 (official GitHub release)
                                              └─ executes math_init.js  ──▶ credential theft + republish
```

Secondary chain, **no npm required**: repo opened in VS Code or an agent runtime → `.vscode/tasks.json` or `.claude/settings.json` autostart hook → same loader. This matters because **npm ≥ 12 does not run `preinstall` hooks by default** — a control keyed on npm alone misses this path entirely.

Three things make it hard:

1. **Provenance does not help.** Initial access was the keyv maintainer's compromised GitHub account. Releases were cut through GitHub Actions, so the poisoned versions carry *valid npm provenance attestations*. Provenance attests the build, not the source.
2. **Version lists go stale on arrival.** The worm republishes every package writable with each stolen credential set, incrementing patch versions. Vendor counts already disagree (JFrog 428 packages, Cloudsmith ~444, Aikido 868). Detection therefore keys on **behaviour and file hashes**, which are version-independent.
3. **C2 is resolved on-chain.** The payload reads its live C2 address from Ethereum contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103` via public RPC providers. Blocking one domain does not sever control; the RPC providers are the chokepoint.

### Three-layer design

| Layer | Where | What it does | Status |
|---|---|---|---|
| 1 — Inventory | `scripts/ioc/match_npm_ioc.py` against the dependency database | Exact `name@version` matching against 2,235 known-malicious pairs. Only place resolved versions exist. | **Working.** Result below. |
| 2 — Detection + containment | Defender XDR custom detection rules (this rollout) | Behaviour and hash detection on the endpoint, with optional automated containment | **Built, not deployed.** Blocked on §1 approvals. |
| 3 — Prevention | MDE indicators + npm configuration | Block known-bad hashes/domains; stop lifecycle scripts running at all | **Blocked** on approval 2; the npm half needs no Microsoft approval |

### Layer 1 result (already complete)

Scan of **1,890 repositories** (full-force rescan, exit code 0, 6 repos timed out — named in `vulnerability_reports/stuck_repos_summary.md`), **46,231 dependency rows across 467 repos**:

- **Exact matches: 0.** No dependency in the inventory resolves to a known-malicious release.
- **Adjacent: 81 distinct repos** carry an IOC package at a *safe* version — `keyv` (77 repos, versions 4.0.3 / 4.3.0 / 4.5.2 / 4.5.3 / 4.5.4), `cacheable-request` (76), `file-entry-cache` (12), `flat-cache` (12).

Adjacent is **not a finding** — these are ubiquitous legitimate dependencies. It is a blast-radius measure: these are the repos an unpinned upgrade would walk into a malicious version.

**That zero is not a clean bill of health.** It is only as current as the IOC list (which moves hourly) and the last scan of each repo. It says nothing about developer laptops, where an install happens outside any repo we scan. That is precisely the gap Layer 2 fills.

---

## 3. Enterprise service principal — not a personal identity

**Current state, to be replaced.** Work to date used app registration `ca38f5b8…` ("Microsoft Graph - RobV") — an individually-owned registration with a client secret in a local `.env`. That is fine for research and unacceptable for a production control. It dies when I leave, it is not attributable to a team, and the secret lives on a laptop.

### Requested target state

| Property | Value |
|---|---|
| Display name | `svc-defender-detection-as-code` |
| Type | Single-tenant app registration + service principal |
| Owners | **Security Engineering group**, minimum two members. No individual sole owner. |
| Credential | **Workload identity federation** (OIDC federated credential) — no secret, no certificate, nothing to rotate or leak |
| Federated subject | The CI identity that runs deployments (see below) |
| Secrets/certs | **None issued.** If federation is impossible, a certificate in Azure Key Vault with a 90-day rotation — never a client secret. |
| Graph permissions | `CustomDetection.ReadWrite.All` (application), admin consent |
| Defender permissions | `Ti.ReadWrite.All` (WindowsDefenderATP, application), admin consent |
| Exclusions | No `Machine.Isolate`, no `Machine.*`, no `SecurityActions.*`. Isolation is triggered by the *rule* running in Defender, never by this principal calling an API. |
| Conditional Access | Workload Identity CA policy: allow only from the CI egress IP range / named location |
| Sign-in logs | Service principal sign-ins reviewed monthly; alert on any sign-in outside the CI named location |
| Review cadence | Access review every 90 days; entitlement expires unless renewed |

### Why federation and not a secret

A client secret for a principal that can create detection rules is a standing credential that can arm automated isolation. Federation binds the token to the CI workload — there is nothing to exfiltrate from a laptop, no rotation to forget, and every issuance is logged against the pipeline run.

**Implemented.** `scripts/ioc/deploy_detection_rules.py` resolves credentials in this order, first match wins:

| Priority | Source | Use |
|---|---|---|
| 1 | `AZURE_FEDERATED_TOKEN_FILE` | Workload identity federation (AKS / Azure Workload Identity). Re-read per token request, so kubelet rotation is handled. |
| 2 | `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | **GitHub Actions OIDC — the intended path.** Needs `permissions: id-token: write`. |
| 3 | `GRAPH_CLIENT_ASSERTION` | Pre-fetched federated JWT (Azure DevOps, other OIDC providers) |
| 4 | `GRAPH_CLIENT_SECRET` | Fallback. **Prints a warning** identifying itself as the thing federation exists to remove. |

`GRAPH_TENANT_ID` and `GRAPH_CLIENT_ID` are required in all four cases. Assertions are fetched per token request rather than cached, because they are minutes-lived. Nothing logs the assertion — only the credential *kind*, which appears in the apply banner and in every audit record.

### Where deployment runs

`.github/workflows/deploy-detection-rules.yml` — written, `workflow_dispatch` only:

| Control | Implementation |
|---|---|
| Manual trigger only | No `push` or `schedule`. A rule that deploys itself can arm isolation with nobody deciding to. |
| Second approver | Modes that touch the tenant run in the protected `defender-prod` environment; `validate` runs in `defender-validate` and needs no credential at all |
| No secret possible | Job requests only `contents: read` and `id-token: write`. No `GRAPH_CLIENT_SECRET` is passed. |
| PR builds cannot deploy | Federated credential subject scoped to repo **and** environment |
| No interleaved runs | `concurrency` group, `cancel-in-progress: false` — a half-applied arm is worse than either outcome |
| Tenant-wide arming is deliberate | `deploy-armed` with no `device_group` **fails** unless `allow_tenant_wide` is ticked |
| Always verifies | `--kill-switch-status` runs even on failure. The rules file is not evidence of tenant state. |
| Evidence retained | `exports/kill-switch-audit.jsonl` uploaded as a 90-day artifact |

Modes: `validate`, `deploy-disabled`, `deploy`, `deploy-armed`, `disarm`, `status`.

Net effect: creating or arming a detection rule requires a reviewed pull request **plus** a second human approving the environment. Neither I nor any single person can do it alone.

**Two GitHub environments must be created** (Settings → Environments) before the workflow runs:

| Environment | Required reviewers | Variables |
|---|---|---|
| `defender-prod` | ≥ 1, from Security Engineering | `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID` |
| `defender-validate` | none | `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID` |

### Human RBAC, separate from the principal

For portal work, portal-based validation, and incident response, humans need Defender XDR Unified RBAC — **not** membership in the service principal's permissions:

| Task | Role |
|---|---|
| Create/tune detection rules in the portal | Defender XDR Unified RBAC → **Detection tuning (Manage)** |
| Release an isolated device | **Security operations → Response (Manage)** — the Machine.Isolate equivalent |
| Grant the app permissions in §1 | Entra **Global Administrator** or **Privileged Role Administrator** (Application Administrator can add but not consent) |

Device release is deliberately a *human* role held by SecOps, not a capability of the automation. Nothing in this system un-isolates a device.

---

## 4. Permission request — text to action

> On a new single-tenant app registration named `svc-defender-detection-as-code`, owned by the Security Engineering group, in tenant `ed8aabd5…`:
>
> 1. Configure a **federated credential** (workload identity federation) for the GitHub Actions `defender-prod` environment of the `auditgithub` repository. Issue **no client secret and no certificate**.
>    - Scenario: GitHub Actions deploying Azure resources
>    - Organization: `sleepnumberinc` · Repository: `auditgithub` · Entity type: **Environment** · Environment name: `defender-prod`
>    - Resulting subject: `repo:sleepnumberinc/auditgithub:environment:defender-prod`
>    - Audience: `api://AzureADTokenExchange` (default)
> 2. Grant these **application** permissions with admin consent:
>    - Microsoft Graph → `CustomDetection.ReadWrite.All`
>    - WindowsDefenderATP → `Ti.ReadWrite.All`
> 3. Do **not** grant `Machine.Isolate`, `Machine.*`, or `SecurityActions.*`.
> 4. Apply the Workload Identity Conditional Access policy restricting sign-in to the CI named location.
>
> Purpose: detection-as-code and IOC publication for the active Shai-Hulud npm worm campaign. Rules are version-controlled in `github_conf/detections/`.

Separately, assign the SecOps on-call rota **Detection tuning (Manage)** and **Security operations → Response (Manage)** in Defender XDR Unified RBAC.

---

## 5. API facts the reviewer should know

| | |
|---|---|
| Endpoint | `POST https://graph.microsoft.com/beta/security/rules/detectionRules` |
| Version | **beta only.** This resource does not exist in v1.0 as of 2026-08-05. Graph SDKs default to v1.0, so SDK examples silently 404. |
| Cloud availability | **Global service only.** Not available in US Gov L4/L5 or 21Vianet. |
| Permission | `CustomDetection.ReadWrite.All` |
| Idempotency | `id` is client-provided and required. The deployer GETs then PATCHes, else POSTs — re-running is safe. |
| Retroactive? | **No.** Custom detections evaluate only from their first scheduled run forward. This is why §6 step 0 exists. |

**Schema deprecations — all removed 2026-10-01.** Rules in this repo already use the current shape; flagged so a reviewer comparing against older Microsoft samples or blog posts is not confused:

| Deprecated | Current |
|---|---|
| `isEnabled` | `status` (`enabled` / `disabled`) |
| `schedule.period` (enum) | `schedule.frequency` (ISO-8601 duration) |
| `schedule.nextRunDateTime`, `detectorId`, `lastRunDetails` | removed |
| `detectionAction.responseActions[]` | `detectionAction.automatedActions` (`automatedActionSet`) |

Note: web search results for this API frequently return the **deprecated** `responseActions` shape. Reviewers should compare against the Microsoft Graph resource reference, not blog examples.

---

## 6. Rollout sequence

### Step 0 — Today. No approvals required.

`ThreatHunting.Read.All` is **already granted**. Because custom detections are not retroactive, anything already on disk in the estate is invisible to the rules no matter how fast they deploy.

**Run all 8 queries in Appendix A and B as one-off Advanced Hunting queries first.** That covers the full 30-day retention window and needs nothing new. Change each `ago(1h)` to `ago(30d)` for the backlog sweep. If something is already present, we need to know now, not at the top of the next hour.

**Also verify Network Protection state** across the estate. Rule 5 (`npm-shaihulud-c2-contact`) reads `RemoteUrl`, which is empty unless Network Protection is in block or audit mode — node performs its own TLS and Defender records only the IP. Without it, that rule deploys, runs, and reports clean forever. This is a prerequisite, not an enhancement.

```kql
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010"   // Network Protection
| summarize Devices = dcount(DeviceId) by IsCompliant, OSPlatform
```

### Step 1 — Service principal and consent (§3, §4)

Blocking gate for steps 3 onward. Nothing to build first — the deployer and the workflow are done.

### Step 2 — Portal pilot, in parallel with step 1

Do not wait on consent to get the two highest-confidence rules live. In `security.microsoft.com` → **Hunting → Advanced hunting**: paste the query, run it, then **Create detection rule**. Map entities on the *Impacted entities* tab, frequency hourly, actions on the *Actions* tab.

Deploy `npm-shaihulud-payload-hash` and `npm-shaihulud-c2-contact` first — both are confirmed-malicious-only, so they are the two worth arming anyway. This needs only the human **Detection tuning (Manage)** role, no app grant.

Once the API grant lands, the deployer PATCHes these in place (same `id` values), so the tenant converges on git with no duplicates.

### Step 3 — Deploy as code, detection only

Run the workflow, `Actions → Deploy Defender Detection Rules → Run workflow`:

| Order | Mode | Effect |
|---|---|---|
| 1 | `deploy-disabled` | Rules created, `status=disabled`. No alerts. |
| 2 | `status` | Confirms what is actually live in the tenant |
| 3 | `deploy` | Enabled, **unarmed** |

Equivalent locally, if the credential is available:

```bash
python3 scripts/ioc/deploy_detection_rules.py --apply --status disabled   # stage, no alerts
python3 scripts/ioc/deploy_detection_rules.py --list                      # confirm all 6 present
python3 scripts/ioc/deploy_detection_rules.py --apply                     # enable, UNARMED
```

`--apply` without `--arm` strips `automatedActions` entirely and warns. Rules alert; nothing is contained.

**Hold here for a minimum of one full baseline cycle.** Detection-only first gives the false-positive rate before any device is isolated for it. `npm-shaihulud-bun-from-node` in particular needs baselining — see §7.

### Step 4 — Arm (requires approval 3, and read §7 first)

**Pilot on one device group first.** Workflow mode `deploy-armed` with `device_group` set to a small group of developer workstations. Tenant-wide arming requires ticking `allow_tenant_wide`, and the workflow fails without it.

```bash
# pilot — one device group
python3 scripts/ioc/deploy_detection_rules.py --apply --arm --scope "Dev Workstations"

# tenant-wide, after the pilot runs clean
python3 scripts/ioc/deploy_detection_rules.py --apply --arm --scope-all-devices

python3 scripts/ioc/deploy_detection_rules.py --kill-switch-status   # reads the TENANT, not the file
```

Both print the full blast radius and require the operator to type `ARM`. The confirmation names the scope, and calls out by name any armed disruptive rule that carries no device-group restriction.

Scope only narrows implicitly: omitting `--scope` on a re-apply leaves the deployed scope untouched, because PATCH does not clear an omitted complex property. Widening back to the whole tenant is explicit — `--scope-all-devices`.

### Step 5 — Prevention layer

Once `Ti.ReadWrite.All` is granted, publish MDE indicators:

| Indicator | Value | Action |
|---|---|---|
| 7 payload SHA-256 hashes | see Appendix C | `BlockAndRemediate` |
| `npm-cache.com`, `js-mirror.com`, `pypi-get.com` | attacker-controlled | `Block` |
| `eth-mainnet.nodereal.io`, `go.getblock.io`, `eth.llamarpc.com` | legitimate RPC providers | **`Audit`** — not Block |
| `104.21.35.216` | **do not create** | Cloudflare shared address; blocking breaks unrelated traffic |

Note: the legacy Graph `tiIndicators` API is being removed by April 2026. Use the MDE Indicators API on `api.securitycenter.microsoft.com`.

**Independent of Microsoft entirely, and arguably the single highest-value item in this document:**

```bash
npm config set ignore-scripts true
```

This kills the primary execution chain outright. Pilot it — it breaks packages with legitimate native build steps. Pair with:

- `scripts/ioc/match_npm_ioc.py` in CI, gating on **exit code 2** (exact match found)
- A registry proxy with a **24-hour quarantine window** on newly published versions. This is also the only place we would get a complete, version-accurate record of what was actually fetched.

---

## 7. Blast radius, and two gaps that are not closed

This section is the substance of approval 3. Please read it before signing.

### The accepted cost

Isolation takes a developer offline mid-build. That is the intended trade, not a side effect. `selective` isolation still severs registry, git and package-manager access — it preserves only Outlook, Teams and Skype so a responder can reach the person. **There is no isolation mode that keeps a build working.**

The justification: this campaign exfiltrates credentials before it does anything else, and republishes from the stolen tokens within hours. The window in which human triage helps is shorter than the window in which it spreads.

### DECISION 1 — CI runners are in scope unless you scope them out

Six self-hosted GitHub Actions runners are Defender-onboarded: **`cxdkrprdapp12`–`17.comfort.com`**. They run `npm install` constantly and are exactly what this worm targets. An armed rule firing there isolates a production CI runner and **stops builds org-wide**.

That may well be correct — a compromised build runner is worse than a stopped one — but it should be a decision, not a surprise.

**Tooling now supports the choice.** `--scope "<device group>"` emits `detectionAction.organizationalScope` (`scopeType: deviceGroup`, verified against the resource reference). The workflow refuses `deploy-armed` with no `device_group` unless `allow_tenant_wide` is explicitly ticked, and the local confirmation prompt names every unscoped armed disruptive rule before accepting `ARM`.

**Recommendation:** pilot armed rules on a developer-workstation device group. Extend to the runners deliberately, in writing, once the pilot has run clean. The one thing not to do is arm tenant-wide by default and discover the runner interaction during an incident.

**One limit worth knowing:** Graph accepts a `scopeNames` entry matching no existing device group, and the rule then matches nothing. A scoped rule with a typo'd group name is indistinguishable from a clean estate. The deployer prints the names back for exactly this reason — read them against the device groups in the Defender portal.

### GAP — Isolation support varies by platform

Estate coverage:

| Platform | Count |
|---|---|
| Windows clients | 2,974 |
| Windows servers | 192 |
| macOS | 106 |
| Linux | 312 |
| Self-hosted CI runners (Defender-onboarded) | 6 |
| GitHub-hosted ephemeral runners | **invisible — no Defender agent, no telemetry, ever** |

Device isolation support differs between Windows and macOS/Linux in MDE. **Confirm before relying on it.** An armed action that silently no-ops on 312 Linux hosts is worse than knowing it will not fire, because it reads as coverage.

### Two-key arming control

Automated response cannot be enabled by any single action:

| Key | Where | Control property |
|---|---|---|
| 1 | `killSwitch.armed: true` in `npm_supply_chain_rules.json` | Reviewed in a pull request, attributable in git history |
| 2 | `--arm` on the deploy command | Deliberate operator intent + typed `ARM` confirmation + append to `exports/kill-switch-audit.jsonl` |

Neither key alone does anything. `--force` does **not** override `armed: false` — that would collapse two keys into one.

### Per-rule containment, as configured

| Rule | Severity | Tier | Armed in file | Automated actions |
|---|---|---|---|---|
| `npm-shaihulud-payload-hash` | high | **isolate-full** | yes | isolate (full), quarantine file, collect package |
| `npm-shaihulud-c2-contact` | high | **isolate-full** | yes | isolate (full), collect package |
| `npm-shaihulud-loader-exec` | high | isolate-selective | yes | isolate (selective), collect package, AV scan |
| `npm-shaihulud-exfil-artifacts` | high | isolate-selective | yes | isolate (selective), quarantine file, collect package |
| `npm-shaihulud-agent-hook-drop` | high | **quarantine-only** | yes | quarantine file, collect package, AV scan — **device stays online** |
| `npm-shaihulud-bun-from-node` | medium | isolate-selective | **NO** | defined and validated, deliberately not armed |

Three judgment calls worth a reviewer's attention:

1. **`agent-hook-drop` is quarantine-only, not isolation.** It is the one rule that can fire *before* compromise — the hook is written but has not necessarily executed. Removing the trigger and leaving the developer working is strictly better than isolating them.
2. **`bun-from-node` is unarmed.** It is the only medium-confidence rule. A toolchain that legitimately drives Bun from a node script trips it, and isolation would take that developer offline for doing nothing wrong. Baseline for a full cycle, then flip `armed` in a reviewed change.
3. **No file quarantine on process-event rules.** `stopAndQuarantineFiles` keys on the file the query returns. On a process rule that file is the interpreter — `node.exe` or `bun.exe`. Quarantining it bricks the toolchain and does nothing to the payload, which is a script. File actions attach only to file-event rules, where the returned hash is the malicious artefact.

### Validation without isolating a real developer

**Do not test an armed rule on someone's working machine.**

1. Use a dedicated, expendable test device.
2. Drop a harmless file named `setup.mjs` on it.
3. Run the rule's KQL as a **hunting query** and confirm it returns the synthetic event.

That proves query correctness and telemetry coverage without triggering any action. Arm only after this passes.

### Guardrails already enforced by the deployer

Validation runs locally and fails closed before any network call:

- Only **verified** automated-action types accepted. `blockFiles`, `allowFiles`, `disableUsers`, `forceUserPasswordResets`, `markUsersAsCompromised` and the six email actions are **rejected** — their nested column-property names are not verified against the Microsoft reference, and guessing risks a wrong-shaped payload that a future schema change silently reinterprets.
- Every action's target column must actually be projected by the query. Catches the silent no-op where an action names a column the query never returns.
- Disruptive action armed on a non-`high`-severity rule is an error unless explicitly forced.
- `isEnabled` and `schedule.period` (deprecated) are rejected.
- Missing `Timestamp` / `ReportId` is rejected — the rule would fail at create time.
- `ago()` lookback is checked against `schedule.frequency`. A longer window re-alerts on the same event every run; a shorter one drops events between runs.

Current state: **6/6 rules validate clean.** Exit codes: 0 ok, 1 error, 3 missing role, 4 validation failed.

### Rollback

```bash
python3 scripts/ioc/deploy_detection_rules.py --disarm --apply
```

Strips `automatedActions` from every deployed rule immediately. No confirmation required, because it only ever reduces capability.

**It does not release already-isolated devices.** Release is a deliberate human action via the Defender portal, or `POST /api/machines/{id}/unisolate` on `api.securitycenter.microsoft.com` (`Machine.Isolate` scope, held by SecOps, not by the automation).

Confirm eradication **and credential rotation** before releasing. A device released with the loader still on disk re-isolates on the next hourly run.

---

## 8. Incident response — first 30 minutes

If a rule fires, containment has likely **already happened**. Start from there.

0. **Confirm current containment state.** Check the alert's automated actions in the portal. Do not assume the device is online.
1. **Rotate credentials before eradication.** The payload exfiltrates first. Revoke, for that user context: npm publish tokens, GitHub PATs, GitHub Actions tokens, cloud provider keys (AWS/GCP/Azure), and anything exported in the shell environment. Eradicating first just means the attacker keeps working tokens.
2. **Capture before remediating.** The file and its parent directory. The investigation package is collected automatically on every armed rule.
3. **Search the working tree** for `setup.mjs`, `math_init.js`, `Math_Symbol.js`, `format-results.txt`, `.claude/`, `.vscode/`, `.github/workflows/codeql_analysis.yml`.
4. **Check the GitHub side.** Branch `dependabot/github_actions/format/setup-formatter`; commit message `chore: update config`; forged trailer `Co-authored-by: claude <claude@users.noreply.github.com>`; workflow author `github-advanced-security[bot]`; new repos described `Shai-Hulud: Here We Go Again` or named from Dune vocabulary (sardaukar, fremen, atreides). **Delete any `format-results` Actions artefact — it contains the stolen credentials.**
5. **Identify the delivering package.** `python3 scripts/ioc/match_npm_ioc.py --target sleepnumberinc` — exit code 2 means an exact match.
6. **Do not simply delete files.** Check `.claude/` and `.vscode/` for the autostart hook, which re-executes with no npm involvement.
7. **Release the device** only after eradication and rotation are both confirmed.

---

## Appendix A — Detection rule queries (6)

Deployable as-is. For the step-0 backlog sweep, change `ago(1h)` to `ago(30d)`.

Each query's `ago()` window matches its `schedule.frequency` of `PT1H` (hourly) by design. Every query projects `Timestamp` and `ReportId` — required by the API — plus every column named by an entity mapping or an automated action.

### A1. `npm-shaihulud-payload-hash` — high — isolate-full (armed)

Known payload SHA-256 on disk. Version-independent: matches regardless of which package version delivered it. No benign process writes these exact bytes.

```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where SHA256 in~ (
    "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc",
    "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb",
    "927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f",
    "14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128",
    "3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7",
    "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7",
    "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668")
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath, SHA256, SHA1,
          ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountSid
| limit 1000
```

MITRE: Execution T1195.002, Initial Access T1195.001

### A2. `npm-shaihulud-loader-exec` — high — isolate-selective (armed)

node/bun executing `setup.mjs` or `math_init.js`. Keys on loader filenames, so it survives every republish. Selective isolation because the responder needs to reach the developer immediately to start token rotation.

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("node","node.exe","bun","bun.exe","npm","npm.exe","npm-cli.js","pnpm","yarn")
     or InitiatingProcessFileName in~ ("node","node.exe","bun","bun.exe","npm","npm.exe")
| where ProcessCommandLine has_any ("setup.mjs","math_init.js","math_init","Math_Symbol")
| project Timestamp, ReportId, DeviceId, DeviceName, AccountName, AccountDomain, AccountSid,
          FileName, FolderPath, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| limit 1000
```

MITRE: Execution T1059.007, Initial Access T1195.002

### A3. `npm-shaihulud-bun-from-node` — medium — **UNARMED**

The loader fetches Bun 1.3.13 specifically to run its payload outside the project's Node runtime. Bun launched by a shell is normal; Bun launched by node or npm during an install is not. Baseline this before considering arming.

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("bun","bun.exe","bunx","bunx.exe")
| where InitiatingProcessFileName in~ ("node","node.exe","npm","npm.exe","npm-cli.js")
| project Timestamp, ReportId, DeviceId, DeviceName, AccountName, AccountDomain, AccountSid,
          FileName, FolderPath, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| limit 1000
```

MITRE: Execution T1059, Defense Evasion T1218

### A4. `npm-shaihulud-agent-hook-drop` — high — quarantine-only (armed, device stays online)

The secondary execution chain, and **the only coverage for npm ≥ 12** where `preinstall` hooks no longer run by default. Opening the repo in VS Code or an agent runtime executes the loader with no `npm install` at all.

```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("\\.claude","/.claude","\\.vscode","/.vscode")
| where FileName in~ ("setup.mjs","math_init.js","Math_Symbol.js")
     or (FileName in~ ("settings.json","tasks.json")
         and SHA256 in~ ("927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f",
                         "14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128"))
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath, SHA256, SHA1, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountSid
| limit 1000
```

MITRE: Persistence T1546, Execution T1195.002

### A5. `npm-shaihulud-c2-contact` — high — isolate-full (armed)

**Requires Network Protection in block or audit mode** — `RemoteUrl` is otherwise empty. Scoped to dev-toolchain initiating processes: these RPC endpoints have legitimate users, but not inside a package install.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteUrl has_any ("npm-cache.com","js-mirror.com","pypi-get.com",
                          "eth-mainnet.nodereal.io","go.getblock.io","eth.llamarpc.com")
| where InitiatingProcessFileName in~ ("node","node.exe","bun","bun.exe","bunx",
                                      "npm","npm.exe","npm-cli.js","pnpm","yarn",
                                      "python","python3","python.exe","git","git.exe")
| project Timestamp, ReportId, DeviceId, DeviceName, RemoteUrl, RemoteIP, RemotePort, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountSid
| limit 1000
```

MITRE: Command and Control T1102, Exfiltration T1041

**Caveats:** if any team here does blockchain work from node, scope this rule to exclude their devices rather than dropping the RPC hostnames — those hostnames are the resilient part of the IOC set, since the on-chain lookup defeats domain-level blocking by design.

### A6. `npm-shaihulud-exfil-artifacts` — high — isolate-selective (armed)

The worm stages stolen data as `format-results.txt` and exfiltrates through a forged `.github/workflows/codeql_analysis.yml` attributed to `github-advanced-security[bot]`. Both filenames are legitimate in isolation; a node or bun process writing them is not.

```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("format-results.txt","format-results","codeql_analysis.yml")
| where InitiatingProcessFileName in~ ("node","node.exe","bun","bun.exe","bunx","npm","npm.exe")
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath, SHA256, SHA1, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountSid
| limit 1000
```

MITRE: Exfiltration T1567.002, Credential Access T1552.001

---

## Appendix B — Hunting queries (2, not deployed as rules)

### B1. `npm-registry-tarball-fetch`

The closest honest implementation of "trigger on npm, inspect what it is fetching, compare to a blacklist" using endpoint telemetry alone. The registry URL path carries the resolved version — `<pkg>/-/<pkg>-<version>.tgz` — which is the only place a package version appears in any `Device*` table.

**Deliberately not a scheduled rule.** It depends on Network Protection populating `RemoteUrl`, and node's own TLS stack means coverage is partial even then. A scheduled rule built on this would return zero on most devices and read as "clean". Authoritative version matching belongs in `match_npm_ioc.py`.

```kql
let bad = dynamic(["keyv-6.0.0.tgz","cacheable-2.5.1.tgz","flat-cache-6.1.24.tgz",
                   "file-entry-cache-11.1.6.tgz","cacheable-request-13.0.20.tgz",
                   "cache-manager-7.2.10.tgz","utils-2.5.1.tgz","memory-2.2.1.tgz"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","node.exe","npm","npm.exe","npm-cli.js","pnpm","yarn","bun","bun.exe")
| where RemoteUrl has "/-/" and RemoteUrl endswith ".tgz"
| extend Tarball = tostring(split(RemoteUrl, "/-/")[1])
| where Tarball has_any (bad)
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Tarball, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| limit 1000
```

Prerequisites and limits: Network Protection enabled; traffic not rewritten by a TLS-inspecting proxy; not routed through a private registry mirror with a different path layout. Only the 8 seed packages are inlined — the full list is 2,235 `name@version` pairs, and `dynamic()` literals are size-limited. That limit is another reason version matching belongs in the database.

### B2. `npm-install-window-baseline`

Establishes who ran a package install in a window, to scope which developers' credentials are in play after a confirmed detection. This is the literal "trigger when npm is used" step — **useful for scoping, not for alerting.** `npm install` is normal; alerting on it produces one alert per developer per day and trains the team to ignore the rule.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("npm","npm.exe","npm-cli.js","node","pnpm","yarn","bun","bun.exe")
| where ProcessCommandLine has_any ("install"," ci","add ")
| summarize Installs = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
         by DeviceName, AccountName
| order by Installs desc
| limit 500
```

---

## Appendix C — IOC reference

Full bundle: `github_conf/ioc/shai_hulud_2026_08.json`

### Payload SHA-256

| Hash | Component |
|---|---|
| `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | `math_init.js` / `Math_Symbol.js` payload |
| `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | `setup.mjs` loader |
| `927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f` | `.vscode/tasks.json` autostart hook |
| `14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128` | `.claude/settings.json` autostart hook |
| `3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7` | `.github/workflows/codeql_analysis.yml` exfil workflow |
| `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7` | GitHub Actions runner memory scraper |
| `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | payload variant observed in internal hunt window |

### Network

| Value | Classification | Indicator action |
|---|---|---|
| `npm-cache.com`, `js-mirror.com`, `pypi-get.com` | attacker-controlled | `Block` |
| `eth-mainnet.nodereal.io`, `go.getblock.io`, `eth.llamarpc.com` | legitimate RPC, abused | `Audit` only |
| `104.21.35.216` | Cloudflare shared address | **do not create an indicator** |
| URL path `/router` | C2 endpoint | pivot |
| Contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103`, selector `0x53ed5143` | on-chain C2 resolution | pivot |

### Dropped files

`math_init.js`, `Math_Symbol.js`, `setup.mjs`, `format-results.txt`, `/tmp/tmp.dpkg_14527.lock`, `.vscode/tasks.json`, `.vscode/setup.mjs`, `.claude/math_init.js`, `.claude/settings.json`, `.claude/setup.mjs`, `.github/workflows/codeql_analysis.yml`

### Persistence paths

`LaunchAgents`, `.config/systemd/user`, `.local/bin`, `.claude`, `.vscode`

### Seed packages (malicious versions)

`keyv@6.0.0`, `cacheable@2.5.1`, `flat-cache@6.1.24`, `file-entry-cache@11.1.6`, `cacheable-request@13.0.20`, `cache-manager@7.2.10`, `@cacheable/utils@2.5.1`, `@cacheable/memory@2.2.1`

Known clean pins: `keyv@5.2.3`, `cacheable@1.8.8`

**These names are deliberately absent from every detection rule.** They are ubiquitous legitimate dependencies, and EDR telemetry does not expose the resolved version — a name-keyed endpoint rule alerts on normal installs and nothing else.

---

## Appendix D — Engineering status

Stated so the reviewer knows what is and is not built.

**Code complete:**

| Item | Where |
|---|---|
| Federated-credential support — workload identity file, GitHub Actions OIDC, pre-fetched assertion, secret fallback with warning | `deploy_detection_rules.py` → `resolve_credential()`, `_credential_form()` |
| `--scope` / `--scope-all-devices` emitting verified `organizationalScope` | `deploy_detection_rules.py` → `scope_object()`, `effective_scope()`, `to_wire()` |
| Scope validation — enum, non-empty names, `unknownFutureValue` rejected | `validate_organizational_scope()` |
| Scope surfaced in the arming confirmation, `--list`, `--kill-switch-status`, and the audit record | throughout |
| Deploy workflow with two-person control and a tenant-wide arming guard | `.github/workflows/deploy-detection-rules.yml` |

**Requires tenant access — cannot be completed from this repo:**

| # | Item | Blocks | Effort |
|---|---|---|---|
| 1 | Create the two GitHub environments (`defender-prod` with a required reviewer, `defender-validate`) and set `GRAPH_TENANT_ID` / `GRAPH_CLIENT_ID` as environment variables | Any workflow run | minutes |
| 2 | Enumerate Defender device groups and pick the pilot group name | Step 4 pilot | minutes |
| 3 | Confirm MDE device-isolation support on macOS and Linux | Truthful coverage claims | investigation |
| 4 | Verify Network Protection coverage across the estate | Rule A5 returning meaningful results | investigation |

---

## Sign-off

| Approval | Role | Name | Date | Decision |
|---|---|---|---|---|
| Service principal + `CustomDetection.ReadWrite.All` | Global Admin / Priv Role Admin | | | |
| `Ti.ReadWrite.All` (indicators) | Global Admin / Priv Role Admin | | | |
| **Automated isolation (§7)** | CISO / Security Owner | | | |
| Pilot device group, and whether CI runners are later included (§7 Decision 1) | Platform / DevOps Owner | | | |
| `npm config set ignore-scripts true` pilot | Engineering Owner | | | |

---

## Related documents

- `docs/playbooks/npm-supply-chain-ids-ips.md` — full technical playbook and design rationale
- `github_conf/detections/npm_supply_chain_rules.json` — rules as code, source of truth
- `github_conf/ioc/shai_hulud_2026_08.json` — IOC bundle
- `scripts/ioc/deploy_detection_rules.py` — deployer (dry-run by default)
- `.github/workflows/deploy-detection-rules.yml` — deploy workflow, two-person control
- `scripts/ioc/match_npm_ioc.py` — Layer 1 inventory matcher
- `exports/ioc-match-shai-hulud.json` — Layer 1 result data
- `exports/kill-switch-audit.jsonl` — arming audit trail
