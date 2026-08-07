# Handover: Shai-Hulud npm Supply-Chain Detection & Containment — Tenant Rollout

**For review and approval by:** Global Administrator / Security Administrator, Microsoft 365 tenant `ed8aabd5…`
**Prepared by:** Rob Vance
**Date:** 2026-08-05 · **revised 2026-08-06** (rule set 6 → 9; see *Revision 2026-08-06* below)
**Threat:** Shai-Hulud "Here We Go Again" — active npm worm, first observed 2026-08-04T10:53Z ([JFrog Security Research](https://research.jfrog.com/post/shai-hulud-is-back-august/)). Also tracked as **CHAINDROP** ([Elastic Security Labs](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain), [StepSecurity](https://www.stepsecurity.io/blog/chaindrop-npm-worm))
**Source of truth for this document:** `github_conf/detections/npm_supply_chain_rules.json`, `github_conf/ioc/shai_hulud_2026_08.json` (+ per-source files `chaindrop_elastic_2026_08.json`, `chaindrop_stepsecurity_2026_08.json`), `scripts/ioc/deploy_detection_rules.py`

> ### Revision 2026-08-06 — what changed and why a reviewer should care
>
> Two further technical analyses were published and arbitrated into the intel set (Elastic, StepSecurity; arbitration recorded in `docs/playbooks/supply-chain-hunt-ttp.md` §1.3). Four changes affect this packet:
>
> 1. **Three new rules** — `npm-shaihulud-token-monitor`, `npm-shaihulud-bun-fetch`, `npm-shaihulud-runner-mem-scrape`. **All three ship unarmed**, so they add detection surface without widening approval 3. §7 and Appendix A cover them.
> 2. **The incident-response order changed** (§8). The worm installs a watchdog that fires the payload *when a stolen token is revoked*. Revocation is its trigger, not its remedy. A new step 1 removes it before anything is rotated.
> 3. **One missing indicator was found** — C2 domain `awqhnjewqjkl.icu` was in an ingested source file while no rule and no indicator list referenced it. It is now in both. Recorded plainly because it was a process failure on our side, not a vendor's.
> 4. **Approval 3's blast radius is unchanged**, and one blind spot is now documented that was not before: the malware declines to run on hosts with a Russian locale, so every *behavioral* rule reads clean there while the dropper sits on disk (§7 GAP 3).

---

## 1. Decision requested

Three approvals. They are independent — approving 1 and 2 delivers detection without any containment risk.

| # | Approval | Risk if approved | Risk if declined |
|---|---|---|---|
| 1 | Create a dedicated enterprise service principal (§3) and grant it `CustomDetection.ReadWrite.All` | Non-human identity can create/modify custom detection rules | Rules must be hand-built in the portal; no version control, no reviewable change history |
| 2 | Grant the same principal `Ti.ReadWrite.All` (WindowsDefenderATP) | Non-human identity can publish IOC block indicators | No preventive blocking; detection only |
| 3 | Authorize **automated device isolation** on 5 of 9 rules (§7) | A false positive isolates a developer or a CI runner mid-build | Containment waits on human triage; this worm exfiltrates credentials in seconds and republishes within hours |

Approval 3's scope did not grow with the rule set: 9 rules, **5 armed in file** — the same 5 as on 2026-08-05. The three added on 2026-08-06 and `bun-from-node` are all unarmed pending baseline.

Approval 3 is the one that needs real scrutiny. §7 documents the blast radius honestly, including the two decisions it forces: which device group to pilot on, and whether the self-hosted CI runners are eventually included.

**One item needs no Microsoft approval at all and is arguably worth more than all three.** A package-manager-native release-age gate (npm 11.10+ `min-release-age`, pnpm 10.16+ `minimumReleaseAge`, Yarn 4.10+ `npmMinimalAgeGate`, Bun 1.3+ `minimumReleaseAge`, Dependabot `cooldown`) set to 24–72 hours makes this entire campaign unreachable: every malicious version was unpublished within hours of publication. It is a config flag, not a project. See §6 step 5.

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

Five things make it hard:

1. **Provenance does not help — and it fails twice.** Initial access was the keyv maintainer's compromised GitHub account, and releases were cut through the project's own GitHub Actions release workflow, so `keyv@6.0.0` carries a *genuine, valid* SLSA provenance attestation for a real build from a real commit. The commit was malicious. Separately, the worm **self-mints** Sigstore attestations (`fulcio.sigstore.dev`, `rekor.sigstore.dev`) for packages it repacks. A provenance-verifying control passes both. Provenance attests the build, not the source.
2. **Version lists go stale on arrival.** The worm republishes every package writable with each stolen credential set, incrementing patch versions. Vendor counts already disagree (JFrog 428 packages, Cloudsmith ~444, StepSecurity 444 / 2,212 versions, Aikido 868). Detection therefore keys on **behavior and file hashes**, which are version-independent.
3. **C2 is resolved on-chain, with 75 fallbacks.** The payload reads its live C2 address from Ethereum contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103` (selector `0x53ed5143`) by trying **75 public RPC endpoints in sequence**, and falls back to GitHub commit search if that fails. Blocking domains does not sever control. The real chokepoint is one hop earlier: the dropper carries no payload and must fetch Bun from the GitHub release CDN before anything runs.
4. **Revoking the stolen token is what triggers the payload.** A watchdog polls `api.github.com/user` every 60 seconds for 24 hours and re-runs collection when the token stops authenticating. It lives outside every path a normal clean-up touches, so a host cleaned of `setup.mjs`, `math_init.js`, `.claude/` and `.vscode/` is still armed. This inverts the standard IR order — see §8.
5. **It reads secrets out of runner memory.** On a self-hosted runner, a `sudo python3` helper reads `/proc/<Runner.Worker pid>/mem` and greps for `"isSecret":true`, taking every secret the runner handled during that job — including masked secrets never written to a log. Masking is not a mitigation here.

### Three-layer design

| Layer | Where | What it does | Status |
|---|---|---|---|
| 1 — Inventory | `scripts/ioc/match_npm_ioc.py` against the dependency database | Exact `name@version` matching against 2,235 known-malicious pairs. Only place resolved versions exist. | **Working.** Result below. |
| 2 — Detection + containment | Defender XDR custom detection rules (this rollout) | Behavior and hash detection on the endpoint, with optional automated containment | **Built, not deployed.** Blocked on §1 approvals. |
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

Everything in this step is a read. There are **30 queries ready to run**, as files, in `github_conf/detections/kql/` — see **Appendix E** for the map. Run them in directory order:

```bash
# lint every query locally first — no credentials needed, no tenant contact
python3 scripts/ioc/run_kql_poc.py

# then execute against the tenant with the existing hunting credential
python3 scripts/ioc/run_kql_poc.py --run --group coverage
python3 scripts/ioc/run_kql_poc.py --run --group backlog
```

Three things this step must establish, in this order:

1. **Coverage, before anything else.** `coverage/01`–`07` answer what the estate can actually see. Every "0 results" later in the rollout is meaningless without them. `coverage/02` produces the exact device-group names needed for `--scope`, which closes Appendix D item 2 without any new permission.

2. **The backlog.** Custom detections are **not retroactive**, so anything already on disk is invisible to the rules permanently. `backlog/20` runs the original six detection signals over the full 30-day retention window in a single query. Run it **before** the rules are deployed: once a rule is armed, a three-week-old artifact can isolate a machine that has been clean for weeks. **It does not cover A7–A9** — the watchdog, the Bun fetch and the memory scrape have no backlog query, so for those three the historical window is simply unexamined rather than clean.

3. **Network Protection state.** Rule 5 (`npm-shaihulud-c2-contact`) reads `RemoteUrl`, which is empty unless Network Protection is in block or audit mode — node performs its own TLS and Defender records only the IP. Without it, that rule deploys, runs, and reports clean forever. This is a prerequisite, not an enhancement.

   `coverage/04` checks the configured state, `coverage/05` checks whether it is actually emitting events, and `poc/34` answers the only question that decides the rule's fate: *does a node process's outbound connection arrive with a URL attached?* The configuration id is deliberately not hardcoded in `coverage/04` — those `scid-*` ids change, and a stale one returns an empty result that reads exactly like "no devices assessed".

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
| `npm-cache.com`, `js-mirror.com`, `pypi-get.com`, **`awqhnjewqjkl.icu`** | attacker-controlled | `Block` |
| `eth-mainnet.nodereal.io`, `go.getblock.io`, `eth.llamarpc.com` | legitimate RPC providers | **`Audit`** — not Block |
| `104.21.35.216` | **do not create** | Cloudflare shared address; blocking breaks unrelated traffic |
| `github.com/oven-sh/bun/releases/download/…` | **do not create** | Legitimate GitHub origin. Blocking it tenant-wide breaks every developer installing Bun. This belongs in the CI egress allowlist below, not in Defender. |

Note: the legacy Graph `tiIndicators` API is being removed by April 2026. Use the MDE Indicators API on `api.securitycenter.microsoft.com`.

`awqhnjewqjkl.icu` was added on 2026-08-06. It had been sitting in an ingested source file since intake while no rule and no indicator list referenced it — worth stating because it shows the failure mode: ingesting threat intel creates the *appearance* of coverage. The playbook now requires diffing each new source file against the deployed rules and this table, and recording the diff.

**Independent of Microsoft entirely.** These need no approval in this packet and cover the chain at points Defender cannot reach:

```bash
npm config set ignore-scripts true      # developer machines
npm ci --ignore-scripts                 # CI, always; never `npm install`
```

This kills the primary execution chain outright. Pilot it — it breaks packages with legitimate native build steps. It does **nothing** against the `.claude`/`.vscode` autostart path. Pair with:

- **A package-manager-native release-age gate — the highest value-per-effort item in this document.** Every malicious version in this campaign was unpublished within hours of publication, so a 24–72 hour hold makes the entire 2 h 40 m publish window unreachable: no rule, no hash, no indicator required.

  | Tool | Setting | Minimum version |
  |---|---|---|
  | npm | `min-release-age` | 11.10 |
  | pnpm | `minimumReleaseAge` | 10.16 |
  | Yarn | `npmMinimalAgeGate` | 4.10 |
  | Bun | `minimumReleaseAge` | 1.3 |
  | Dependabot | `cooldown` | n/a (config block) |

  This is a config flag, not a project. It does not replace a registry proxy — it gives no fetch record, and no protection against a malicious version that stays published — but it is available this week rather than next quarter.
- **An egress allowlist on build agents.** The dropper carries no payload: it fetches Bun from `github.com/oven-sh/bun/releases/download/bun-v1.3.13/` and stage 2 only executes under Bun. An allowlist that routes release binaries through a controlled mirror **stops the chain at its first hop** — stage 2 never runs and no credential is ever read. Strictly better than blocking C2: one origin instead of 75 RPC endpoints plus two fallback channels, and it acts before collection rather than after.
- **A release-tooling review gate.** Commit `ee2681a` edited `scripts/release-publish.ts` to read `latestMajor` from the repository's own `package.json` instead of a protected CI variable — which is how a malicious major published as `latest` through a legitimate, signed pipeline. Flag any diff that relocates a version, channel or `latest`-tag decision from CI configuration into repository-controlled state. This applies to us as a publisher, not only as a consumer, and it is the only control in this document that acts *before* a malicious package exists.
- **Remove passwordless `sudo` from the self-hosted runner service accounts.** That is what makes the `/proc/<Runner.Worker>/mem` secret scrape possible, and removing it is the durable fix; the detection rule is the fallback.
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

### GAP — The malware declines to run on some hosts, and those hosts read as clean

CHAINDROP reads the `LANG` environment variable and exits without executing if it indicates a Russian locale. On such a host the dropper is on disk and would have executed under any other locale, but **every behavioral rule returns nothing** — no Bun spawn, no loader execution, no C2 contact, no exfil artifact. Only the file-write rules fire: `payload-hash`, `agent-hook-drop`, and the new `token-monitor`.

This is not a curiosity; it is the general shape of the problem. A rule set weighted towards behavior has a false-negative surface exactly equal to the malware's own evasion logic, and that surface grows with each variant. Two consequences for how this rollout should be read:

- **Enumerate estate locales before reporting a behavioral zero as clean.** This is cheap and has not been done.
- **File and hash telemetry stays the primary surface** wherever the payload has a known hash, because that surface does not care whether the code ran. It is also the reason `payload-hash` is the only rule armed at `isolate-full` on a file event.

### GAP — The three new rules have no proof-of-concept coverage yet

Appendix E's 30-query library was built against the original six rules. The rules added on 2026-08-06 have **no shape proof, no baseline query and no coverage query**, which means their plumbing is unverified in exactly the way the library exists to prevent. Two of them have known telemetry dependencies that a shape proof would settle:

| New rule | Unverified dependency |
|---|---|
| `npm-shaihulud-bun-fetch` | Needs `RemoteUrl`, i.e. Network Protection — the same dependency that may make `c2-contact` dead on arrival. `poc/34` answers this for both; it has not been run. |
| `npm-shaihulud-token-monitor` | Its quarantine action needs a populated `SHA1` on the matched rows, the same failure mode `coverage/07` and `poc/33` were written for. Without it the rule alerts and does not quarantine, which reads as handled. |
| `npm-shaihulud-runner-mem-scrape` | Needs a baseline on the CI device group before arming, and the correct device-group name from `coverage/02`. |

**Do not record the three new rules as coverage until their shape proofs exist and pass.** They are detection surface on paper.

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
| `npm-shaihulud-token-monitor` *(new)* | high | **quarantine-only** | **NO** | quarantine file, collect package — **device stays online** |
| `npm-shaihulud-bun-fetch` *(new)* | medium | isolate-selective | **NO** | defined and validated, deliberately not armed |
| `npm-shaihulud-runner-mem-scrape` *(new)* | high | **isolate-full** | **NO** | defined and validated, deliberately not armed — **and must be `--scope`d to the CI device group** |

**Approval 3's blast radius did not change on 2026-08-06.** The three new rules add detection surface only; all three are unarmed in file, so no additional automated action becomes possible under this approval. Arming any of them is a later, separately reviewed change.

Five judgment calls worth a reviewer's attention:

1. **`agent-hook-drop` is quarantine-only, not isolation.** It is the one rule that can fire *before* compromise — the hook is written but has not necessarily executed. Removing the trigger and leaving the developer working is strictly better than isolating them.
2. **`bun-from-node` and `bun-fetch` are unarmed for the same reason.** They are the two medium-confidence rules, and they trip on the same population: a toolchain that legitimately drives Bun from a node script, or installs Bun through one. Isolation would take that developer offline for doing nothing wrong. Baseline both for a full cycle, then flip `armed` in a reviewed change.
3. **`token-monitor` is the one new rule that should be armed soon, and it is quarantine-only.** An *alert* on this rule does not disarm the watchdog, and the watchdog fires the payload when a stolen token is revoked — so between the alert and a human reading it, an unrelated routine credential rotation can trigger re-exfiltration. Quarantining the script closes that window at machine speed and takes nobody offline. It is unarmed today only because it has never run against this tenant. There is no legitimate file called `gh-token-monitor.sh`, so the expected benign rate is zero; one baseline cycle should be enough. **Note that quarantine removes the script but not the systemd unit or launchd plist** — §8 step 1 still runs by hand.
4. **`runner-mem-scrape` must be scoped, and arming it is a change-control decision, not a detection decision.** Its target is a shared build runner, so `isolate-full` takes out every pipeline on that host, not one developer. That may still be right — a runner that has read `/proc/<Runner.Worker>/mem` has already surrendered every secret it handled — but it needs the CI owners' sign-off. Deploy with `--scope` on the self-hosted-runner device group; on a developer workstation, `python3` touching `/proc` has benign explanations (profilers, debuggers) that do not exist on a build agent, so tenant-wide deployment turns a high-signal rule into noise.
5. **No file quarantine on process-event rules.** `stopAndQuarantineFiles` keys on the file the query returns. On a process rule that file is the interpreter — `node.exe` or `bun.exe`. Quarantining it bricks the toolchain and does nothing to the payload, which is a script. File actions attach only to file-event rules, where the returned hash is the malicious artifact.

### Validation without isolating a real developer

**Do not test an armed rule on someone's working machine.**

`github_conf/detections/kql/poc/` contains one shape proof per rule, built specifically for this. Each takes the deployed rule and changes **only** the malicious-specific predicate, substituting a benign marker while keeping the table, joins, `project` list and entity columns identical. Most of them need **no trigger at all** — they run against existing telemetry and return a computed `PASS` / `WARN` / `FAIL` verdict:

```bash
python3 scripts/ioc/run_kql_poc.py --run --group poc
```

Read the verdicts literally. A `FAIL` means the rule cannot fire as deployed, and should not be recorded as coverage or armed. The runner exits `3` if any shape proof fails.

Where a trigger is genuinely needed:

1. Use a dedicated, expendable, onboarded test device — not a laptop in use, not a CI runner.
2. Confirm the rule is unarmed: `deploy_detection_rules.py --kill-switch-status`, and `--disarm --apply` if it is not.
3. Follow the Form B block in the relevant `poc/` file, then confirm the alert arrived with `poc/36`.
4. Log the test. A synthetic artifact later found in a backlog sweep and worked as a real infection costs an IR cycle.

Two of the triggers are genuine rule matches and cannot be made otherwise: `poc/31` runs `node setup.mjs`, which is a literal match for `npm-shaihulud-loader-exec` (armed, selective isolation), and `poc/33` writes `.vscode/setup.mjs`, which matches `npm-shaihulud-agent-hook-drop` (armed, quarantine only — device stays online). Both are documented as such in the files.

`poc/33` also checks the thing most likely to be missed: `stopAndQuarantineFiles` needs a populated `SHA1`. If `SHA1` is empty on the matched rows, the alert still fires and the file is **not** quarantined — a failure that reads as "handled". `coverage/07` measures that coverage per platform before anything is armed.

### Guardrails already enforced by the deployer

Validation runs locally and fails closed before any network call:

- Only **verified** automated-action types accepted. `blockFiles`, `allowFiles`, `disableUsers`, `forceUserPasswordResets`, `markUsersAsCompromised` and the six email actions are **rejected** — their nested column-property names are not verified against the Microsoft reference, and guessing risks a wrong-shaped payload that a future schema change silently reinterprets.
- Every action's target column must actually be projected by the query. Catches the silent no-op where an action names a column the query never returns.
- Disruptive action armed on a non-`high`-severity rule is an error unless explicitly forced.
- `isEnabled` and `schedule.period` (deprecated) are rejected.
- Missing `Timestamp` / `ReportId` is rejected — the rule would fail at create time.
- `ago()` lookback is checked against `schedule.frequency`. A longer window re-alerts on the same event every run; a shorter one drops events between runs.

Current state: **9/9 rules validate clean** (re-run 2026-08-06 after the three additions). Validation is a statement about payload shape, not about telemetry: the three new rules pass the validator and still have no shape proof. Exit codes: 0 ok, 1 error, 3 missing role, 4 validation failed.

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

1. **Remove the token-revocation watchdog before you revoke anything.** *(New 2026-08-06. This step is ahead of rotation deliberately — read it before acting on step 2.)*

   The payload installs a watchdog that polls `https://api.github.com/user` every 60 seconds for 24 hours and **executes the payload when the token stops authenticating**. Revocation is its trigger condition, not its remedy: it responds by re-collecting and re-exfiltrating from whatever credentials are still live on the host. It also survives deleting `setup.mjs`, `math_init.js`, `.claude/` and `.vscode/` — none of those paths contain it — so a host cleaned by step 4 alone is still armed.

   ```bash
   # Linux
   systemctl --user disable --now gh-token-monitor.service 2>/dev/null
   rm -f  ~/.local/bin/gh-token-monitor.sh
   rm -rf ~/.config/gh-token-monitor/
   rm -f  ~/.config/systemd/user/gh-token-monitor.service
   systemctl --user daemon-reload

   # macOS
   launchctl bootout gui/$(id -u)/com.user.gh-token-monitor 2>/dev/null
   rm -f  ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
   rm -f  ~/.local/bin/gh-token-monitor.sh
   rm -rf ~/.config/gh-token-monitor/

   # both — confirm nothing survives
   pgrep -af gh-token-monitor
   ```

   `kql/ir/52` (persistence sweep) finds it across the estate. **This does not reverse "rotate before eradicate"** — the payload still exfiltrates first, so a full clean-up before rotation still destroys evidence while credentials stay live. The order is: *remove the watchdog* → *rotate* → *eradicate the rest*. It is a carve-out for the one artifact whose removal must precede rotation. If the device is fully isolated the watchdog cannot observe the revocation, but do not rely on that: `selective` isolation and any pre-isolation window both leave it live.

2. **Rotate credentials before eradication, and scope it wider than GitHub and npm.** The payload exfiltrates first, so eradicating first just means the attacker keeps working tokens. The collector matches 300+ patterns across ~140 hotspot paths. Revoke, for that user context:
   - npm publish tokens — **especially any with `bypass_2fa: true`**, which the collector explicitly prefers — GitHub PATs, GitHub Actions tokens, JWT and session tokens
   - **AI tooling credentials**, new in this campaign and present on this estate's workstations: `.claude/credentials.json`, `.codex/auth.json`, `.cursor/credentials.json`, `.openai/auth.json`, `.anthropic/auth.json`, `.gemini/.env`
   - cloud provider keys (AWS/GCP/Azure/Alibaba), **plus anything reachable from IMDSv2 or ECS task metadata on that host**. Check CloudTrail for `sts:GetCallerIdentity`, `secretsmanager:ListSecrets`, `secretsmanager:GetSecretValue` and `ssm:GetParameters` from the harvested principal **across all 16 regions** — the collector sweeps regions, so a single-region check under-scopes
   - HashiCorp Vault tokens (Kubernetes and IAM auth), SSH private keys, Kubernetes service-account tokens, any kubeconfig on the host
   - anything exported in the shell environment

   **If the device contacted `npm-cache.com`, scope it as arbitrary code execution, not credential theft.** The exfil channel is bidirectional — a response containing a `code` field is passed to `eval()`. Rotation scope is everything reachable from that host.

   **If the device is one of the six self-hosted runners,** rotate **every secret any workflow on that runner consumed in the window**, not just the triggering repository's — including org and environment secrets. The memory scrape reads masked values out of heap, so secrets the compromised step never referenced are also disclosed. Then rotate the runner registration token and re-provision the host: a self-hosted runner that has executed attacker code cannot be cleaned in place.
3. **Capture before remediating.** The file and its parent directory. The investigation package is collected automatically on every armed rule.
4. **Search the working tree** for `setup.mjs`, `math_init.js`, `Math_Symbol.js`, `format-results.txt`, `.claude/`, `.vscode/`, `.github/workflows/codeql_analysis.yml`. Match `setup.mjs` **by hash** where possible — there are two malicious variants (29,918 B and 11,017 B) and legitimate `setup.mjs` files exist. Also check the temp directory for `bun-dl-*` staging directories and `tmp.dpkg_<pid>.lock` beacons.
5. **Check the GitHub side.** Branch `dependabot/github_actions/format/setup-formatter`; commit message `chore: update config`; forged trailer `Co-authored-by: claude <claude@users.noreply.github.com>`; workflow author `github-advanced-security[bot]`; new repos described `Shai-Hulud: Here We Go Again` or named from Dune vocabulary (sardaukar, fremen, atreides); staging repos holding `results-*.json`. **Delete any `format-results` Actions artifact — it contains the stolen credentials.** Two additions:
   - **Enumerate every branch, not just the default.** Where a GitHub App token is stolen the worm commits to up to 50 branches per accessible repository, so a default-branch check reads a compromised repository as clean.
   - **Search the primitive, not the filename.** Two exfil-workflow variants are documented: `codeql_analysis.yml`, and a workflow named `Run Copilot` on `push`. Both write `${{ toJSON(secrets) }}` to a file and upload it. Grep every workflow added or modified by a non-human identity for `toJSON(secrets)`.
6. **Identify the delivering package.** `python3 scripts/ioc/match_npm_ioc.py --target sleepnumberinc` — exit code 2 means an exact match.
7. **Do not simply delete files.** Check `.claude/` and `.vscode/` for the autostart hook, which re-executes with no npm involvement. The two sets cross-reference each other, so removing one leaves the other live.
8. **Release the device** only after eradication and rotation are both confirmed — and after `pgrep -af gh-token-monitor` returns nothing.

---

## Appendix A — Detection rule queries (9)

Deployable as-is. For the step-0 backlog sweep, change `ago(1h)` to `ago(30d)`.

Each query's `ago()` window matches its `schedule.frequency` of `PT1H` (hourly) by design. Every query projects `Timestamp` and `ReportId` — required by the API — plus every column named by an entity mapping or an automated action.

**A1–A6 are the six rules covered by Approval 3 and already validated against the tenant. A7–A9 were added on 2026-08-06 from the CHAINDROP analysis, are `armed: false` in the file, and have never run here** — see §7 "The three new rules have no proof-of-concept coverage yet" before treating them as coverage.

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

### A7. `npm-shaihulud-token-monitor` — high — quarantine-only (**new 2026-08-06, UNARMED**)

The token-revocation watchdog. It is the only artifact that survives deleting `setup.mjs`, `math_init.js`, `.claude/` and `.vscode/`, so a host cleaned on that basis is still armed. There is no legitimate `gh-token-monitor.sh`, so the expected benign rate is zero and this is the one new rule that should be armed quickly — an *alert* does not disarm a watchdog, and a routine credential rotation between the alert and a human reading it re-triggers exfiltration.

```kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("gh-token-monitor.sh","gh-token-monitor.service",
                      "com.user.gh-token-monitor.plist","com.user.gh-token-monitor")
     or FolderPath has_any ("\\gh-token-monitor","/gh-token-monitor")
| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath, SHA256, SHA1,
          ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain,
          InitiatingProcessAccountSid
| limit 1000
```

MITRE: Persistence T1543, Credential Access T1552

**Caveat:** quarantine removes the *script* but not the systemd unit or the launchd plist. §8 step 1 still runs by hand. `stopAndQuarantineFiles` also needs `SHA1` populated on the matching rows — unverified on this tenant for `DeviceFileEvents`, which is why the rule is held unarmed.

### A8. `npm-shaihulud-bun-fetch` — medium — isolate-selective (**new 2026-08-06, UNARMED**)

The dropper carries no payload: it fetches a Bun release archive from the GitHub release CDN, and stage 2 only executes under Bun. This is the **earliest network event in the chain** — before any credential is read, where A5 fires only after collection has completed. One origin, no on-chain indirection, no 75-endpoint fallback list. The Bun version is deliberately left out of the predicate so a version bump does not blind the rule.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteUrl has "oven-sh/bun/releases/download"
| where InitiatingProcessFileName in~ ("node","node.exe","npm","npm.exe","npm-cli.js",
                                      "pnpm","yarn","bun","bun.exe","bunx")
| project Timestamp, ReportId, DeviceId, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName,
          InitiatingProcessAccountDomain, InitiatingProcessAccountSid
| limit 1000
```

MITRE: Command and Control T1105, Defense Evasion T1218

**Caveat:** same `RemoteUrl` dependency as A5 — dead without Network Protection in block or audit mode. Unarmed for the same reason as A3: a developer running a documented Bun install through a build script matches, and the only discriminator is the initiating process.

### A9. `npm-shaihulud-runner-mem-scrape` — high — isolate-full (**new 2026-08-06, UNARMED**)

`sudo python3` reading `/proc/<Runner.Worker pid>/mem` and grepping for `"isSecret":true`. This defeats masked-secret hygiene entirely — a secret never written to a log or a file is still in the runner process's heap — and it takes every secret the runner handled during the job, not only those the compromised step referenced. It writes no file and opens no connection, so A1, A5 and A6 are all blind to it.

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("python","python3","python.exe","python3.exe")
| where ProcessCommandLine matches regex @"/proc/[0-9]+/mem"
     or ProcessCommandLine has_any ("Runner.Worker","isSecret")
     or (InitiatingProcessFileName in~ ("sudo","sh","bash","dash")
         and ProcessCommandLine has "/proc/")
| project Timestamp, ReportId, DeviceId, DeviceName, AccountName, AccountDomain, AccountSid,
          FileName, FolderPath, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath
| limit 1000
```

MITRE: Credential Access T1003.007, Collection T1005

**Caveats:** deploy **scoped to the CI device group via `--scope`, never tenant-wide** — the third predicate (a shell-initiated python touching `/proc/`) is the weakest of the three and will produce noise on general-purpose hosts. Arming is a change-control decision, not a detection one: isolating a shared runner takes out every pipeline on that host. That may still be correct, but it needs the CI owners' sign-off.

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

Full bundle: `github_conf/ioc/shai_hulud_2026_08.json`. Per-source assertions, kept separate so a claim can be attributed and contradicted: `github_conf/ioc/chaindrop_elastic_2026_08.json`, `github_conf/ioc/chaindrop_stepsecurity_2026_08.json`. Arbitration rules and the open Tier 0 escalation: `docs/playbooks/supply-chain-hunt-ttp.md` §1.1–§1.3.

### Payload SHA-256

| Hash | Component | Size |
|---|---|---|
| `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | `math_init.js` / `Math_Symbol.js` payload (stage 2) | 727,680 B |
| `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | `setup.mjs` loader — **variant 2** | 11,017 B |
| `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | `setup.mjs` loader — **variant 1** | 29,918 B |
| `927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f` | `.vscode/tasks.json` autostart hook | |
| `14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128` | `.claude/settings.json` autostart hook | |
| `3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7` | exfil workflow (see the variant note below) | |
| `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7` | GitHub Actions runner memory scraper | |

`54dc7ea5…` was originally recorded as a "payload variant observed in the internal hunt window"; StepSecurity identifies it as the first-stage `setup.mjs`, which is why there are two loader hashes rather than one. **Match `setup.mjs` by hash, not by name** — legitimate `setup.mjs` files exist, and there are two malicious ones.

**Two exfil-workflow variants are documented,** not one: `.github/workflows/codeql_analysis.yml` attributed to `github-advanced-security[bot]`, and a workflow named `Run Copilot` triggered on `push`. Both write `${{ toJSON(secrets) }}` to a file and upload it as an artifact. Hunt the primitive, not the filename.

### Network

| Value | Classification | Indicator action |
|---|---|---|
| `npm-cache.com`, `js-mirror.com`, `pypi-get.com`, `awqhnjewqjkl.icu` | attacker-controlled | `Block` |
| `eth-mainnet.nodereal.io`, `go.getblock.io`, `eth.llamarpc.com` | legitimate RPC, abused | `Audit` only |
| `github.com/oven-sh/bun/releases/download/…` | legitimate Bun CDN, abused as the dropper's first hop | **do not create an indicator** — blocking it breaks legitimate Bun installs; detect via A8 instead |
| `104.21.35.216` | Cloudflare shared address | **do not create an indicator** |
| URL path `/router` | C2 endpoint | pivot |
| Contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103`, selector `0x53ed5143` | on-chain C2 resolution | pivot |

`awqhnjewqjkl.icu` was present in an ingested source file while every rule and every indicator list omitted it, for an unknown period. **The three RPC hostnames are telemetry, not a chokepoint:** the on-chain resolver tries **75 endpoints in sequence**, so blocking three changes nothing about whether C2 resolves. The exfil channel is bidirectional — a response containing a `code` field reaches `eval()` — so a contacted host is scoped as arbitrary code execution.

### Dropped files

`math_init.js`, `Math_Symbol.js`, `setup.mjs`, `format-results.txt`, `/tmp/tmp.dpkg_<pid>.lock` (observed: `tmp.dpkg_14527.lock`), `bun-dl-*` staging directories from `mkdtemp('/tmp/bun-dl-')`, `.vscode/tasks.json`, `.vscode/setup.mjs`, `.claude/math_init.js`, `.claude/settings.json`, `.claude/setup.mjs`, `.github/workflows/codeql_analysis.yml`, `results-*.json` in attacker staging repositories

### Persistence paths

`LaunchAgents`, `.config/systemd/user`, `.local/bin`, `.claude`, `.vscode`

Token-revocation watchdog — the artifact set that survives cleaning the paths above:

| Artifact | Platform |
|---|---|
| `~/.local/bin/gh-token-monitor.sh` | both |
| `~/.config/gh-token-monitor/` | both |
| `gh-token-monitor.service` (user unit) | Linux |
| `com.user.gh-token-monitor` (launchd label / plist) | macOS |

### Credential paths, AI tooling

New in this campaign and present on this estate's workstations: `.claude/credentials.json`, `.codex/auth.json`, `.cursor/credentials.json`, `.openai/auth.json`, `.anthropic/auth.json`, `.gemini/.env`. The collector matches 300+ patterns across ~140 hotspot paths; these are the ones a standard rotation runbook omits.

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
| 30-query proof-of-concept KQL library — coverage, backlog, rules, shape proofs, baselines, IR, prevention | `github_conf/detections/kql/` (Appendix E) |
| PoC runner — lints every query with the repo's own `lint_kql`, refuses to send parameterized IR queries with placeholders intact | `scripts/ioc/run_kql_poc.py` |

**Requires tenant access — cannot be completed from this repo:**

| # | Item | Blocks | Effort |
|---|---|---|---|
| 1 | Create the two GitHub environments (`defender-prod` with a required reviewer, `defender-validate`) and set `GRAPH_TENANT_ID` / `GRAPH_CLIENT_ID` as environment variables | Any workflow run | minutes |
| 2 | Enumerate Defender device groups and pick the pilot group name — **query written**, run `kql/coverage/02` and `kql/coverage/03` | Step 4 pilot | minutes |
| 3 | Confirm MDE device-isolation support on macOS and Linux. `kql/coverage/07` measures whether the *quarantine* action has a target per platform; isolation support itself is a product-capability question the tables cannot answer | Truthful coverage claims | investigation |
| 4 | Verify Network Protection coverage across the estate — **queries written**, run `kql/coverage/04`, `kql/coverage/05` and `kql/poc/34` | Rules A5 and **A8** returning meaningful results | minutes to run, then remediation |

**Added 2026-08-06 — nothing below is written yet:**

| # | Item | Blocks | Effort |
|---|---|---|---|
| 5 | Shape proofs for A7, A8 and A9. No `poc/` file exists for any of them, so the library covers 6 of 9 rules | Recording the three new rules as coverage at all | hours |
| 6 | Confirm A7's quarantine has a target — `stopAndQuarantineFiles` needs `SHA1` populated on the matching `DeviceFileEvents` rows. `coverage/07` measures this generally; A7 needs it confirmed for its own filenames | Arming A7, which is the new rule most worth arming | minutes once `coverage/07` runs |
| 7 | Enumerate `LANG` / locale across the estate. The payload declines to run under a Russian locale, and those hosts read as clean on every behavioral rule — only A1, A4 and A7 (file/hash) still fire | Knowing the size of the behavioral blind spot | minutes to run |
| 8 | Egress allowlist on build agents. Stops the chain at its first hop and needs no Microsoft approval — but it is a network-team change, not a security-team one | Nothing; independent prevention | days, cross-team |
| 9 | Roll out a package-manager-native release-age gate (§6 Step 5 table). Needs a version floor per manager and a lockfile-refresh window | Nothing; independent prevention | days |
| 10 | Remove passwordless `sudo` from the self-hosted runner service accounts. The memory scrape needs root; without it A9's whole class is prevented rather than detected | Nothing; independent prevention. Verify no build step depends on it first | hours, needs CI-owner sign-off |

---

## Appendix E — Proof-of-concept KQL library

30 query files in `github_conf/detections/kql/`, plus a runner. **All of them run today** with the already-granted `ThreatHunting.Read.All`; none needs `CustomDetection.ReadWrite.All`. Nothing here can deploy a rule or arm a response action.

**The library covers 6 of the 9 rules.** It was built against the original six and has not been extended for A7, A8 or A9 — no `detections/`, `backlog/` or `poc/` file exists for any of them. The backlog sweep in Step 0 therefore does not look back for the watchdog, the Bun fetch or the memory scrape at all. Appendix D items 5–7 are what closes this.

```bash
python3 scripts/ioc/run_kql_poc.py                       # lint + list, no tenant contact
python3 scripts/ioc/run_kql_poc.py --run                 # execute everything runnable
python3 scripts/ioc/run_kql_poc.py --run --group coverage
python3 scripts/ioc/run_kql_poc.py --run --json exports/kql-poc-results.json
```

### Why the library is ordered the way it is

A detection rule that deploys cleanly and returns nothing looks identical to a clean estate. So: **prove the telemetry exists before believing any zero, and prove the action has a target before arming it.**

| Group | Files | What it establishes |
|---|---|---|
| `coverage/` | 7 | Onboarding by platform · **device groups for `--scope`** · CI-runner group · Network Protection configured · Network Protection actually firing · is node/npm visible at all · **is `SHA1` populated** |
| `backlog/` | 2 | The original six signals over the full 30-day window (rules are not retroactive) · which devices hold the adjacent package trees |
| `detections/` | 6 | Six of the nine rule queries, verbatim from `npm_supply_chain_rules.json`, each with its backlog variant noted |
| `poc/` | 7 | One shape proof per *original* rule with a computed `PASS`/`WARN`/`FAIL` verdict · alert and entity-mapping verification |
| `baseline/` | 3 | **Arming gate for `bun-from-node`** · registry tarball fetches · install-window baseline |
| `ir/` | 4 | Device timeline · credential-rotation scope · persistence sweep · spread check |
| `prevention/` | 1 | Are the Layer 3 indicator blocks firing, or merely existing |

### Controls in the runner

- Every query is linted with the repo's own `lint_kql()` **before any credential is touched**. All 30 pass with zero warnings. The linter rejects constructs that return a plausible wrong answer rather than an error: the `$`-prefixed table macro (unavailable via Graph), `order by ... asc | take N` (keeps the oldest rows, discards the recent tail), a missing time predicate, a missing row limit.
- The four `ir/` queries carry placeholder device names. The runner **refuses to send them** unless `--params device=<name>` supplies a real value. Sending one unedited would query for a device called `REPLACE-WITH-DEVICE-NAME` and report zero rows, which reads as "device is clean". A `--params` key matching no placeholder is an error, not a silent no-op.
- `require_role("runHuntingQuery")` runs before the first query. An app-only token missing the role returns an empty result set indistinguishable from a clean estate.
- Advanced hunting is throttled to 15 requests/minute; the client self-paces rather than collecting 429s that a careless caller reads as zero results.
- Exit codes: `0` clean · `1` execution error · `2` lint failure · `3` at least one shape proof returned `FAIL`.

### Honest limits

- **No query here has been executed.** There are no hunting credentials in this repository's environment. Each query is linted and reviewed against the Microsoft table schemas, but expect to correct a column name or two on first run. That is the acceptable failure mode: a wrong column name errors loudly instead of returning a wrong answer.
- **Automated action outcomes are not in advanced hunting.** Isolation and quarantine results live in the Action center and `GET https://api.securitycenter.microsoft.com/api/machineactions`. `poc/36` *discovers* what `DeviceEvents` ActionTypes this tenant emits rather than asserting names that may not exist.
- **Indicator inventory is not queryable either.** `prevention/60` shows enforcement events; confirming which indicators exist needs `GET .../api/indicators`. An empty result is consistent with both "published, nothing tried to reach the C2" and "never published".

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
- `docs/playbooks/supply-chain-hunt-ttp.md` — hunt methodology; §1.1–§1.3 hold the source tiering, the arbitration table and the open Tier 0 escalation on the propagation-window close
- `github_conf/detections/npm_supply_chain_rules.json` — rules as code, source of truth (9 rules; 5 armed)
- `github_conf/detections/kql/` — 30-query proof-of-concept library (Appendix E), with `README.md` and `poc/README.md`
- `scripts/ioc/run_kql_poc.py` — lints and runs the library; read-only, no deployment capability
- `github_conf/ioc/shai_hulud_2026_08.json` — IOC bundle
- `github_conf/ioc/chaindrop_elastic_2026_08.json` — Elastic Security Labs assertions, one source per file
- `github_conf/ioc/chaindrop_stepsecurity_2026_08.json` — StepSecurity assertions, including the two `contradicts` entries that are unresolved
- `scripts/ioc/deploy_detection_rules.py` — deployer (dry-run by default)
- `.github/workflows/deploy-detection-rules.yml` — deploy workflow, two-person control
- `scripts/ioc/match_npm_ioc.py` — Layer 1 inventory matcher
- `exports/ioc-match-shai-hulud.json` — Layer 1 result data
- `exports/kill-switch-audit.jsonl` — arming audit trail
