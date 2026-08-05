# Supply-Chain Compromise Hunt — Tactics, Techniques & Process (TTP)

**Playbook ID:** `ttp-supply-chain-hunt`
**Applies to:** registry-borne compromise of a package the estate consumes (npm, PyPI, crates, RubyGems, Maven, NuGet, Go)
**Scope:** all GitHub organizations registered in AuditGithub — currently `sleepnumber` (Digital),
`sleepnumberlabs`, `SleepNumberInc`
**Surfaces:** dependency trees · GitHub code search · GitHub Actions CI · self-hosted runners ·
endpoints & identity via Microsoft Graph / Defender XDR · attacker infrastructure
**Reference run:** Mini Shai-Hulud (`keyv` / `cacheable`), 2026-08-04 — worked example throughout
**Status:** validated against the reference run
**Owner:** Security Engineering

---

## 0. Doctrine — read this before running anything

Five rules that determine whether the output is evidence or theatre.

### 0.1 A zero is only meaningful if the query could have found the thing

Every negative result must be paired with a **control** — the same query logic, widened until it
returns non-zero. Without a control, "0 hits" is indistinguishable from a broken query, an
unindexed org, or a missing permission.

> **Reference run, control 1.** The in-window install query returned 0. The same logic across the
> full two days returned **34 hourly buckets** of real install activity. The detection worked; the
> window was genuinely empty.
>
> **Reference run, control 2.** The `node_modules` package-directory query returned 0 for the
> affected family. The same query without the family filter returned **266,104 events / 1,850
> devices / 10,152 distinct package directories**. Defender does record per-package writes, so the
> absence was a real absence.

### 0.2 Registry ground truth beats every vendor advisory

Vendor advisories are snapshots taken during a live incident. They disagree, they lag, and some are
simply wrong. The package registry is the only authority on what was actually published.

**Definition of a malicious version** — treat a `name@version` as malicious only if it was
**published inside the attack window AND subsequently unpublished / withdrawn**. Both conditions.
Anything else is an allegation pending verification.

### 0.3 Lockfiles are authoritative; code search is not

GitHub code search **does not index files over 384 KB**. Every lockfile in the Digital org is
415 KB – 950 KB, so lockfiles are structurally invisible to code search. Parse them directly.
A code-search-only exposure check on a large repo returns a false negative by construction.

Corollary: the SBOM/dependency-graph API is unusable where the graph is not enabled — 8 of 9
Digital repos returned **HTTP 404** on `/dependency-graph/sbom` during the reference run. A zero
from a 404-ing endpoint is not a zero.

### 0.4 Never `order by … asc | take N` in a hunt query

Ascending sort with a row cap truncates the **recent** tail — exactly the data you need. This
silently hid all Aug 4–5 activity behind 92 older rows during the reference run. Always sort
descending, or bucket and aggregate.

### 0.5 Absence of misuse in retained logs is not proof of no misuse

Log retention windows are shorter than exposure windows. A credential exposed for five months and
"clean" across 30 days of retained sign-ins is still a credential that must be rotated. Scope your
confidence to your retention.

---

## 1. Phase 1 — Intel acquisition and cross-source arbitration

**Objective:** produce one reconciled, registry-verified IoC and affected-version set before
touching the estate. Hunting against an unreconciled vendor list wastes the run.

### 1.1 Source registry

Sources are tiered by evidentiary weight. **Tier 0 decides**; tiers 1–3 generate hypotheses.

#### Tier 0 — ground truth (authoritative, machine-queryable)

| Source | URL | Use |
|---|---|---|
| npm registry (packument) | `https://registry.npmjs.org/<package>` | Full version list, `time` map with publish timestamps, and — critically — versions present in `time` but absent from `versions` = **unpublished**. This is the malicious-version oracle. |
| npm registry (single version) | `https://registry.npmjs.org/<package>/<version>` | 404 on a version that appears in `time` confirms withdrawal. |
| PyPI JSON API | `https://pypi.org/pypi/<package>/json` | Same role for Python. |
| crates.io | `https://crates.io/api/v1/crates/<crate>` | Same role for Rust; check `yanked`. |
| RubyGems | `https://rubygems.org/api/v1/versions/<gem>.json` | Same role for Ruby. |
| OSV | `https://api.osv.dev/v1/query` · `https://osv.dev` | Cross-ecosystem vulnerability ranges, machine-readable. |
| GitHub Advisory Database | `https://github.com/advisories` · GraphQL `securityAdvisories` | GHSA IDs, affected ranges. |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Known-exploited status. Already cached by this platform at `.cache/kev.json`. |
| EPSS | `https://epss.cyentia.com/epss_scores-current.csv.gz` | Exploitation probability. Already cached at `.cache/epss.json`. |

#### Tier 1 — primary vendor research (the three required comparison sources)

| Source | URL |
|---|---|
| **Chainguard** | `https://www.chainguard.dev/unchained/the-keyv-and-cacheable-npm-supply-chain-attack-inside-the-mini-shai-hulud-campaign` |
| **Socket** — analysis | `https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain` |
| **Socket** — live campaign tracker | `https://socket.dev/supply-chain-attacks/keyv-and-cacheable-compromise` |
| **Phoenix Security** | `https://phoenix.security/mini-shai-hulud-keyv-cacheable-npm-supply-chain-worm/` |

#### Tier 2 — corroborating vendor research (use to break Tier 1 ties)

| Source | URL | Distinct contribution in the reference run |
|---|---|---|
| Wiz | `https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack` | Ethereum-smart-contract C2 resolution; IDE persistence via Claude Code hooks and VS Code `tasks.json`; prevalence data (~46% of measured environments) |
| Aikido | `https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack` | Confirmed the two-file payload shape and the dynamic C2 fallback |
| SafeDep | `https://safedep.io/keyv-npm-supply-chain-compromise/` | Largest confirmed footprint count: 2,234 poisoned versions / 444 package names |
| JFrog | `https://research.jfrog.com/post/shai-hulud-is-back-august/` | 428 packages / 1,700+ versions; **npm ≥ 12 does not run `preinstall` by default** — a material mitigating factor |
| Snyk | `https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/` | Exploit-maturity rating; provenance analysis |
| Cloudsmith | `https://cloudsmith.com/blog/keyv-and-cacheable-npm-packages-compromised-in-active-supply-chain-attack` | ~444 packages / ~2,236 malicious versions; registry-operator view |
| Kodem | `https://www.kodemsecurity.com/resources/keyv-supply-chain-attack-shai-hulud-npm-worm-affected-versions-iocs-and-first-hour-response-runbook` | Consolidated IoC list + first-hour runbook |

#### Tier 3 — press (timeline only, never IoCs)

`https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html` ·
`https://www.scworld.com/news/keyv-cacheable-npm-supply-chain-attack-hits-400-plus-packages`

**Excluded during the reference run:** `gbhackers.com` dated the compromise **2023** while citing a
source that says 2026. A source that contradicts its own citation is disqualified, not averaged in.

### 1.2 Arbitration procedure

For every claim — affected package, malicious version, timestamp, IoC hash, C2 indicator:

1. **Normalize** the claim to `(claim_type, subject, value)` so sources become comparable.
2. **Tabulate** which sources assert, deny, or omit it. Omission ≠ denial; record all three states.
3. **Classify:**
   - **Consensus** — all asserting sources agree, no denials. Accept; still verify against Tier 0.
   - **Disagreement** — sources conflict. **Escalate to Tier 0 and let the registry decide.**
   - **Single-source** — one source only. Mark `unverified`; hunt for it anyway (cheap), but never
     report it as established.
4. **Record the resolution and the loser.** A vendor that was wrong once is a calibration data
   point for the next incident. Do not quietly drop it.
5. **Hunt the union, report the arbitrated set.** Hunting is cheap and false negatives are
   expensive, so query for every claimed indicator. But the verdict cites only what Tier 0 confirms.

### 1.3 Reference run — the arbitration table

All tier-0 values below were produced by `src/threat_intel/registry_oracle.py` against the live npm
registry on 2026-08-05 and are reproducible with `RegistryOracle().derive_malicious_set(...)`.

| Claim | Chainguard | Socket | Phoenix | Others | Tier 0 registry | Resolution |
|---|---|---|---|---|---|---|
| `keyv@6.0.0` malicious | ✅ ~09:35Z | ✅ 09:35Z | ✅ | ✅ | ✅ **09:35:00.763Z**, unpublished | **Consensus, confirmed** |
| First malicious publish time | ~09:35Z | 09:35Z | — | Wiz ~09:00Z takeover | **`@keyv/mongo@6.0.0` at 09:31:03.692Z** | **Disagreement → registry wins.** The scoped `@keyv/*` packages went out **3 m 57 s before** the headline `keyv@6.0.0`, in a 26-second burst (`mongo` 09:31:03 → `mysql` :09 → `postgres` :14 → `sqlite` :24 → `valkey` :29 → `redis` 09:32:24). Every vendor anchored on the famous package and missed the true start. |
| **Last malicious publish time** | implied ~10:40Z | cacheable burst ends 10:14Z | — | — | **`@thiennq/docs-viewer@1.6.4` at 12:11:19.909Z** | **All sources under-ran the window.** See §1.5 — this is a correction to the reference run's own scoping. |
| `ecto@5.0.1` affected | ❌ **stated unaffected** | omitted | omitted | omitted | ✅ **published 10:28:01Z, unpublished** | **Disagreement → registry wins. Chainguard was wrong.** Had we trusted it, `ecto` would have been excluded from the hunt set. |
| `file-entry-cache` malicious version | omitted | ✅ **11.1.6** | ✅ | ✅ | ✅ **11.1.6**; 11.1.7 never existed | **Consensus on 11.1.6.** An earlier-snapshot artifact circulating `11.1.7` was refuted by the registry — 11.1.7 was never published at all. |
| Campaign footprint | "~400 to >2,200" | "868+ packages" | — | SafeDep 2,234 versions / 444 names · JFrog 428 / 1,700+ · Cloudsmith 444 / ~2,236 | not enumerable in one call | **Unresolvable during a live incident — by design.** Counts are snapshots of a spreading worm. Treat every number as a floor. See §1.4. |
| Exfil via GitHub dead-drop repos, description `Shai-Hulud: Here We Go Again.` | ✅ | ✅ | ✅ | Wiz ✅ | n/a | **Consensus, confirmed IoC.** |
| C2 resolved from an Ethereum smart contract | omitted | omitted | — | Wiz ✅ Aikido ✅ | n/a | **Tier 2 consensus.** Accepted; explains the absence of a static C2 host. |
| IDE persistence — Claude Code hooks, VS Code `tasks.json` | ✅ | ✅ | — | Wiz ✅ Snyk ✅ | n/a | **Consensus, confirmed IoC.** |
| `preinstall` blocked on npm ≥ 12 | omitted | omitted | omitted | **JFrog ✅** | verifiable per-host | **Single-source, high value.** Verify the npm major version on every builder — it may be the control that mattered. |
| Payload hash `9fc2570b…cf1bcc` (`Math_Symbol.js` / `math_init.js`) | — | ✅ | — | Kodem ✅ | n/a | **Consensus, confirmed IoC.** |
| Safe restore versions | `keyv@5.6.0`, `flat-cache@6.1.23`, `cache-manager@7.2.9`, `cacheable-request@13.0.19` | — | — | — | ✅ present in registry | **Accepted** as pin targets. |

**Scorecard from the reference run:** Chainguard 1 material error (`ecto`). Socket accurate on
versions, conservative on scope. Phoenix accurate but methodological rather than enumerative — its
contribution was the *detection-philosophy* argument (lifecycle-script delta rules catch this class;
CVE and signature controls have no detection surface for it), not an IoC list.

### 1.4 The scope-reconciliation trap — read this

Vendors converge on roughly **428–444 poisoned package names across ~1,700–2,236 versions**. A hunt
built only from the **seed** packages will under-scope.

> **Gap identified in the reference run.** The original hunt derived a rigorous, registry-verified
> set of **20 `name@version` pairs** — correct for every seed package, and the basis of a sound
> not-exposed verdict for those. But the campaign reached ~444 names. The 20-pair set was
> *precise*, not *complete*. The estate verdict held because the affected-family repos all resolve
> to pinned versions multiple majors below the compromised releases, which is a structural defence
> independent of list completeness — but the list was narrower than the campaign, and that must be
> stated rather than glossed.

**Mandatory step:** after seed reconciliation, expand to the full campaign name set (Tier 2
enumerations, deduplicated) and re-run Phase 3 against it. Log the delta between seed-set and
full-set coverage. Never report seed-set coverage as campaign coverage.

### 1.5 Derive the attack window from the registry, never from the advisories

**The window is an output of Phase 1, not an input to it.** Vendor advisories are written while the
campaign is still spreading, so their stated window is always a lower bound.

Procedure: run the tier-0 oracle across the candidate package set with a deliberately generous
bracket (days, not hours), then take the window as
`[min(malicious.published), max(malicious.published)]`. Re-derive it whenever the package set grows.

> **Reference run — correction to its own scoping.** Every report in `exports/` used
> **09:31Z – 10:40Z (69 minutes)**, derived from the keyv/cacheable publishes and the npm unpublish.
> The oracle, run across Jul 1 – Aug 31, returns 20 malicious specs bounded by:
>
> - **First:** `@keyv/mongo@6.0.0` at **2026-08-04T09:31:03.692Z**
> - **Last:** `@thiennq/docs-viewer@1.6.4` at **2026-08-04T12:11:19.909Z**
>
> The true window is **2 h 40 m**, not 69 minutes. `@thiennq/docs-viewer` `1.6.3` and `1.6.4` were
> published at **12:11:05.959Z** and **12:11:19.909Z** — about 91 minutes after the assumed close.
>
> **Consequence:** the endpoint install-activity hunt bounded its timeline at 12:00Z and stated
> "nothing installed again until after 12:00Z, by which time the malicious versions were
> unpublished." Both halves need qualifying — two malicious versions were published *after* 12:00Z,
> and 12:00–12:20Z was never examined for install activity.
>
> **Why the verdict still holds:** `@thiennq/docs-viewer` appears in no lockfile, manifest, or
> `node_modules` directory anywhere in the estate, so the extended window adds no exposure. But the
> reports' window claim was wrong, and a campaign that *had* touched a consumed package in that
> extra 91 minutes would have been missed. Re-run install-activity checks against the derived
> window, not the assumed one.

### 1.6 Exposure-mechanics refinement

Not every malicious version is reachable. Socket's semver analysis: nothing in a typical tree
declares `^6`, so a caret range on `keyv` v4/v5 **refuses** `keyv@6.0.0`. Only `npm i keyv@latest`
or an explicit `6` pin pulls it.

The versions that install **silently**, inside existing ranges:
`cacheable-request@13.0.20` · `cache-manager@7.2.10` · `@cacheable/utils@2.5.1`

**Prioritize these in Phase 3.** A major-version jump is loud and mostly self-blocking; an in-range
patch bump is the actual risk.

---

## 2. Phase 2 — Affected-family enumeration

**Objective:** reduce thousands of repos to the set that could possibly be affected, without
losing any.

1. Enumerate every repo in every registered org with `type=all`. **Reconcile the count against
   `GET /orgs/<org>` `public_repos` + `total_private_repos`.** A shortfall means invisible repos —
   record it as a coverage gap, do not silently proceed.
2. Select repos referencing any affected-family name (direct or transitive) in any manifest or
   lockfile.
3. Record, per repo: lockfile inventory, install commands in workflows, and self-hosted-runner use.

> **Reference run.** 2,799 repos queried (`SleepNumberInc` 2,284 + `sleepnumberlabs` 515) plus 9
> Digital → **153 affected-family repos**. `GET /orgs/sleepnumber` reported 2 public + 10 private
> = 12, but `type=all` returned 9. **3 private repos invisible** — token role is `member`, and a
> classic PAT scope cannot exceed the underlying role. Logged as a gap, never as a zero.

### Float-risk model

The only path into a build is an unpinned resolution landing on a malicious version during the
publish window. Classify each repo:

| Lockfile | Install command | Risk |
|---|---|---|
| present | `npm ci` | **none** — lockfile-strict, cannot float |
| present | `npm install` / `yarn install` | **low** — resolution pinned by the lockfile |
| absent | `npm install` / floating range | **HIGH** — the only real exposure path |

> **Reference run.** 153/153 affected-family repos had a committed lockfile. Zero repos combined a
> missing lockfile with a floating install command. Install commands: `npm ci` ×29,
> `npm install` ×8, `npm audit` ×7, `yarn install` ×2 — all lockfile-backed.

---

## 3. Phase 3 — Dependency-tree exposure

**Objective:** determine whether any malicious version is actually resolved anywhere.

**Method — parse committed lockfiles directly.** Authoritative. Not code search (§0.3), not the
SBOM API alone (404s), not `npm audit` (campaign artifacts and withdrawn versions are not modelled
like CVEs).

Formats: `package-lock.json` (v1/v2/v3), `yarn.lock` (classic + berry), `pnpm-lock.yaml`,
`poetry.lock`, `Cargo.lock`, `Gemfile.lock`, `go.sum`.

For each resolved package, compare against the arbitrated set from §1 — **both** the seed pairs and
the full campaign name set (§1.4). Report exact version *and* the gap to the malicious release,
because the gap is the protective factor worth stating.

**Cross-validate the parser.** Where the SBOM API *does* resolve, diff it against the parser output.

> **Reference run.** 10/10 Digital lockfiles parsed; 153/153 affected-family repos checked.
> **Zero malicious versions.** Present versions sat multiple majors below:
>
> | Package | Present | Malicious | Gap |
> |---|---|---|---|
> | `keyv` | 4.5.4 | 6.0.0 | 2 majors |
> | `file-entry-cache` | 5.0.1 / 6.0.1 | 11.1.6 | 5–6 majors |
> | `flat-cache` | 2.0.1 / 3.2.0 | 6.1.24 | 3–4 majors |
>
> All three were **transitive** eslint dev-toolchain dependencies, not direct. No `@keyv/*`,
> `@cacheable/*`, `cacheable`, `cacheable-request`, `cache-manager`, `ecto`, or
> `@thiennq/docs-viewer` anywhere in the estate. For `.com`, SBOM and parser agreed exactly on all
> three packages — parser cross-validated.

---

## 4. Phase 4 — CI/CD execution surface

**Objective:** determine whether the worm ever executed in a build.

1. **Enumerate runs** across the incident window plus a tail. Retry unresolved runs individually —
   never accept an aggregate "log unavailable."
2. **Content-scan every retrievable log** for IoC filenames, malicious `name@version` pairs, and
   bare family names.
3. **Isolate in-window runs** and check each for registry resolution. A run that performs no npm
   resolution cannot introduce an npm package.
4. **Verify every bare-name match.** Substring collisions are rampant.
5. **Determine runner topology from log paths** — ephemeral vs persistent is the single most
   important property.

> **Reference run.** 464 runs (`SleepNumberInc` + `sleepnumberlabs`) + 65 (Digital) = **529**.
> 440 + 65 logs scanned; 24 unretrievable, all outside the window, both affected-family ones
> resolved on retry. **12 in-window runs, 0 in an affected-family repo, 0 performing npm
> resolution.** Digital had **0 in-window runs at all**.
>
> **Zero IoCs.** All bare-name matches were false positives, verified individually:
> `safe.dir`**`ecto`**`ry`, `KeyV`ault resource IDs, a repo literally named `snip-key-vault-sync`,
> `vendor/gems/mongoid-6.4.8/lib/mongoid/cacheable.rb` (a **Ruby** gem, not the npm package),
> "Found bundled copilot CLI, skipping npm installation", and `apt` fetching `.deb` files matching
> `added `.
>
> **A query bug worth remembering:** the first install-detection query used `has_any(" ci ")` and
> missed real `npm ci` invocations because the command line *ends* with `ci`. Caught only when a
> manual pivot surfaced an `npm ci` the query had not returned. Use token-based matching:
> `has_any("install","ci","add","update","rebuild")`.

### Runner posture

| Fleet | Path signature | Persistence | Risk |
|---|---|---|---|
| GitHub-hosted | `/home/runner/work/...` | ephemeral | none |
| `sleepnumberlabs` (CodeBuild) | `/codebuild/output/src<N>/src/actions-runner/_work/...` | ephemeral, re-`git init` per job | none |
| `SleepNumberInc` self-hosted | `/shared/github/runner/devops-runner-<id>/<repo>/<repo>` | **shared & persistent** | **the one place an infection outlives the dependency tree** |

Persistent runners retain `node_modules` and filesystem state between jobs. They require host-level
inspection (Phase 5), not just log scanning.

**Expect `GET /orgs/<org>/actions/runners` → HTTP 403** without org admin or
`organization_self_hosted_runners:read`. Do not treat this as a dead end — resolve runner hostnames
from log paths and pivot to Defender (§5.4). The reference run closed this gap entirely from a
different data source.

---

## 5. Phase 5 — Endpoint and identity hunt (Microsoft Graph / Defender XDR)

**Objective:** determine whether the payload executed, persisted, or stole credentials on any host.

### 5.1 Access

`POST https://graph.microsoft.com/v1.0/security/runHuntingQuery` — app-only, `client_credentials`.

| Permission | Purpose | Required? |
|---|---|---|
| `ThreatHunting.Read.All` | KQL over all `Device*` and identity tables | **yes — the core capability** |
| `SecurityAlert.Read.All` | `GET /security/alerts_v2` | yes |
| `SecurityIncident.Read.All` | `GET /security/incidents` | yes |
| `AuditLog.Read.All` | sign-in / directory audit | **no — do not request.** `AADSignInEventsBeta`, `AADSpnSignInEventsBeta` and `IdentityLogonEvents` are reachable with `ThreatHunting.Read.All` alone and answer the same questions |
| `DeviceManagementManagedDevices.Read.All` | Intune inventory | **no.** `mobileDeviceManagementAuthority` is `None`; that inventory is empty |

**Do not confuse MDM authority with EDR onboarding.** They are separate control planes. macOS here
is Jamf-managed *and* Defender-onboarded — a mistake in the reference run's first draft cost a
wrongly-declared blind spot and a needless Jamf API request.

### 5.2 Establish coverage before believing any zero

Query `DeviceInfo` for onboarded counts by OS, then per-table event counts and reporting-device
counts for the window.

> **Reference run.** ~3,585 onboarded: Windows 11/10 **2,974** · Windows Server **192** · Linux
> **312** · macOS **106** · iOS 1. Live coverage confirmed: `DeviceProcessEvents` 18,736,696 /
> 3,330 devices · `DeviceFileEvents` 14,999,681 / 3,331 · `DeviceNetworkEvents` 17,714,665 / 3,333
> · `DeviceEvents` 9,981,314 / 3,334.

**Known structural blind spot:** Docker Desktop on macOS runs containers in a Linux VM that the
macOS Defender agent does not instrument. In-container processes are invisible; the host-side
`docker` invocation is captured. Account for this before concluding a process did not run.

### 5.3 The hunt set

Ten queries, each with a control. Adapt the indicator lists per incident.

1. **Payload files on disk** — `DeviceFileEvents`, IoC filenames and persistence artifacts
2. **Known-bad hashes** — `DeviceFileEvents` by `SHA256`
3. **C2 contact** — `DeviceNetworkEvents`, domains + IPs. *Include the blockchain-RPC hosts;* this
   campaign resolved C2 from an Ethereum contract, so `nodereal` / `getblock` / `llamarpc` traffic
   is itself an indicator
4. **Package-manager installs inside the window** — `DeviceProcessEvents`, token-matched (§4)
5. **Lifecycle-hook execution** — payload script names in `ProcessCommandLine`
6. **Persistence** — `LaunchAgents`, `.config/systemd/user`, `.local/bin`, **`.claude`**,
   **`.vscode`** (this campaign wrote Claude Code hooks and VS Code `tasks.json`)
7. **Affected-family `node_modules` directories written** — per-package granularity
8. **Alternate runtime installed or executed** — `bun` was the delivery mechanism here
9. **Credential-store reads** — `.npmrc`, `.git-credentials`, `.config/gh`, `.aws/credentials`,
   `.ssh`, Vault tokens, kubeconfig, by `node`/`npm`/`curl`/shell
10. **Alerts on any runner host or developer machine** in the window

### 5.4 Pivot: who actually ran the package manager

Build the exposure cohort from query 4, then check each identity individually for IoCs, C2, and
sign-in anomalies. This converts a tenant-wide zero into a per-identity zero, which is far stronger.

> **Reference run.** Six identities ran installs on Aug 4–5 — five named developers plus `root` on
> the six runner hosts. All 0 IoCs, 0 C2, US-only sign-ins, no impossible travel.
>
> **Runner gap closed via Defender**, not GitHub: hostnames `cxdkrprdapp12`–`17.comfort.com`
> resolved from CI log paths, all six Defender-onboarded and reporting 3,264–4,125 processes.
> Zero IoCs, zero C2, zero alerts.

### 5.5 The decisive question

Not "did we find the payload" but **"was there any opportunity for it to execute?"**

> **Reference run — the finding the whole verdict rests on.** Zero package-manager installs
> anywhere in the estate during the publish window. Last install **09:22:59Z**, **7 m 55 s** before
> the first malicious publish (`@keyv/mongo@6.0.0`, 09:31:03.692Z).
>
> ⚠️ **Qualify this claim.** The reports state "nothing installed again until after 12:00Z, by which
> time the versions were unpublished." Per §1.5 the true window closes at **12:11:19.909Z**, so two
> malicious versions were published *after* 12:00Z and the interval 12:00–12:20Z was never checked
> for install activity. Re-run against the derived window. The verdict survives only because the
> two late versions belong to `@thiennq/docs-viewer`, which the estate does not consume.
>
> The 2 h 40 m window fell at **04:31–07:11 CDT** — still before US working hours, but note this is
> a **circumstantial** protection, not a control. The structural protection was pinned lockfiles.

### 5.6 Graph / KQL API constraints — hard-won, encode them

| Constraint | Consequence |
|---|---|
| `GET /security/alerts_v2` **silently caps at 100 rows** with **no `@odata.nextLink`** | A paging loop terminates at 100 and you conclude an alert does not exist. Always narrow with `$filter`; never trust an unfiltered list |
| `title` is **not** `$filter`-able on `alerts_v2` | Filter on `severity` and `createdDateTime` instead |
| `$filter` values must be **URL-encoded** | An unencoded space raises `http.client.InvalidURL: URL can't contain control characters` |
| **`$table` is unsupported** in `runHuntingQuery` | Use `withsource=` on `union`, or split into per-table queries |
| `AADSpnSignInEventsBeta` has **no `UserAgent` column** | Use `AADSignInEventsBeta` (`AccountUpn`) for user sign-ins; SP sign-ins carry no UA there |
| `order by … asc \| take N` | Truncates the recent tail — see §0.4 |

### 5.7 Read the alert evidence array before dispositioning anything

> **Reference run — a real analytical failure.** A high-severity "possibly compromised service
> principal" alert was initially dismissed because the source IP was corporate Zscaler egress,
> "not an attacker range." **That reasoning was wrong** — Zscaler egress is shared, and an insider
> or a compromised internal host is indistinguishable from it at the IP level.
>
> The alert's own `evidence` array held the answer: `cloudLogonSessionEvidence.userAgent =
> "TruffleHog"`. The detector (`xdr_CredentialStuffingToolObserved`) had matched a self-identifying
> tool UA. The true finding — a live leaked Azure AD client secret discovered and verified by our
> own scanner — was in the payload all along.
>
> **Rule: never disposition a cloud alert on metadata alone. Pull the full alert object and read
> every evidence node** (`userEvidence`, `cloudLogonSessionEvidence`, `ipEvidence`,
> `cloudLogonRequestEvidence`). See `exports/sp-assessment-corp-functions-it-spend-tracker.md`.

---

## 6. Phase 6 — Attacker infrastructure and persistence sweep

**Objective:** find the worm's own artifacts inside our orgs. This phase is about **our** GitHub
tenancy as a *victim surface*, not as a code host.

Modern worms exfiltrate over **provider-owned infrastructure** — dead-drop repositories and Actions
artifacts — precisely to defeat egress-based C2 detection. A clean network hunt (§5.3 query 3)
therefore proves much less than it appears to.

**Required checks:**

1. **Dead-drop repositories** — search every org for repos whose description matches the campaign
   marker. This campaign's default was **`Shai-Hulud: Here We Go Again.`** Check public *and*
   private, and check recently-created repos regardless of description.
2. **Anomalous Actions artifacts** — unexpected artifact uploads in the window, especially from
   workflows that do not normally produce artifacts.
3. **Repository history manipulation** — force-pushes to default branches, tag deletion and
   re-creation, and commits adding lifecycle hooks. The reference campaign showed force-pushes to
   `main`, repeated deletion of the `v6.0.0` tag, and a commit titled *"add setup.mjs and
   Math_Symbol.js to all @keyv/* packages"* — history was being rewritten in real time.
4. **New or modified npm automation tokens / trusted publishers** on org repos.
5. **Entra persistence TTPs** — `Add service principal credentials`, `Consent to application`,
   `Add owner to application`, `Add app role assignment`, `Add delegated permission grant`.
   Attribute every event to a named human.
6. **Lifecycle-script delta** — diff `preinstall` / `postinstall` / `prepare` across dependency
   updates. This is Phoenix's central argument and the highest-signal generic control for this
   entire attack class: it needs no IoC list and no CVE, and would have fired on every Shai-Hulud
   wave to date.

> **Reference run — coverage gap.** Checks 1–4 were **not performed**. The hunt tested
> network-egress C2 (`npm-cache.com`, `js-mirror.com`, `pypi-get.com`, the blockchain RPC hosts,
> `104.21.35.216`) and found nothing — but the campaign's actual exfiltration path was GitHub
> dead-drop repos, which was never searched. Check 5 *was* performed: 17 Entra events since Aug 4,
> all attributable to named human admins plus one `snow_ansible_automation` certificate rotation.
>
> The estate verdict is not overturned — with zero installs in the window there was no execution to
> exfiltrate from — but **the dead-drop sweep is cheap, decisive, and must run.** It is now
> mandatory in this playbook.

---

## 7. Phase 7 — Verdict assembly

A verdict is publishable only when every row is either ✅ with a control, or an explicitly stated
gap. No blanks, no implied coverage.

| Surface | Verdict | Control that makes the zero meaningful | Gaps |
|---|---|---|---|
| Intel reconciliation | | Tier 0 verification of every accepted claim | seed-set vs full-campaign delta (§1.4) |
| Dependency trees | | parser cross-validated against SBOM where available | invisible repos |
| Code search IoCs | | non-zero control queries prove the org is indexed | >384 KB files unindexed |
| Actions CI | | every in-window run individually cleared | unretrievable logs |
| Runner hosts | | host-level telemetry, not just logs | non-onboarded hosts |
| Endpoints | | per-table event + device counts for the window | in-container / Docker VM blind spot |
| Identity | | per-identity cohort check, not just tenant aggregate | log retention window |
| Attacker infra | | dead-drop repo search across all orgs | — |

**Report obligations:**

- State the **decisive fact**, not just the absence of findings. "No opportunity to execute" is a
  far stronger claim than "we found nothing."
- Name every **protective factor** and say whether it was structural (pinned lockfiles) or
  circumstantial (window fell outside working hours). Circumstantial protection is not a control.
- Publish **disagreement resolutions** (§1.3) so the next run starts calibrated.
- Log every **silent cap** — top-N, sampling, no-retry. Undisclosed truncation reads as full
  coverage.
- Record **self-corrections** inline. The reference run produced four (macOS reachability, the
  `has_any(" ci ")` bug, ascending truncation, the Zscaler-IP misjudgement); each is now a rule in
  this playbook.

---

## 8. Reference-run index

| Report | Contents |
|---|---|
| `exports/mini-shai-hulud-exposure.md` | Dependency-tree exposure, 153 affected-family repos |
| `exports/ci-hunt-mini-shai-hulud.md` | Actions CI, 464 runs, `SleepNumberInc` + `sleepnumberlabs` |
| `exports/digital-hunt-mini-shai-hulud.md` | Digital org, 9 of 12 repos, 65 runs |
| `exports/graph-hunt-mini-shai-hulud.md` | Access test + query record (superseded) |
| `exports/graph-hunt-mini-shai-hulud-RESULTS.md` | Endpoint/identity hunt, ~3,585 devices |
| `exports/sp-assessment-corp-functions-it-spend-tracker.md` | Alert-disposition case study — §5.7 |

**Net verdict of the reference run:** not exposed on any surface, in any org. Protective factors —
pinned lockfiles across all 153 affected-family repos (**structural**), and a publish window falling
before US working hours (**circumstantial**).

**Registry-derived ground truth, reproducible via `RegistryOracle`:** 20 malicious `name@version`
specs, window **2026-08-04T09:31:03.692Z → 12:11:19.909Z**. Note this supersedes the 09:31–10:40Z
window used in every report under `exports/` — see §1.5.

---

## 9. Open items carried forward

1. **Run the dead-drop repository sweep** (§6 checks 1–4) across all three orgs. Never performed.
2. **Re-run Phase 3 against the full ~444-name campaign set**, not the 20 seed pairs (§1.4).
3. **Re-run the install-activity check against the registry-derived window** ending
   **12:11:19.909Z**, not 10:40Z or 12:00Z (§1.5). Specifically cover 12:00–12:20Z, which no hunt
   has examined.
3. **Verify the npm major version on every builder** — npm ≥ 12 disables `preinstall` by default
   and may be the control that actually mattered (JFrog, single-source).
4. **Implement the lifecycle-script delta rule** (§6 check 6) as a standing control.
5. **Obtain org `owner` on `sleepnumber`** — 3 private repos remain invisible.
6. `organization_self_hosted_runners:read` — not needed for hunting, useful for inventory hygiene.
