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

Seven rules that determine whether the output is evidence or theater.

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

**The malware itself is a false-negative source.** A control proves the *query* could have found
the thing; it does not prove the *malware would have run*. CHAINDROP reads `LANG` and exits without
executing if it indicates a Russian locale (StepSecurity). On such a host every behavioral rule
returns clean — no Bun spawn, no stage 2, no C2 — while the dropper sits on disk and would have
executed under any other locale. File-hash rules still fire; process and network rules do not.

So a behavioral zero needs **two** pairings: a control query, and a check that the evasion
condition was absent. Enumerate the estate's locales before reading a behavioral zero as clean,
and prefer file-hash and file-write telemetry as the primary surface wherever the payload has a
known hash — that surface is indifferent to whether the code ran.

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

### 0.6 Report nothing you cannot prove, and price every gap in exact privileges

Three obligations. All three are enforced in code by `scripts/hunt/render_hunt_report.py`, which
refuses to write a report that violates any of them.

**(a) Every claim carries its proof, or it is not made.** A status is not an opinion; it is a
conclusion drawn from an artifact. Each vector must supply the coverage evidence that earns its
status, and each `FINDINGS` vector must name the specific items that earned it. A number with no
artifact behind it is deleted from the report — not softened, not hedged, not footnoted. There is
no wording that makes an unproven claim safe to publish, because the reader cannot tell which
sentences you were confident about.

This binds inference as hard as it binds measurement. "Microsoft shipped a Win32 signature,
therefore the Windows path is confirmed in the wild" is not a finding. The signature's existence is
provable; what it implies about this estate is not. Write the first, drop the second.

**(b) Every gap names the exact privilege that closes it.** A gap reported as "insufficient access"
is not a work item, it is a research project handed to whoever reads it. State the API, the exact
endpoint, the exact permission string, the grant type (application vs delegated), who can grant it,
and what the query would prove once granted. Six fields. If any is unknown, that is a gap in the
hunt's own understanding — go and find it before publishing.

> **Verify the grant against the tenant, never against config.** The reference run reported the
> endpoint vector `BLOCKED` because `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID` and `GRAPH_CLIENT_SECRET`
> were absent from `.env`. True observation, wrong conclusion: `GraphClient.from_db` reads the
> encrypted credential store, and the store held an app registration carrying
> `ThreatHunting.Read.All`. The report raised a priority-1 access request for a permission already
> granted, and told an executive the laptops were unseen on a cycle where they could have been
> searched in under a minute. Absence of a credential where you looked is evidence about where you
> looked. Ask the tenant: `GET /servicePrincipals/{id}/appRoleAssignments`.

**(c) No false positives for the sake of false positives.** A hunt that reports weak signal to look
thorough spends the reader's trust to buy the author's cover, and the next real finding arrives in
a queue the reader has already learned to discount. Two specific prohibitions:

- **Do not report hygiene as compromise.** Unpinned action refs and bulk secrets exposure are real
  and worth fixing, and neither is evidence this campaign reached us. They travel under `FINDINGS`
  with `is_compromise_evidence` false, and only compromise evidence drives the verdict to RED.
- **Do not report a triaged-benign hit as a hit.** Show it, say what explains it, and keep it out
  of the counts that carry the verdict. The reference run found exactly one Bun execution
  estate-wide — Homebrew, on a macOS laptop, parented by `zsh`. It appears in the report in full,
  as an explained row, and it moved no status.

The rule cuts symmetrically. Suppressing a real finding because it is inconvenient is the same
defect as inflating a weak one, and both are caught the same way: by requiring the evidence next
to the claim.

**(d) A doctrine the tooling cannot express is a doctrine that will be violated.** Rule (c) above —
*do not report a triaged-benign hit as a hit* — was written before the r5 run and was already
correct. The renderer had no way to obey it. `vector_branches` set `FINDINGS` from the mere
existence of a flagged commit, and `branches` is in the `is_compromise_evidence` tuple, so a single
flag drove the verdict straight to **RED / "Are we breached? YES — evidence of compromise found.
Treat as an active incident."** In r5 that flag was one commit changing `.claude/settings.json`
inside the window, which on reading carried **no `hooks` key** — the campaign's actual injection
vector — and a `deny` list that independently blocks `Bash(curl *)` and `.env` reads. The flag was
right to fire. The report was wrong to call it a breach, and it would have launched an incident
response.

The fix is a **disposition file**, `exports/hunt/dispositions.json`, and its design is the part worth
keeping:

- **Observation and adjudication live in separate files.** Coverage artifacts record what a collector
  *saw* and are written by the collector. The disposition file records what a human *concluded* and
  why. Merging them lets a judgement be read as a measurement.
- **A disposition needs `reason` *and* `evidence`, or the renderer ignores it and the flag stays
  open.** Clearing a flag by naming its sha with no stated basis is precisely the unprovable claim
  §0.6 forbids. `evidence` must say what was checked and what was found, repeatably — not the
  conclusion restated. This deliberately **fails toward the alarm**.
- **A cleared item is still printed, with its reason, in the report.** A disposition changes whether
  an item counts as evidence of compromise; it never changes whether the item is shown. The reader
  must be able to disagree with the adjudication.
- **Open and cleared are counted separately, and the cleared count prints even at zero.** A run where
  every flag was reviewed and cleared must not look identical to a run where nothing fired.
- **`unresolved` is a valid disposition and keeps the flag open.** Reviewing something without
  reaching a conclusion is honest; recording it as cleared is not.

**Generalize this.** Any vector that can flag an individual item needs the same mechanism before its
flags reach a verdict. Until one exists for a vector, that vector can only ever say *something fired*
— never *and we looked at it*.

### 0.7 Result and coverage are two axes. Never report them as one

A hunt answers two questions and they are independent:

- **Result** — in the population we can observe, did we find the thing?
- **Coverage** — how much of the estate is that population, and what is the rest?

Fusing them destroys both. The reference run's endpoint vector found no trace of the campaign
across 3,424 devices, with controls proving every query could have found it — and reported
`INCOMPLETE`, driving the whole report to AMBER, because 1,379 other devices send no telemetry at
all. That reads as though the hunt found something worrying. The worrying thing was our own
instrumentation, no amount of hunting will change it, and a color that says AMBER every day for a
structural reason is a color nobody reads on the day it means something.

So the status is judged **only** against the population the check could observe, and the
unobservable remainder is reported on its own axis, in its own register, priced and never folded
into the verdict. The report states both: "no evidence of compromise across everything we can
observe" **and** "here is what we cannot observe, and what would change that". Inside a coverage
gap, the honest answer is *we can neither confirm nor deny* — and saying that plainly is worth more
than a color.

The test for which axis a shortfall belongs on is one question — **can we close it with the access
we already hold?**

| | Belongs to | Why |
|---|---|---|
| Repository trees not yet read | `INCOMPLETE`, result axis | Our unfinished work. An unfinished hunt is not a clean hunt. |
| Devices that emit no telemetry | Coverage register | Needs somebody to onboard them. No query will ever resolve it. |
| A telemetry column never populated | Coverage register | Needs a configuration change or a vendor answer. |
| A privilege we do not hold, that closes a blind spot | Coverage register, priced per §0.6(b) | Needs a grant. |
| A privilege we do not hold, that closes nothing | Neither — `access_required` only | Nothing is unobservable because of it. Filing it as a gap is a false positive on the coverage axis. |

**A coverage gap must name its resources, or it is not a gap.** "A third of the estate is dark" is
not a work item; nobody can act on it. Every gap carries the query or artifact that returns the
individual members, by an identifier the owner acts on — and that query must be **grouped the same
way as the count beside it**, or the list and the number disagree. An early draft grouped the
enumeration by `DeviceId, DeviceName` against a count grouped by `DeviceId`, and returned 590 rows
for a population of 570, because a renamed device appears twice.

The edge is worth stating precisely:

- **Enumerable** — 569 devices in `DeviceInfo` with `OnboardingStatus != "Onboarded"`. Each has a
  `DeviceId`. Nameable, therefore fixable, therefore a gap, therefore reported with an owner.
- **Unenumerable** — machines that have never contacted Defender at all. They are not in
  `DeviceInfo`, so there is no list and no number. Reporting it anyway invents a population to
  worry about, which is §0.6(c) in its purest form. It becomes reportable when some other source
  can enumerate it — Intune, AD, the CMDB — at which point the gap is "reconcile Defender against
  that source" and the enumeration query points there.

Enforced in code: `COVERAGE_GAP_FIELDS` in `scripts/hunt/render_hunt_report.py` requires `gap`,
`population`, `named_by`, `cannot_confirm_or_deny`, `closed_by` and `owner`, and the render aborts
if any is blank. `compute_coverage()` is separate from `compute_verdict()`, and no coverage gap can
reach the RAG letter.

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
| **Elastic Security Labs** | `https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain` | Named the campaign **CHAINDROP**; C2 domain `awqhnjewqjkl.icu`; the `node  setup.mjs` double-space execution variant; 50-branches-per-repository propagation via stolen GitHub App tokens; Dune-fiction payload strings; AI-tooling credential targets |
| **Cycode** | `https://cycode.com/blog/keyv-cacheable-npm-worm-ai-coding-agents/` | Per-package **safe rollback versions** (a superset of Chainguard's four); the injected dependency name `@opensearch/setup`; `StringListStore`, the `Bun/1.3.13` user agent, and Jenkins `master.key` / Argo CD / Harbor secrets as harvest targets; and the only **explicit denial** of the transitive-`keyv`-reach narrative |
| **Unit 42 (Palo Alto Networks)** | `https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/` | Sole source for the **second propagation path — repository-gated OIDC trusted publishing with genuine Sigstore provenance**, which defeats provenance verification with no stolen credential; the third dropped file `router_runtime.js`; the on-chain C2 rotation transaction and its 15:15:26Z timestamp; the dead-drop and commit-marker strings the worm itself searches for; `gh auth token` as the PAT-capture command |
| **StepSecurity** | `https://www.stepsecurity.io/blog/chaindrop-npm-worm` | Deepest teardown published. Sole source for: the **pre-publish GitHub timeline** (§1.5); the `release-publish.ts` hijack; the **token-revocation monitor**; the **runner-memory scrape** via `/proc/<Runner.Worker>/mem`; the self-republish chain incl. self-minted Sigstore; the Russian-locale kill switch; the second-wave namespace breakdown; both `setup.mjs` byte sizes |

> **Keep this table synchronized with `github_conf/ioc/`.** Elastic and StepSecurity were
> incorporated into that directory as `chaindrop_elastic_2026_08.json` and
> `chaindrop_stepsecurity_2026_08.json` *before* they appeared here, so for a period the registry
> under-reported the sources the hunt was actually running on. **One source, one file, and a row in
> this table** — a source in `github_conf/ioc/` but not in §1.1 has no tier, and an untiered source
> cannot be arbitrated.

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

**Round 2 — CHAINDROP claims (Elastic, StepSecurity), arbitrated 2026-08-06.**

| Claim | Elastic | StepSecurity | Others | Tier 0 registry | Resolution |
|---|---|---|---|---|---|
| **Last malicious publish / propagation close** | omitted | **09:38 – 13:20Z** | Socket implies ~10:14Z | **13:18:41.376Z** | **RESOLVED 2026-08-10 in StepSecurity's favor, at Tier 0.** The 12:11:19.909Z figure was an artifact of a candidate set too narrow, not a registry fact: re-deriving over the full 443-name set returned **13:18:41.376Z**, which corroborates StepSecurity's 13:20Z to within 79 seconds. Round 4 then proved the close is **bracket-independent** — the 18:00Z and 2026-08-05T00:00Z brackets return the *identical* malicious set of 2,208 specs with the same latest publish, so six extra hours add nothing and the close is a property of the registry rather than of the bound. StepSecurity was right and this playbook's own earlier number was wrong. See §1.5 Round 4. |
| `setup.mjs` has **two** distinct hashes | ✅ both listed, no sizes | ✅ **29,918 B** (v1) and **11,017 B** (v2) | — | n/a | **Consensus, StepSecurity adds the sizes.** Both were already in the payload-hash rule. Confirms the doctrine: one filename, two byte sizes, both malicious — filename and size hunting are both worthless. |
| C2 domain `awqhnjewqjkl.icu` | ✅ | omitted | — | n/a | **Single-source, accepted into hunt scope.** It was in `chaindrop_elastic_2026_08.json` and **absent from the indicator block list and every detection rule** until 2026-08-06 — a known C2 domain we were not blocking. Ingesting a source file is not the same as acting on it. |
| Ethereum resolution tries **75** RPC endpoints | "multiple fallbacks" | ✅ 75, selector `0x53ed5143` | Wiz ✅ mechanism | n/a | **Consensus on mechanism, StepSecurity quantifies it.** Decides a control question: blocking three RPC hosts is not a chokepoint at 75. See §6. |
| Token-revocation monitor fires the payload | omitted | ✅ `~/.local/bin/gh-token-monitor.sh`, polls `api.github.com/user` /60s for 24h | — | n/a | **Single-source, high value, acted on.** Inverts IR order — revocation is the *trigger*. Also the only artifact surviving cleanup of `setup.mjs`, `math_init.js`, `.claude/` and `.vscode/`. |
| Runner memory scraped for masked secrets | omitted | ✅ `sudo python3` reading `/proc/<Runner.Worker pid>/mem`, grep `"isSecret":true` | — | n/a | **Single-source, high value.** Defeats masked-secret hygiene entirely: it takes every secret the runner handled in the job, not only those the compromised step referenced. Self-hosted Linux only — `cxdkrprdapp12–17.comfort.com` are in scope. |
| Exfil channel is **bidirectional** (`code` field → `eval()`) | "exfil" only | ✅ | — | n/a | **Single-source, changes incident scoping.** A host that reached `npm-cache.com` must be scoped as *arbitrary code execution*, not *credential theft*. |
| Provenance defeated **twice** — self-minted Sigstore, and the real release workflow | omitted | ✅ `fulcio.sigstore.dev` + `rekor.sigstore.dev`; and `keyv@6.0.0` published by the project's own workflow | Snyk ✅ provenance analysis | ✅ `keyv@6.0.0` present with valid attestation | **Consensus, confirmed.** A provenance-verifying control **passes** this package. Provenance proves build integrity, not source integrity. |
| Russian-locale kill switch (`LANG`) | omitted | ✅ | — | n/a | **Single-source. Promoted to doctrine (§0.1)** as a behavioral-rule false-negative source, not filed as trivia. |
| Campaign footprint | "over 400 packages" | **444 pkgs / 2,212 versions** @ 2026-08-04 18:10Z | SafeDep 444/2,234 · Cloudsmith 444/~2,236 · JFrog 428/1,700+ | not enumerable in one call | **Tier 2 consensus at ~444 names**, JFrog low. Still a floor (§1.4). |
| Exfil workflow identity | omitted | **`Run Copilot`**, `on: push` | prior set: `codeql_analysis.yml` on `dependabot/github_actions/format/setup-formatter` | n/a | **Variant, not contradiction.** Two observed dressings of one primitive: dump `${{ toJSON(secrets) }}` to a file, upload the file. **Detect the primitive** — a workflow added by a non-human identity referencing `toJSON(secrets)`. Keying on either filename misses the other and the next one. |

**Round 3 — Cycode, arbitrated 2026-08-10.** Source: `github_conf/ioc/keyv_cycode_2026_08.json`.

| Claim | Cycode | Others | Tier 0 registry | Resolution |
|---|---|---|---|---|
| **No commonly declared dependency range accepts `keyv` 6.x**, so the widely repeated "ESLint pulls `keyv` transitively" account cannot explain a `keyv@6.0.0` install — only an explicit `npm i keyv@latest` or a range pinned into 6.x installed it | ✅ explicit denial | this playbook §3 records three adjacent packages in this estate arriving as transitive `eslint` dev-toolchain dependencies | semver-checkable per estate | **OPEN, and probably not a real conflict.** The two statements are about different subjects: Cycode describes *reachability of 6.x*; the corpus line describes how three **adjacent** packages — right name, safe version — arrived here. Both can hold. Estate-specific half is resolvable from evidence: `check_declared_ranges.py` over the r5 lockfile set. That answers it **for this estate only** and does not settle Cycode's general claim. Owner: item #6 of this run. |
| `@opensearch/setup` as an injected dependency name | ✅ | omitted by all | n/a | **Single-source, and it had NO detection surface.** No rule in `npm_supply_chain_rules.json` keys on a dependency *name*, so this is a dependency-inventory hunt only. Added to the r5 inventory match as a direct search. |
| Per-package **safe rollback versions** | ✅ full table | Chainguard partial (4 packages) | ✅ present in registry | **Accepted, superset of Chainguard's.** Operationally the most useful thing in the source. |
| Footprint "2,000-plus versions across affected scopes" | ✅ | StepSecurity 444 pkgs / 2,212 versions · Elastic ">400 packages" · Unit 42 "over 400 packages" · SafeDep 444/2,234 | not enumerable in one call | **Recorded, deliberately not reconciled.** Three sources, three magnitudes, two different *units* (packages vs versions), different as-of times. **No estate decision depends on the total** — matching runs against the derived `package@version` set, never a count. |
| `StringListStore`, `Bun/1.3.13` UA, Jenkins `master.key`, Argo CD / Harbor secrets as harvest targets | ✅ | omitted | n/a | **Single-source, accepted into hunt scope.** All five were absent from every indicator list and rule before this file. |

**Round 4 — Unit 42, arbitrated 2026-08-10.** Source: `github_conf/ioc/chaindrop_unit42_2026_08.json`.

| Claim | Unit 42 | Others | Tier 0 registry | Resolution |
|---|---|---|---|---|
| **Second propagation path: repository-gated OIDC trusted publishing.** Mint an npm publish credential from Actions OIDC (audience `npm:registry.npmjs.org`) gated on `GITHUB_REPOSITORY` / `GITHUB_WORKFLOW_REF`, inject `@opensearch/setup`, then mint **genuine** Sigstore provenance (audience `sigstore`, Fulcio + Rekor, SLSA v1 in-toto over SHA-512, DSSE with an ephemeral P-256 key) | ✅ sole source | StepSecurity ✅ self-minted Sigstore, but via the stolen-token path | ✅ attestations verify | **Single-source, highest-value claim in the round, and it changes a control assumption.** There is **no stolen credential to revoke** on this path and the resulting package **passes provenance verification** — the provenance is real, it just attests a build whose *source* was poisoned. Acted on: §6 check 11 now requires counting repositories that combine `id-token: write` with a publish step, and `sweep_actions_posture.py` detects the pair. That combination is **not a finding** — it is how trusted publishing is designed to work — it is the *precondition the technique requires*, and this playbook had never asked for the count. |
| Third dropped file `router_runtime.js` | ✅ sole source | omitted | n/a | **Single-source, accepted.** Added to the r5 tree-sweep `indicator_basenames` and to the endpoint dropped-file query. A sweep run before 2026-08-10 could not have found it. |
| Dead-drop prefix `thebeautifulsnadsoftime`; exfil repo name words `harkonnen`, `atreides`, `futar`, `ghola`; `_NODE_RUNTIME_INIT` | ✅ | Elastic ✅ `thebeautifulmarchoftime`, `sardaukar`, `mentat` | n/a | **Variant, not contradiction** — a second dressing of the same generator. Acted on with a caveat: §6 check 12 requires these searches to be **unbounded by window**, and the Dune vocabulary produces real false positives (`SCDT-Supplier-Portal-Documentation` and `retail-network-segmentation` both contain "mentat" as a substring), so the `<word>-<word>-<digits>` shape is matched rather than the bare word. |
| **C2 rotated on chain** 2026-08-04 **15:15:26Z**, tx `0xc55920f1…b507c91`; operator wallet `0x55f9780e…97f31cd`; setter selector `0xd3c159e5` | ✅ sole source | none | n/a | **RESOLVED IN FAVOR OF WIDENING, and it is not an averaging.** A signed on-chain transaction with a timestamp is a harder artifact than either the 13:20Z close or the 12:11:19.909Z publish bound. It shows the operator was **acting** 1 h 56 m after the window this estate had hunted to. It does **not** show a malicious package was published after 13:18:41.376Z — rotating a C2 address is operator maintenance, not propagation, and Round 4's bracket-independence proof rules the later publish out at Tier 0. **Both facts hold; they are about different activities.** Consequence: hunts keyed on *operator activity* (C2 contact, exfil, dead-drop creation) must not inherit the publish-window bound. |
| Base91 + PBKDF2 obfuscation layers; `gh auth token` as the PAT-capture command; `.netrc`, Electrum wallets, kubeconfigs, shell histories as harvest targets | ✅ | omitted | n/a | **Single-source, accepted into hunt and rotation scope.** `gh auth token` matters most: it captures a credential from the CLI's own store, so a host with no PAT in an environment variable is not therefore clean. |
| Footprint "over 400 packages" | ✅ | see Round 3 row | not enumerable | **Consistent with the ~444-name Tier 2 consensus; still a floor.** |

> **Round 3–4 scorecard.** Neither source contradicts Tier 0. Cycode's one apparent conflict is a
> subject mismatch that estate evidence can settle; its real contribution is the rollback table and
> `@opensearch/setup`. Unit 42's contribution is the second propagation path, and it is the first
> claim in four rounds that invalidates a *control* rather than adding an indicator: provenance
> verification and credential revocation both pass a package published this way. **Both sources were
> ingested into `github_conf/ioc/` and diffed before being trusted** — the diff is recorded in each
> file under `_diff_against_corpus`, and in both cases `rule_coverage_of_the_new_indicators` is
> **NONE**. Ingesting a source file is not coverage.

**Scorecard from the reference run:** Chainguard 1 material error (`ecto`). Socket accurate on
versions, conservative on scope. Phoenix accurate but methodological rather than enumerative — its
contribution was the *detection-philosophy* argument (lifecycle-script delta rules catch this class;
CVE and signature controls have no detection surface for it), not an IoC list.

**Round-2 scorecard:** no contradictions of Tier 0 by either source, and no source-vs-source
conflict except the propagation close time. Elastic's distinct value is breadth (new C2 domain,
propagation scale, evasion strings); StepSecurity's is depth, and it is the only source describing
the part of the campaign that occurred **before** any malicious publish — which is the only phase
where prevention was still available. Both earn Tier 2. Neither is promotable to Tier 1: the
material claims are single-source and not registry-verifiable, because they concern commits and
processes in repositories and hosts we do not control.

**Round-2 process failure, recorded per §1.2 step 4.** The failure was ours, not a vendor's:
`awqhnjewqjkl.icu` sat in `chaindrop_elastic_2026_08.json` while every detection rule and the
indicator-block list omitted it. Ingesting a source file created the *appearance* of coverage. Rule:
adding a source file is step 1 of 3 — arbitrate it into §1.3, then diff it against the deployed
rules and the indicator list, and record the diff.

### 1.4 The scope-reconciliation trap — read this

Vendors converge on roughly **428–444 poisoned package names across ~1,700–2,236 versions**. A hunt
built only from the **seed** packages will under-scope.

> **Gap identified in the reference run.** The original hunt derived a rigorous, registry-verified
> set of **20 `name@version` pairs** — correct for every seed package, and the basis of a sound
> not-exposed verdict for those. But the campaign reached ~444 names. The 20-pair set was
> *precise*, not *complete*. The estate verdict held because the affected-family repos all resolve
> to pinned versions multiple majors below the compromised releases, which is a structural defense
> independent of list completeness — but the list was narrower than the campaign, and that must be
> stated rather than glossed.

**Mandatory step:** after seed reconciliation, expand to the full campaign name set (Tier 2
enumerations, deduplicated) and re-run Phase 3 against it. Log the delta between seed-set and
full-set coverage. Never report seed-set coverage as campaign coverage.

**Expand by namespace, not by name.** StepSecurity breaks the second wave (433 packages / 2,201
versions, first observed `@thiennq/docs-viewer@1.6.2`) down by the publisher account it was stolen
from, which is the shape the expansion should follow:

| Namespace | Versions | Namespace | Versions |
|---|---|---|---|
| `@servicetitan` | 141 | `@nebula.js` | 22 |
| `@onereach` | 78 | `@deliveroo` | 2 |
| `@or-sdk` | 74 | `@picsart` | 2 |
| `@ornikar` | 42 | `@adminide-stack` | 2 |
| `@qlik` | 28 | unscoped | 26 |

Compromised publishers: `jaredwray` · `thiennq` · `hubsyncdevops` · `abarreir-ornikar` ·
`sitthidet_arv` · `rooci` · `picsart-npm-service-owner` · `onereach.user`.

Two reasons this is the better expansion unit. First, a **name** list is stale the moment the worm
republishes; a **namespace** is stable for as long as the token is live, so
`/-/v1/search?text=maintainer:<account>` against each compromised publisher enumerates the
blast radius directly from Tier 0 instead of from a vendor snapshot. Second, `grep`ping nine scope
prefixes across every lockfile in the estate is one cheap pass, where 444 exact names is not —
and a hit on `@servicetitan/*` at *any* version is worth triaging even if that exact version was
never in anyone's list.

This is also the input set for the unresolved propagation-close question (§1.3, §1.5): re-run the
oracle across these namespaces with a bracket past 14:00Z.

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

**~~The window is still open at the far end.~~ RESOLVED 2026-08-07 at Tier 0 — in StepSecurity's
favor.** The disagreement was: StepSecurity put second-wave propagation at **09:38 – 13:20Z**,
while the oracle's last malicious publish was **12:11:19.909Z** — 69 minutes where a vendor claimed
publishing activity and Tier 0 recorded none. Per §1.2 that escalated rather than averaging.

Re-ran `derive_malicious_set` over the **full 443-name campaign list** (`keyv-packages-wiz.csv`),
bracket **09:00 – 14:00Z**, deliberately past both claims:

| | Prior derivation | Round-3 re-derivation |
|---|---|---|
| Package set | 20 seed pairs | **443 names** |
| Malicious specs | 20 | **2,206** |
| First malicious publish | `@keyv/mongo@6.0.0` 09:31:03.692Z | `keyv@6.0.0` **09:35:00.763Z** |
| Last malicious publish | `@thiennq/docs-viewer@1.6.4` 12:11:19.909Z | `@umacloud/cli-linux-musl-x64@1.0.74` **13:18:41.376Z** |
| Publishes after the prior close | — | **207** |

**The 12:11:19.909Z close was an artifact of the 20-package seed set, not a fact about the
registry.** It is superseded. StepSecurity's 13:20Z is corroborated at Tier 0 to within 79 seconds
— the last malicious publish lands at 13:18:41.376Z, *inside* their claim. The escalation is
closed and the interim "hunt to 13:20Z, report 12:11:19.909Z" rule is withdrawn.

**Two qualifications, both of which widen scope rather than narrow it:**

1. **Hunt scope runs to 13:30:46.398Z, not 13:20Z.** The *suspected-uncleaned* set — registry
   cleanup misses that are still installable, and which §1.5 already requires be folded into scope
   rather than the verdict — extends past the malicious tail to `@adminide-stack/yantra-mobile@12.0.33-alpha.3`
   at **13:30:46.398Z**. Twenty-four specs, five of them after the old close.
2. **The 14:00Z bracket is a real bound, not a truncation.** The latest hit of any kind sits 29
   minutes inside the bracket end, so the close is measured rather than clipped — which is exactly
   the check the generous-bracket rule above exists to make possible.

**One unresolved package:** `@hubsync/web-sdk-react` could not be authoritatively resolved
(1 of 443). Per §0.1 it is **unknown, not clean**, and it is the only name in the campaign set with
no Tier 0 verdict.

#### Round 4 (2026-08-10): the close is bracket-independent, and the suspected axis is not a bound

Round 3 left the close resting on a single bracket. Unit 42 then put operator activity at
**15:15:26Z** (§1.3 round 3), which is *after* every claimed close — so the 14:00Z bracket had to be
tested rather than trusted. Two wider brackets were run over the same 443 names:

| Bracket end | Malicious specs | Last malicious publish | Suspected uncleaned | Last suspected publish |
|---|---|---|---|---|
| 14:00Z (round 3) | 2,206 | 13:18:41.376Z | 24 | 13:30:46.398Z |
| **18:00Z** | **2,208** | **13:18:41.376Z** | 34 | 17:52:34.295Z |
| **2026-08-05 00:00Z** | **2,208** | **13:18:41.376Z** | 111 | 21:32:29.337Z |

**The malicious sets for the 18:00Z and 00:00Z brackets are identical — not equal in count, equal as
sets.** Adding another six hours of bracket adds no malicious publish. The close
**2026-08-04T13:18:41.376Z** is therefore a property of the registry and not of the bound, which is
the strongest form this number can take. Unit 42's 15:15:26Z rotation stands as operator activity
after propagation ended; the two facts do not conflict.

**Why 2,208 and not 2,206, stated exactly, because a moving count invites the wrong inference.** The
two additions are `@ornikar/intl-config@10.0.10` (published 12:44:09.580Z) and
`@ornikar/react-native-svg-transformer@1.0.13` (12:44:09.763Z). Both were already in the round-3
data — as *suspected uncleaned*, with `unpublished: false`. On 2026-08-10 the registry reports
`unpublished: true` for both. **npm's cleanup caught up in the three days between runs and moved
them across axes.** Nothing was newly discovered and nothing was lost (`round3 − round4 = ∅`); the
bracket did not cause it. The lesson is that a derivation is a snapshot of registry state, so a
re-derivation must diff against the prior artifact rather than replace it.

**Qualification 1 of round 3 — "hunt scope runs to 13:30:46.398Z" — is withdrawn.** All 34
suspected-uncleaned specs from the 18:00Z run were resolved the only way that settles them: download
the tarball npm is currently serving and hash its members (`verify_live_tarballs.py`, nothing
installed or executed). Result: **33 `clean_no_dropper_artifacts`, 1 `npm_security_tombstone`
(`@servicetitan/suppress-warnings@0.0.1-security`), 0 malicious.** And the twelve specs the wider
bracket added are all `@onereach/*` and `@or-sdk/*` billing packages published 17:42–17:52Z with
sequential beta build numbers (`27.3.1-beta.8179.0`, `-beta.8180.0`) — an ordinary CI cadence over
four hours after the close.

> **Rule, added here.** The suspected-uncleaned set's latest publish must **never** be reported as a
> window bound. It grows monotonically with the bracket by construction — 24 → 34 → 111 as the
> bracket moved 14:00Z → 18:00Z → midnight — because a wider bracket sweeps in more ordinary
> publishing by the same vendors. It is a **work queue for hash verification**, and only a hash
> verdict retires an entry from it. Read as a bound it manufactures an ever-later close from an
> ever-wider bracket, which is the exact circularity `verify_live_tarballs.py` exists to break.

> **Consequence for the estate hunt, stated plainly.** Every GitHub-side check in round 3 already
> ran to 13:18:42Z, so those are covered. The **endpoint install-activity check is not** — it was
> last run against a window ending 12:00Z, and there are now 207 known malicious publishes after
> that. Nothing in this round could re-run it: the Graph hunting credential is absent from this
> environment (§5.1). That is an open gap, not a clean result. See §9 item 1.

#### The window has a front end too, and it is where prevention lived

The derived window bounds *publishes*. The **compromise** starts earlier, and every hunt so far has
treated `09:31:03.692Z` as t=0. StepSecurity's reconstruction of `jaredwray/keyv` (single-source;
the commits are in a repository we do not control, so this is **not** Tier 0 verifiable):

| Time (UTC) | Event |
|---|---|
| **09:02:37** | Commit `ee2681a` to `main`: adds the dropper, adds `"preinstall": "node setup.mjs"`, adds the dropper to the package `files` array, adds a **fake cover test** at `core/keyv/test/preinstall.test.ts`, and edits `scripts/release-publish.ts` |
| **09:04:30** | Persistence commit `d8c850c` |
| **09:23:50** | Cover-test deletion `f97eabc` |
| **09:31:03.692** | First malicious publish, `@keyv/mongo@6.0.0` — Tier 0 |
| **09:35:00.763** | `keyv@6.0.0` published **by the project's own release workflow**, valid SLSA provenance — Tier 0 |
| **09:38 – 13:20** | Second wave from stolen publish tokens (close time disputed, above) |

**28 minutes and 30 seconds of visible, reviewable malicious commits before the first publish.**

The `release-publish.ts` edit is the mechanism and the most reusable technique in the campaign: it
moves `latestMajor` out of a protected CI variable and into the repository's own `package.json` —
a file the attacker already controls. The malicious major then publishes as `latest` through the
real, signed, provenance-emitting release pipeline. **Nothing in the pipeline was compromised.** It
did exactly what its configuration told it to, which is why `keyv@6.0.0` carries genuine SLSA
provenance and why any control that verifies provenance passes this package (see §1.3 round 2).

**Three consequences for how we hunt and how we defend:**

1. **Widen the derived window backwards for the *source* surface.** `[min(published), max(published)]`
   is the right bracket for registry and install-activity questions. It is the wrong bracket for
   *commit* questions — history manipulation, lifecycle-hook additions, release-tooling diffs. For
   those, extend at least an hour earlier and search on shape, not on timestamp.
2. **A cover test is an IoC of intent.** A test added and deleted 21 minutes later, whose only job
   was to make a lifecycle-hook addition look routine to a reviewer, is a strong signal on its own.
   Add "test file added and removed within the same day, touching install or lifecycle behavior"
   to the §6 lifecycle-script delta control.
3. **Release-tooling diffs are the highest-leverage review gate in this attack class.** A change
   that relocates a version, channel or `latest`-tag decision from CI configuration into
   repository-controlled state is upstream of every indicator elsewhere in this playbook, and it is
   plainly visible in a pull request. This applies to us as a publisher, not only as a consumer.

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

### Reconcile the IOC list against registry ground truth before trusting any match

§0.2 says the registry beats every vendor advisory. That is a rule about *adjudication*, and it has a
corollary about *matching* that is easy to get backwards: the list you match against should be the
**superset**, not the registry set. A registry-confirmed spec missing from the match list is a
silent miss; a vendor-claimed spec the registry cannot confirm only costs a false positive you then
adjudicate. So compare the two sets explicitly and in that direction.

**r5 reconciliation (2026-08-10).** Vendor list `keyv-packages-wiz.csv` — **443 names / 2,235
specs** — against the registry-derived malicious set — **442 names / 2,208 specs**:

| Direction | Count | Consequence |
|---|---|---|
| Registry-confirmed specs **missing** from the IOC list | **0** | No silent miss. The match ran against everything ground truth confirmed. |
| Registry names missing from the IOC list | **0** | |
| IOC specs the registry did **not** confirm | 27 | Over-inclusive tail. Harmless for a negative result. |

> **All 27 unconfirmed specs are one package: `@hubsync/web-sdk-react`, versions 6.3.7–6.3.33.** That
> is the same package §9 item 1 carries as *unresolved at Tier 0 — unknown, not clean*, and the
> reconciliation resolves what that means for this estate. The registry oracle still cannot adjudicate
> it, so it stays unknown as an *intel* question. But every one of its 27 claimed versions **is** in
> the list the estate was matched against, and the match returned zero — so its unresolved status
> creates **no exposure blind spot here**. Those are two different questions and the report must keep
> them apart: the intel gap is open, the exposure question is answered.

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

#### Run r5 (2026-08-10) — the full estate, three independent axes

The reference run above covered 153 repositories. r5 covers **364 npm-relevant repositories out of
2,811**, matched against the **2,208-spec** derived set, and separates three questions that earlier
runs had merged.

| Axis | Question | Result | Control that makes the zero readable |
|---|---|---|---|
| **Installed today** (`collect_lockfiles.py`) | Is a malicious `name@version` resolved anywhere? | **0 matches** across **236,703 resolved pairs** in **328 repos** | **277 repositories contain an affected package NAME** at a safe version (`file-entry-cache` 273, `flat-cache` 273, `keyv` 200, `cacheable-request` 164). The matcher provably reaches these packages, so the absence of the malicious versions is evidence rather than silence. |
| **Reachable by declaration** (`check_declared_ranges.py`) | Could a fresh `npm install` pull one? | **0 reachable**, 688/688 manifests read | See the parse control below — mandatory, because this script only records in-scope declarations and a broken reader produces an identical clean-looking zero. |
| **Injected by name** (`--watch-names`) | Is `@opensearch/setup` in any tree, at any version? | **0** | **None.** Stated as the weaker zero it is — see below. |

**The parse control decides whether the ranges zero means anything.** `control_declared_parse.py`
re-read 137 manifests across the 60 repositories most likely to hold a direct declaration (selected
by affected-name count in their lockfiles) and counted **every** declaration rather than only
in-scope ones: **2,622 declarations, 290 distinct names, 0 in the 442-name campaign scope**
(`dependencies` 1,224 · `devDependencies` 1,389 · `peerDependencies` 7 · `optionalDependencies` 2).
Verdict `control_passed_reader_works_and_no_in_scope_declarations`. The reader works; the zero is a
finding.

> **This resolves the Cycode contradiction (§1.3 Round 3) for this estate, and it resolves it by
> confirming both statements.** Cycode: no commonly declared range accepts `keyv` 6.x. This corpus:
> the affected packages are here as transitive eslint dev-toolchain dependencies. Both are true —
> **not one campaign package name is declared directly anywhere in this estate**, so every appearance
> of `keyv`, `file-entry-cache`, `flat-cache` and `cacheable-request` is transitive, and no declared
> range in the estate can reach 6.x because no declaration reaches `keyv` at all. Note the scope of
> what has been settled: this is an estate-specific answer and it does **not** adjudicate Cycode's
> general claim about the npm ecosystem.

> **The injected-name zero is weaker than the other two, and must be reported that way.** An injected
> dependency has no safe version to subtract, so `all_pairs & scope` structurally cannot see it —
> which is why `--watch-names` exists and why Cycode's diff recorded that **no rule in
> `npm_supply_chain_rules.json` keys on a dependency name at all**. But the zero carries no control:
> `@opensearch/setup` has never appeared in this estate at any version, so unlike the four affected
> names there is no positive case proving the matcher would have found it. It is an unexercised check
> returning zero, not a demonstrated absence.

**Still unmeasured, and not clean:** **36 repositories** have a `package.json` and no lockfile. Their
installed versions are recorded nowhere in the repository, so this method could not clear them — it
had nothing to read. They are listed in `declared_ranges_r5.json` under `repos_without_lockfile`.
Artifacts: `lockfiles_r5.json`, `declared_ranges_r5.json`, `declared_parse_control_r5.json`.

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

### CI telemetry — reference run r5 (2026-08-10)

`collect_ci_telemetry.py` over **999 repositories** with workflow files, baseline from 2026-07-05:
**8,591 runs**, **0 campaign-flagged runs**, **91 in-window runs**, **42 in-window deployments**.
Coverage is clean and earned: **0** throttled, **0** `HTTP 404`, **0** other errors — so
`coverage_supports_negative_finding` is true rather than assumed. 1,812 repositories with no workflow
files were skipped, which is a disclosed narrowing, not a zero.

> **A truncation bug this run caught, and the rule it produces.** §0.4 says never
> `order by … asc | take N`. This collector never says `asc` — and it truncated the wrong end anyway.
> The runs API paginates **newest-first**, so a page cap cuts the **oldest** runs, which is exactly
> where the worm window sits. `SleepNumberInc/SBLDevOps-CCPA` collected 300 of 497 runs reaching back
> only to **2026-08-05T08:59:24Z — a day after the window closed** — and reported
> `in_window_runs: 0`. That zero was a measurement artifact, and the coverage file called the estate
> negative *supportable* while it stood. Re-collected with `--max-pages 6`: all 497 runs, oldest
> 2026-07-07, still 0 in-window and 0 flagged — now a result. The remaining 6 capped repositories all
> reach back past the window, so their caps are disclosed bounds and nothing more.
> **The rule: a page cap is only a disclosed bound if the oldest collected record predates the
> window. Otherwise it is a coverage failure.** `collect_ci_telemetry.py` now computes
> `repos_capped_before_reaching_window`, refuses `coverage_supports_negative_finding: true` while it
> is non-empty, and prints the repositories to re-run. Generalize this to any newest-first paginated
> source before trusting its zero.

**The 91 in-window runs, read rather than counted.** 20 repositories, ordinary work: `terraform_cd`,
`rails`, `lint_js`, PR-title automation, super-linter. Actors are **17 named humans plus three
legitimate bots** — `clouddevopsdeploymentreadwrite[bot]`, `dependabot[bot]`, `atlassian[bot]`.
**No `claude`, no `github-advanced-security[bot]`, no `codeql_analysis.yml`.**

> **One near-miss worth naming, because a keyword rule would have fired on it.** Five in-window runs
> are `dependabot[bot]` on branch **`dependabot/github_actions/actions-4413991923`**. The campaign
> branch is **`dependabot/github_actions/format/setup-formatter`** — the same ecosystem prefix. The
> distinguishing part is the segment *after* the ecosystem, so a prefix match on
> `dependabot/github_actions/` would flag every routine Actions bump in the estate. Match the full
> branch, not the prefix. It is also a `github_actions` ecosystem update, not npm, so it could not
> have pulled a malicious package regardless.

> **The 8 in-window `pull_request_target` runs are safe for a structural reason, and read anyway.**
> All 8 are one workflow, `pull-request-automation.yml` in `sleepnumberlabs`, on internal JIRA-named
> branches. The posture sweep's `privileged_trigger_with_pr_head_checkout: 0` predicted this and the
> file confirms it: top-level `permissions: {}`, and **no checkout step at all** — it passes the PR
> *title* to `morrisoncole/pr-lint-action@v1.7.1`. No untrusted code executes, so the classic
> `pull_request_target` compromise is structurally unavailable here.
> **The residual is the action ref, not the trigger:** `@v1.7.1` is a mutable tag on a third-party
> action running in a `pull_request_target` context holding `pull-requests: write` and
> `statuses: write`. Repointing that tag yields PR write access across every repository using it —
> the same exposure as the 8,115 mutable refs, reached through a privileged trigger.

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

> **Confirmed from the other side, 2026-08-10.** The self-hosted runners are not just inferable from
> log paths — they appear in endpoint telemetry as onboarded devices. `cxdkrprdapp12.comfort.com` and
> `cxdkrprdapp16.comfort.com` (both Linux 8.10) ran `node /shared/github/hostedtoolcache/node/22.23.2/x64/bin/npm ci`
> **inside the exposure window**, and `cxdkrprdapp16` executed `sh -c "node install.js"` as a child of
> that `npm ci` at 12:23:53Z. So the CI and endpoint populations **overlap**, and their results must
> never be summed as if they were separate estates. This also makes the StepSecurity runner-memory
> scrape (`/proc/<Runner.Worker>/mem`) directly applicable: it is self-hosted-Linux-only, and these
> are self-hosted Linux.

### Posture sweep — reference run r5 (2026-08-10)

`scripts/hunt/sweep_actions_posture.py` over **999 repositories with workflow files, 5,077 workflows
read, read rate 1.00**.

| Measure | Count | Reading |
|---|---|---|
| `id-token: write` **+ a publish step** in one workflow | **0** | **The Unit 42 trusted-publishing precondition does not exist in this estate.** See below. |
| `id-token: write` with no publish step | 6 | Cloud federation, the ordinary use. Not the technique. |
| `toJSON(secrets)` — whole secrets context serialized | **119** in **60 repos** | The exfil primitive, present **as designed behavior**. See below. |
| Secrets interpolated into a `run:` block | 838 | Script-injection surface, pre-existing. |
| Action refs on **mutable** refs | **8,115** | vs **960** pinned to a commit SHA — 89% mutable. |
| Workflows with no `permissions:` block | 4,933 of 5,077 | Default token scope, unrestricted. |
| Self-hosted runners | 95 | Matches the runner fleet above. |
| `curl`/`wget` piped to a shell | 4 | **All four read** (2026-08-10). Three fetch from a **mutable `main` branch of a third-party repo**. See below. |
| Bun fetch markers / `bun.exe` references | 0 / 0 | The campaign's own installer footprint is absent. |
| Privileged trigger **+** PR-head checkout | **0** | The classic `pull_request_target` compromise is absent. |

> **The `id-token: write` + publish zero is the most valuable single number in this sweep, and it is
> a *precondition* count, not a finding count.** Unit 42's second propagation path needs a workflow
> that can both mint an OIDC token and publish. Zero workflows in 999 repositories combine the two,
> so the technique has no foothold here — and this is the first run in which the playbook even asked.
> Note what the zero does **not** say: trusted publishing is a *good* practice, so this number should
> be expected to rise, and the check exists to make that rise visible rather than to keep it at zero.

> **The 119 `toJSON(secrets)` workflows are legitimate and still a real exposure.** They were read
> rather than counted. The pattern is a deliberate Terraform convention — the whole secrets context is
> handed to a third-party action that filters it:
>
> ```yaml
> - name: Map TF Secrets to Env
>   uses: Firenza/secrets-to-env@v1.1.0        # 52 workflows
>   with:
>     secrets: ${{ toJSON(secrets) }}
>     secret_filter_regex: TF_VAR_*
> ```
>
> **The filter runs inside the action, after it already holds every secret in the repository.**
> `v1.1.0` is a mutable tag, and 76 of the 119 workflows carry unpinned third-party action refs —
> `c-py/action-dotenv-to-setenv@v3` (53), `FranzDiebold/github-env-vars-action@v2.1.0` (52),
> `chrnorm/deployment-action@releases/v1` and `notiz-dev/github-action-json-property@release` (branch
> refs, mutable by definition and updated silently). Repointing any one of those tags hands an
> attacker the full secrets context of 60 repositories with no code change in this estate. That is the
> same primitive this campaign uses, reached by a different route.
>
> **Doctrine consequence.** §1.3 Round 2 said "detect the primitive — a workflow referencing
> `toJSON(secrets)`". In this estate that rule fires **119 times legitimately**, so an alert on the
> primitive alone is 119 false positives and the real signal — a *newly added* one, authored by a
> non-human identity — is buried. The rule must be a **delta on the primitive**, not the primitive:
> alert when `toJSON(secrets)` appears in a workflow that did not previously contain it. A baseline
> is a prerequisite for the detection, and `actions_posture_r5.jsonl` is now that baseline.

> **The 4 curl-pipe workflows, read rather than named** (closing the r5 open item; source text
> retained at `exports/hunt/curlpipe_workflows_r5.json`). Two distinct trust models, and the
> difference decides which one matters:
>
> | Workflow | Piped source | Trigger | Secrets in job |
> |---|---|---|---|
> | `SleepNumberInc/sleep-number-claude-code-plugins` `ci.yaml` (2 steps) | `https://claude.ai/install.sh` | `pull_request` → `main` | none |
> | `sleepnumberlabs/sdna-new-databricks` `1-sync-databricks-jobs.yml` | `raw.githubusercontent.com/databricks/setup-cli/**main**/install.sh` | `workflow_dispatch` | none referenced |
> | `sleepnumberlabs/sdp-databricks-pytest-poc` `run-integration-tests.yml` | same, `**main**` | `pull_request` → `develop`, `workflow_dispatch` | `DATABRICKS_TOKEN` |
> | `sleepnumberlabs/sdp-databricks-pytest-poc` `run-tests-on-databricks-dev.yml` | same, `**main**` | `pull_request` → `develop`, `workflow_dispatch` | `DATABRICKS_TOKEN`, `SLACK_WEBHOOK_URL` |
>
> The first pipes from a vendor-controlled apex domain (`claude.ai`) — an install script fetched over
> TLS from the vendor whose tool is being installed, which is the ordinary distribution channel and
> carries no ref that *could* be pinned. The other three pipe from the **`main` branch of a
> third-party GitHub repository**, `databricks/setup-cli`. That is materially worse and is fixable:
> `main` is mutable, so any push to that repository changes what executes here, with no change in
> this estate and no release boundary to review. `setup-cli` publishes tags; the fetch does not use
> one.
>
> **Exposure, stated precisely.** All four use `pull_request`, **not** `pull_request_target` — so a
> **fork** PR gets a read-only token and **no** secrets, and the fork path is not the concern. The
> concern is the internal path: a same-repository branch PR (or a `workflow_dispatch`) runs the piped
> script with `DATABRICKS_TOKEN` and `SLACK_WEBHOOK_URL` present in the job environment. None of the
> four declares a `permissions:` block, so the `GITHUB_TOKEN` is at the org default scope, which this
> sweep does not read — an org-settings lookup, recorded here as unmeasured rather than assumed.
>
> **What this is not.** No campaign IOC appears in any of the four; `databricks/setup-cli` and
> `claude.ai` are not campaign infrastructure. This is a standing trust-model exposure surfaced by
> the hunt, not evidence of this compromise.

### Attribution — reference run r5 (2026-08-10)

A posture finding with no owner is a finding nobody will fix, so the finding set is resolved to
CODEOWNERS and, separately, to blast radius. `repo_owners_r5.json`, 182 repositories — every
repository named by any posture finding list.

| Measure | Count | Reading |
|---|---|---|
| Repositories resolved | 182 | Every posture finding routes to a repository. |
| `owner_lookup_error` | **0** | **No rights gap.** CODEOWNERS was readable at all three honored paths in all 182. |
| `owned` | 146 | |
| `unowned` — no CODEOWNERS at any of the three paths | **36** | The attribution gap. |
| Owned but **no catch-all** `*` owner | 99 | |
| …and no workflow-path owner either | **0** | So all 146 route for *this* finding set, which is entirely workflow findings. |
| `unowned` **AND** `reaches_production` | 0 | **Do not read this as clean.** See below. |

> **The `unowned AND reaches production` zero is a coverage artifact, not a result.** Blast radius is
> `None` for **157 of 182** repositories (95 `unknown`, 62 `not_in_topology`), so the intersection was
> computed over the 25 repositories whose radius is actually known. **34 of the 36 unowned
> repositories have an unknown blast radius** — the honest statement is "nobody owns them and we
> cannot say what they reach," which is strictly worse than the zero suggests. Closing it is a
> topology-coverage task, not a permission request.

> **Where ownership and sharpness intersect.** All three repositories piping remote code from a
> mutable third-party `main` are **unowned**: `SleepNumberInc/sleep-number-claude-code-plugins`,
> `sleepnumberlabs/sdna-new-databricks`, `sleepnumberlabs/sdp-databricks-pytest-poc`. So is
> `SleepNumberInc/sn-identity`, which carries both `toJSON(secrets)` and secrets interpolated into a
> `run:` block. The 6 repositories that provably reach production are all owned, 4 of them by
> `@SleepNumberInc/devops-cloud`.

> **Two limits that keep "owned" from meaning "safe."** CODEOWNERS is read from the default branch
> only, and owner tokens are **not** validated against GitHub team membership — a CODEOWNERS naming a
> team that no longer exists reads as `owned` here and routes to nobody. Both are recorded in the
> artifact's `limits` array rather than left for a reader to discover.

> **A collector defect this run exposed, worth encoding.** `sweep_actions_posture.py` emitted the new
> `id_token_write_without_publish_step` list as `"org/repo:path"` **strings** while every other
> finding list emits `{repo, path}` **dicts**. `collect_repo_owners.py` read `entry["repo"]` and
> skipped non-dicts silently, so 5 repositories reached the finding set with **no owner and no
> error** — the exact outcome that script exists to prevent. Both sides are now fixed: the sweep
> emits dicts, and the owners collector normalizes either shape and records anything it still cannot
> attribute in `unattributable_findings` (0 after the fix) instead of dropping it. **A new finding
> list must be added to the owners key tuple in the same commit that adds the check.**

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
8. **Alternate runtime installed or executed** — `bun` was the delivery mechanism here.
   **Hunt the binary on both platforms and on all three tables** — see §5.3.1
9. **Credential-store reads** — `.npmrc`, `.git-credentials`, `.config/gh`, `.aws/credentials`,
   `.ssh`, Vault tokens, kubeconfig, by `node`/`npm`/`curl`/shell
10. **Alerts on any runner host or developer machine** in the window

#### 5.3.1 The Bun bootstrap is described in POSIX and executes on Windows

Query 8 above, and every Bun query in the deployed rule set, was written from the documented
bootstrap: `mkdtemp('/tmp/bun-dl-')` → `chmod 755` → execute stage 2 → delete the staging
directory. **Two of those three steps do not exist on Windows.** The same source that documents
them (`chaindrop_stepsecurity_2026_08.json`, `bun_bootstrap.assets`) also lists
`bun-windows-x64-baseline.zip` and `bun-windows-aarch64.zip` among the fetched release assets.
Those unpack to **`bun.exe`**, under `%TEMP%` / `%LOCALAPPDATA%\Temp`, with no `chmod` and no
`/tmp` path anywhere on the chain.

This estate's endpoint population is overwhelmingly Windows. A hunt that models only the POSIX
shape reads a bootstrapped Windows host as clean.

Three specific blind spots, each with the query that closes it:

| Blind spot | Why the existing coverage misses it | Closed by |
|---|---|---|
| The **binary write itself** | Nothing in the library queried `DeviceFileEvents` for the Bun binary. Only execution and network fetch were covered. | `backlog/22`, `DeviceFileEvents` branch |
| **Non-package-manager parents** | `detections/12` and `baseline/40` require `InitiatingProcessFileName` to be `node`/`npm`. Correct for a low-noise *rule*; wrong for a *hunt*. A drop by `cmd.exe`, `powershell.exe` or an extraction helper is invisible. | `backlog/22` reports the parent instead of filtering on it |
| **Side-loaded rather than spawned** | A `bun.exe` loaded into a host process produces no `DeviceProcessEvents` row. | `backlog/22`, `DeviceImageLoadEvents` branch |

**Triage rule.** A Bun artifact is a **provenance question, not a detection**. Bun is a legitimate
runtime and `setup-bun` is an ordinary CI step. The discriminators, in order: is the path a temp or
staging directory rather than a versioned install root; does a `bun-dl-` segment appear; is the
parent process a package manager or a shell; does the `SHA256` match the published release for that
version. `bun.lock` and `bun.lockb` are **not** indicators — including them turns the hunt into a
"does anyone here use Bun" census, which is a different and much larger question.

**Read the zero against `coverage/08` before believing it.** That query reports Bun *beside*
`node`/`npm` on the same table and the same platform, because "no Bun on this estate" is only a
finding if node and npm are non-zero next to it. If every tool is zero on a platform, the platform
is not reporting and no Bun conclusion is available at all (§0.1). `coverage/08` also reports
`SHA256` population per table: the provenance triage above *is* a hash comparison, so a row with an
empty hash cannot be triaged no matter how suspicious its path.

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
   wave to date. **Extend it** (per §1.5) to a test file added and deleted the same day that touches
   install or lifecycle behavior — CHAINDROP shipped a cover test for exactly this reason.
7. **Non-default branches.** Where a GitHub App token is stolen, CHAINDROP commits hooks to up to
   **50 branches per accessible repository** (Elastic), as `claude <claude@users.noreply.github.com>`
   with the message `chore: update config`, via GraphQL `FetchBranches` + `createCommitOnBranch`.
   **A sweep that inspects only the default branch reads a compromised repository as clean.**
   Enumerate all branches; search on the author identity and the commit message, not on file paths.
8. **The exfil-workflow primitive, not its filename.** Two variants are documented — a workflow
   named `Run Copilot` on `push` (StepSecurity), and `codeql_analysis.yml` on branch
   `dependabot/github_actions/format/setup-formatter` (prior set). Both do one thing: write
   `${{ toJSON(secrets) }}` to a file and upload it as an artifact (`format-results`), plus staging
   repositories holding `results-*.json`. **Detect the primitive** — any workflow added or modified
   by a non-human identity that references `toJSON(secrets)`. Keying on either filename misses the
   other variant, and the next one.
9. **npm publisher-side abuse on our own scopes.** The worm authenticates as the stolen publisher
   and calls `/-/whoami`, `/-/org/`, `/-/npm/v1/tokens`, `/-/v1/search?text=maintainer:<account>`
   and `/-/npm/v1/oidc/token/exchange/*` with UA `npm/11.13.1 node/v24.10.0`, then repacks tarballs
   with recomputed SHA-512/SHA-1 and **self-mints Sigstore attestations** through
   `fulcio.sigstore.dev` and `rekor.sigstore.dev`. For any scope we publish: enumerate automation
   tokens, check for tokens with `bypass_2fa: true` (the collector explicitly prefers these), and
   review recent attestations against known-good release runs.
10. **Bun artifacts in the source estate, including `bun.exe`.** Two surfaces, and they answer
    different questions. **Git trees** answer whether a Bun binary or release archive is committed
    (`bun.exe`, `bunx.exe`, the seven `bun-*.zip` assets, any `bun-dl-` path segment) — this is
    authoritative, because it reads the tree itself. **Code search** answers whether a workflow or
    script *fetches* one, and is the weaker of the two: GitHub's code-search index excludes
    binaries, so `filename:bun.exe` returns `total_count: 0` for a repository that has one
    committed. That zero is a property of the index, not of the estate. Never report it as
    coverage — the tree sweep is what clears binary presence.
    On the CI side the useful signal is not the presence of Bun but whether the fetch is **pinned
    and mirrored**: the release CDN is the dropper's first hop and it is *one* egress origin,
    against 75 RPC endpoints downstream. See §5.3.1 for the endpoint half.

11. **Trusted publishing as a propagation path that needs no stolen token** (added 2026-08-10 from
    Unit 42). The worm carries a second publish path that never touches an npm credential: inside a
    repository matching its gate — `GITHUB_ACTIONS` set, `GITHUB_REPOSITORY` matching
    `/opensearch-js`, `GITHUB_WORKFLOW_REF` matching `release-drafter.yml` — it requests an OIDC
    token with audience `npm:registry.npmjs.org`, trades it at npm's trusted-publishing endpoint for
    a real publish credential, injects the typosquatted dependency `@opensearch/setup`, then mints a
    **genuine** Sigstore bundle: second OIDC token with audience `sigstore`, Fulcio certificate,
    SLSA v1 in-toto provenance over SHA-512, DSSE-signed with an ephemeral P-256 key, uploaded to the
    public Rekor log and attached as `<name>-<version>.sigstore`.
    **Why this is a check and not trivia.** Every control this playbook recommends against the
    primary path assumes a stolen npm token — rotate npm credentials, gate on release age, block
    install scripts. None of them touch this path. And the provenance it produces is real, so a
    provenance-verifying consumer passes the artifact. That is the **third** defeat of attestation in
    this campaign (§1.3 round 2), and the first where the attacker never needed a credential at all.
    **What to count in this estate:** the gate means the payload will not take this path here. The
    *technique* transfers to any repository that combines `id-token: write` with a publish step, so
    the Actions sweep must count that combination — not as a finding, since it is how trusted
    publishing is designed to work, but as the precondition the technique requires. This playbook has
    never asked for that count.
12. **Our own repositories as dead drops, unbounded by the attack window** (added 2026-08-10 from
    Unit 42). The worm searches the GitHub commit API for `thebeautifulmarchoftime` to find and reuse
    credentials other infections published; the backup-domain dead drop is prefixed
    `thebeautifulsnadsoftime`. Run both searches against our own orgs. Unit 42 found 453 marker
    repositories across five accounts with the **earliest dated 2026-05-11** — almost three months
    before the keyv compromise. **Therefore this search must not be window-bounded.** Code and commit
    search have no window, so widening costs nothing, while the branch and CI-telemetry vectors stay
    window-bounded because they hunt what the worm did during propagation. Dead-drop repository
    *names* also draw on a small Dune vocabulary (`sardaukar`, `mentat`, `fremen`, `atreides`,
    `harkonnen`, `futar`, `ghola`, e.g. `sardaukar-futar-421`); usable against repository names,
    never as content indicators — see the caveat in `chaindrop_elastic_2026_08.json`.

### Dead-drop sweep — reference run r5 (2026-08-10), checks 1 and 12

This check had been listed since the first revision and **never executed**. It cost nothing to
execute, which is the lesson: `scripts/hunt/sweep_dead_drops.py`, `dead_drops_r5.json`, **zero API
calls**. Repository names and descriptions were already in `repo_trees_r5.jsonl`, because
`collect_repo_trees.py` paginates the org listing to completion — so the enumeration is complete by
construction rather than by sampling.

**Result: 0 marker repositories across 2,811 repositories in all three orgs** (SleepNumberInc 2,285,
sleepnumberlabs 517, sleepnumber 9). No `Shai-Hulud: Here We Go Again.` description, no
`thebeautifulmarchoftime` / `thebeautifulsnadsoftime` in any name or description, no Dune-vocabulary
name, no `results-*` staging name.

**Controls pass, and they are what make the zero worth printing.** Four positive controls — a canary
description carrying the real marker, `sardaukar-futar-421`, `thebeautifulmarchoftime-loot`,
`results-20260804` — were each caught by the matcher; two ordinary repositories
(`documentation-site`, `api-gateway`) produced no false positive. The script returns exit 2 and
labels the run *inconclusive rather than clean* if either control fails.

> **The two halves of this sweep do not have the same coverage, and averaging them would be exactly
> the lie §0.7 forbids.** The **name** checks cover **2,811 of 2,811** — every repository has a name,
> so that zero is true over the whole estate. The **description** check covers **1,569 of 2,811
> (55.8%)**: 1,242 repositories have no description at all, so it could never have fired on them.
> Those 1,242 are cleared by the name checks only. A dead drop created with a blank description and an
> innocuous name is invisible to this sweep, which is precisely why check 12's content search runs
> alongside — and that search returned `weak_zero_partial_index`, not a clean zero.

> **`created_at` is unmeasured, not clear.** Check 1 also asks for recently-created repositories
> *regardless of description*, because the attacker can leave it blank. The trees artifact does not
> retain `created_at`, so that sub-check is **not covered**. Closing it needs the repository listing
> re-read with `created_at` kept — **no new privilege, only a re-run**, so this is not a rights gap.
> The weaker `pushed_at`-in-window proxy is reported on its own axis and returns 5 repositories, all
> pre-existing with ordinary names (`snip-key-vault-sync` — the known bare-name false positive from
> the run above — `semantic-release-deployment-workflow`, `snint-sleepiq-appcs-infra`,
> `snint-sleepiq-proxy-fna`, `sn-rails-fly`). An active repository pushes during any 6.5-hour window,
> so this number carries almost no signal and is not evidence of anything.

**Still not covered by this run:** check 2 (Actions artifacts), check 3 (force-push and tag history),
check 4 (npm automation tokens / trusted publishers). Different APIs; none attempted.

### 6.1 Persistence that survives eradication — sweep this before revoking anything

Two artifacts sit outside every path a normal cleanup touches.

**The token-revocation monitor** (StepSecurity, single-source):

| Artifact | Platform |
|---|---|
| `~/.local/bin/gh-token-monitor.sh` | all |
| `~/.config/gh-token-monitor/` | all |
| `gh-token-monitor.service` | Linux (systemd) |
| `com.user.gh-token-monitor` | macOS (launchd) |

It polls `https://api.github.com/user` every 60 seconds for 24 hours and **fires the payload when
the token stops authenticating**. Two consequences, and both invert normal practice:

- **It survives clean-up.** Deleting `setup.mjs`, `math_init.js`, `.claude/` and `.vscode/` removes
  nothing here. None of those paths contain it. A host declared eradicated on that basis is not.
- **Revocation is the trigger, not the remedy.** Rotating the stolen token is the condition the
  monitor waits for, and it responds by re-collecting and re-exfiltrating from whatever credentials
  are still live. **Remove the monitor from every affected host before the first revocation.** This
  is a carve-out to "rotate before you eradicate", not a reversal of it — the payload still
  exfiltrates first, so the ordering is: sweep and remove the monitor, then rotate, then eradicate
  the rest.
- **A quarantine alert is not confirmation of removal** (added 2026-08-10, from running
  `coverage/07-file-hash-column-coverage.kql` for the first time). The armed quarantine action on the
  agent-hook-drop rule needs a populated `SHA1` column. Measured on this tenant, SHA1 is present on
  **83.2%** of matching `DeviceFileEvents` rows on Windows10, 96.1% on WindowsServer2025, 97.0–97.1%
  on WindowsServer2019 and Windows11, 98.6–99.1% on WindowsServer2012R2/2016, 98.9% on
  WindowsServer2022, and **100% only on macOS**. On the remainder `stopAndQuarantineFiles` silently
  no-ops **while the alert still fires** — so an operator can read "quarantined" and rotate, which is
  precisely the trigger. And even a successful quarantine removes only the *script*: the
  `gh-token-monitor.service` user unit and the `com.user.gh-token-monitor` launchd label stay
  registered. **Removal is verified on the host with `pgrep -af gh-token-monitor` returning nothing,
  never from the alert.** That check gates the first revocation, not the alert.

**Runner memory scraping** (StepSecurity, single-source). A `sudo python3` helper reads
`/proc/<Runner.Worker pid>/mem` and greps for `"isSecret":true`. This defeats masked-secret hygiene
completely: a secret never written to a log or a file is still in the runner process's heap, and any
job with passwordless `sudo` can read it. It takes **every secret the runner handled during that
job**, not only those the compromised step referenced.

Scope: **self-hosted Linux runners only** — GitHub-hosted runners are discarded per job. The
estate's `cxdkrprdapp12–17.comfort.com` are directly in scope. It leaves no file and no network
trace, so hunt it as a process pattern (`python3` under `sudo` with `/proc` in the command line,
initiated from a runner work directory) and expand the rotation scope for any affected runner to
every secret any workflow on it consumed in the window — not the secrets of the triggering repo.

### 6.2 Credential-rotation scope

Scoping rotation to GitHub and npm tokens leaves behind most of what the collector was built to
take: ~140 hotspot paths and 19 regex secret patterns, 300+ claimed unique patterns.

- **AI tooling** (new in this campaign, and present on this estate's workstations):
  `.claude/credentials.json` · `.codex/auth.json` · `.cursor/credentials.json` ·
  `.openai/auth.json` · `.anthropic/auth.json` · `.gemini/.env`
- **Cloud:** SigV4-signed `sts:GetCallerIdentity`, `secretsmanager:ListSecrets`,
  `secretsmanager:GetSecretValue`, `ssm:GetParameters` across **16 regions**, plus IMDSv2 and ECS
  task-metadata chains. **CloudTrail is the detection surface here** — mass `ListSecrets` /
  `GetSecretValue` from a single principal across many regions in a short window is a strong,
  cheap signal and does not depend on any endpoint telemetry.
- **Vault:** Kubernetes auth and IAM auth token exchange.
- **Kubernetes:** kubeconfig discovery and service-account token theft.
- **CI/CD and registry platforms** (added 2026-08-10 from Cycode and Unit 42, and absent from every
  earlier rotation scope): Jenkins `master.key` and its encrypted credential store · Argo CD secrets ·
  Harbor secrets · Terraform state · Poetry/PyPI and RubyGems tokens · Docker and Helm
  configuration · `.netrc` and stored git credentials · shell histories.
- **Additional cloud:** Alibaba Cloud and Tencent Cloud instance metadata and IAM credentials.
- **Wallets:** Bitcoin/Electrum, Foundry, Solana, Monero key material. Named here not because this
  estate holds crypto but because a harvester that reads wallet files also read everything beside
  them — the paths bound what was *seen*, not what was *taken*.

> Each class above is a **rotation scope item, not a detection**. Nothing in this estate's telemetry
> reports "Jenkins master.key was read." They are on this list so that a rotation plan drawn from it
> is as wide as the collector, which is the only property that matters after execution is confirmed.
> Where execution is *not* confirmed — as in every run so far — the list still bounds what a
> confirmed execution would cost, and that is what makes it worth keeping accurate.

**Scope a contacted host as code execution, not credential theft.** The exfil envelope is
`gzip(JSON)` → AES-256-GCM → RSA-OAEP-SHA256-wrapped key → base64 → `POST`, and a response
containing a `code` field is passed to `eval()`. The channel is bidirectional. Any host that reached
`npm-cache.com` gave the attacker arbitrary code execution for the duration of the connection, so
the rotation scope is everything reachable from that host, not a list of file paths.

> **Reference run — coverage gap.** Checks 1–4 were **not performed**. The hunt tested
> network-egress C2 (`npm-cache.com`, `js-mirror.com`, `pypi-get.com`, the blockchain RPC hosts,
> `104.21.35.216`) and found nothing — but the campaign's actual exfiltration path was GitHub
> dead-drop repos, which was never searched. Check 5 *was* performed: 17 Entra events since Aug 4,
> all attributable to named human admins plus one `snow_ansible_automation` certificate rotation.
>
> The estate verdict is not overturned — with zero installs in the window there was no execution to
> exfiltrate from — but **the dead-drop sweep is cheap, decisive, and must run.** It is now
> mandatory in this playbook.
>
> **Checks 7–9 and §6.1–§6.2 were added on 2026-08-06** from the CHAINDROP round-2 arbitration and
> have never been performed either. The same reasoning covers them — no execution means nothing to
> persist — but note that §6.1's token monitor and §6.2's runner-memory scrape would have been
> invisible to every surface the reference run examined, and the non-default-branch sweep (check 7)
> is a gap in the dead-drop hunt as originally written, not just an unperformed step.

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
| Attacker infra | | dead-drop repo search across all orgs, **all branches** (§6 check 7) | non-default branches never enumerated |
| Persistence | | token-monitor sweep (§6.1) run *before* any revocation | monitor survives normal eradication; leaves no file/network trace on the scrape path |
| Publisher side | | automation-token + attestation review on our own npm scopes (§6 check 9) | — |
| Cloud identity | | CloudTrail: mass `ListSecrets`/`GetSecretValue` per principal across regions (§6.2) | — |

**Report obligations:**

- State the **decisive fact**, not just the absence of findings. "No opportunity to execute" is a
  far stronger claim than "we found nothing."
- Name every **protective factor** and say whether it was structural (pinned lockfiles) or
  circumstantial (window fell outside working hours). Circumstantial protection is not a control.
- Publish **disagreement resolutions** (§1.3) so the next run starts calibrated.
- Log every **silent cap** — top-N, sampling, no-retry. Undisclosed truncation reads as full
  coverage.
- Record **self-corrections** inline. The reference run produced four (macOS reachability, the
  `has_any(" ci ")` bug, ascending truncation, the Zscaler-IP misjudgment); each is now a rule in
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
| `exports/hunt-report-2026-08-10.{md,docx,pdf}` | **Run r5** — full estate, three orgs. AMBER / coverage PARTIAL. |

**Run r5 artifact index (2026-08-10).** Every number in the r5 report traces to one of these:

| Artifact | What it establishes |
|---|---|
| `repo_trees_r5.jsonl` + `_coverage.json` | 2,811 repos enumerated, 2,761 file trees read in full |
| `actions_posture_r5.jsonl` + `_coverage.json` | 5,077 workflows in 999 repos; the CI exposure baseline |
| `branches_r5.json` + `branches_r5_coverage.json` | 5,640 branches, 127 commits, 0 campaign branches, 1 flag |
| `lockfiles_r5.json` + `_coverage.json` | 236,703 installed pairs; 328 of 364 npm repos parsed |
| `declared_ranges_r5.json` + `declared_parse_control_r5.json` | 688 manifests, 2,622 declarations, with its parse control |
| `ioc_match_r5.json` / `.md` | DB inventory axis: 75,963 rows / 720 repos, 0 exact matches |
| `code_search_r5.json` | Corroborating only; every zero labeled `weak_zero_partial_index` |
| `rederive_window_0000z_aug5.json` | Registry ground truth, 2,208 specs, set-identical to the 18:00Z bracket |
| `ci_telemetry_r5.jsonl` + `_coverage.json` | 8,591 runs, 0 campaign-flagged, 91 in-window |
| `repo_owners_r5.json` | 182 finding repos attributed; 36 unowned, 0 lookup errors |
| `dead_drops_r5.json` | 2,811 repos by name and description, 0 markers, controls pass |
| `endpoint_hunt_r9.json` | Defender endpoint and identity hunt |
| `dispositions.json` | The one flag, adjudicated with reason and evidence |
| `curlpipe_workflows_r5.json`, `pr_target_workflow_r5.yml` | Source text of the workflows read by hand |

**Net verdict of the reference run:** not exposed on any surface, in any org. Protective factors —
pinned lockfiles across all 153 affected-family repos (**structural**), and a publish window falling
before US working hours (**circumstantial**).

**Registry-derived ground truth, reproducible via `RegistryOracle`:** 20 malicious `name@version`
specs, window **2026-08-04T09:31:03.692Z → 12:11:19.909Z**. Note this supersedes the 09:31–10:40Z
window used in every report under `exports/` — see §1.5.

---

## 9. Open items carried forward

1. ~~**Resolve the propagation-close disagreement.**~~ **DONE 2026-08-07.** Re-derived over the
   full 443-name set with a 09:00–14:00Z bracket: 2,206 malicious specs, last at **13:18:41.376Z**,
   corroborating StepSecurity's 13:20Z at Tier 0. See §1.5. **What this leaves open is bigger than
   what it closed:** the endpoint install-activity check was last run to 12:00Z and there are 207
   malicious publishes after that. Re-run it against **09:35:00.763Z – 13:30:46.398Z** (the
   suspected-uncleaned tail, not the malicious tail) the moment Graph credentials are available.
   `@hubsync/web-sdk-react` remains unresolved at Tier 0 — unknown, not clean **as an intel
   question**. Its *exposure* half is closed as of 2026-08-10: all 27 claimed versions
   (6.3.7–6.3.33) are present in the list the estate was matched against and the match returned zero,
   so the unresolved adjudication creates no blind spot here. See §2's reconciliation table.
   **Superseded 2026-08-10 by item 5**, which ran the check to 2026-08-05T00:00:00Z. Note that the
   window instruction above is itself withdrawn: bounding an install-side check at the
   suspected-uncleaned tail was wrong, because that set is a work queue that grows with the bracket
   and is not a bound (Round 4, §1.5).
2. ~~**Run the dead-drop repository sweep**~~ **PARTLY DONE 2026-08-10.** Checks **1 and 12** are
   closed: `sweep_dead_drops.py` matched names and descriptions for **all 2,811 repositories in all
   three orgs — 0 marker repositories**, with four positive and two negative controls passing, at
   **zero API cost** (the data was already in `repo_trees_r5.jsonl`). **This check sat open for three
   revisions and cost nothing to run** — the lesson is to check what the existing artifacts already
   answer before pricing a check as expensive.
   **Still open, and do not read the zero as covering them:** the description half reaches only
   **1,569 of 2,811 (55.8%)** because 1,242 repositories have no description; `created_at` is
   unmeasured, so "recently created regardless of description" is *not* covered (a re-run with
   `created_at` retained closes it — no new privilege); and checks **2** (Actions artifacts), **3**
   (force-push / tag history) and **4** (npm automation tokens and trusted publishers) were not
   attempted at all.
3. ~~**Enumerate non-default branches**~~ **DONE 2026-08-10** (§6 check 7). `hunt_branches.py`
   enumerated **5,640 branches to completion across 100 repositories** — **0 campaign branches**,
   141 in-window activity events, 127 commits inspected, and **zero API errors of any kind**
   (`branch_errors: []`, `activity_errors: []`, `branch_enumeration_incomplete_for: []`). The
   activity endpoint requires push access and returned data on all 100, so there is **no rights gap
   to file here**.

   **Why 100 and not 2,811, and what that does not clear.** A push to *any* ref updates
   `pushed_at`, so the 2,711 repositories whose `pushed_at` predates 2026-08-04T09:35:00Z received no
   push to any branch during the window and cannot hold a branch the worm created in it. The
   narrowing is **exact for pushes**, not a sample. It clears those repositories of having *received
   a worm push*; it does **not** clear a repository whose compromise predates the window, which is a
   different claim this campaign's timeline does not support. Running `--all-repos` instead was
   measured at ~24 API calls per repository — roughly **67,000 calls, over 13 hours of the shared
   5,000/hr budget** — and was abandoned for that reason, not for lack of value.

   **One flagged commit, resolved by hash rather than by argument.** `SleepNumber/sndotcom`
   `cc7de3928f74` touched `.claude/settings.json` at 2026-08-04T14:16:01Z. Filename matching alone
   cannot decide this — `settings.json` is the campaign's IDE-persistence target *and* an ordinary
   file most Claude Code repositories have. Fetched at that commit and hashed:
   **sha256 `d69eddd7…82fb9b`, 800 bytes**, against the campaign hash
   **`14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128`** — **no match**. The
   content settles it independently: the file contains **no `hooks` key at all**, which is the only
   part of `settings.json` the campaign uses, and its `deny` list blocks `Bash(curl *)` and
   `Read(.env)`. It arrived in a 300-file human-authored `release-to-main` merge (author
   `luismercadoSN`, committed via `web-flow`, i.e. the merge button). **Benign, and the flag was
   correct to fire** — this is what a name-level indicator is for, and the hash is what closes it.
   Artifacts: `branches_r5.json`, `branches_r5_coverage.json`.
4. ~~**Re-run Phase 3 against the full ~444-name campaign set**~~ **DONE 2026-08-10.** 364
   npm-relevant repositories against the 2,208-spec / 442-name derived set: **0 installed, 0
   reachable by declared range, 0 injected by name**, with the parse control passing at 2,622
   declarations. Three axes, three separate answers, full detail in §3 "Run r5". Still open within
   it: **36 repositories with a `package.json` and no lockfile are unmeasured, not clean.**
5. ~~**Re-run the install-activity check against the registry-derived window**~~ **DONE
   2026-08-10, and the answer is INCOMPLETE with a named cause rather than clean.** The check had
   never been written at all — `scripts/hunt/hunt_install_activity.py` is new. It runs
   **09:35:00.763Z – 2026-08-05T00:00:00Z**, deliberately past the last malicious publish, because
   a version stays installable until it is *unpublished* and those removal times are not in this
   corpus: the exposure window has a proven start and an unproven end.
   **Result:** 69 install command lines on 5 devices in the window, **0 tarball fetches**. That
   pairing is a contradiction, not an absence, and the collector now fails closed on it. The cause
   is measured, and it is not the mirror this playbook assumed:

   | OSPlatform | Devices | Network rows (7d) | With a URL | With a URL **path** |
   |---|---|---|---|---|
   | Windows11 | 2,831 | 68,229,524 | 31,028,285 | 17,005,280 |
   | Windows10 | 2 | 27,958 | 7,908 | 5,469 |
   | **macOS** | **83** | **687,005** | **0** | **0** |
   | **Linux** | **308** | **200,063** | 132,459 | **0** |
   | WindowsServer2016/2019/2022/2025/2012R2 | 189 | 1,088,634 | 233,920 | **0** |

   > **Corpus-wide consequence, not a quirk of one collector.** `DeviceNetworkEvents.RemoteUrl`
   > carries a URL **path** only on Windows client SKUs. On macOS the column is never populated at
   > all; on Linux and every Windows Server SKU it holds a hostname with no path. **Any check in
   > this corpus that matches on a URL path is therefore silently Windows-client-only**, and a zero
   > from one says nothing about the other 580 devices. The npm registry connection *was* recorded
   > from the Linux runner (`registry.npmjs.org`, `104.16.8.34:443`, initiated by
   > `node .../npm ci`) — only the `/-/<name>-<version>.tgz` path was missing. **Closes it:** enable
   > Defender Network Protection in audit mode on macOS and Linux. This is a configuration change,
   > not a rights gap — `ThreatHunting.Read.All` already returns the table; the column is empty at
   > source.

   Two further facts fell out of the same run. **`npm` does not appear as `FileName` on macOS or
   Linux** — it runs as `node /path/to/npm install`, so a `FileName in~ ("npm", ...)` filter returns
   only `bun` estate-wide and would have reported a clean window. Any process filter in this corpus
   must match `node`/`node.exe` and read the command line. And **6 install command lines ran from
   `/shared/github/hostedtoolcache/`** — part of this estate's CI executes on onboarded endpoints,
   so the endpoint and Actions populations overlap and their results must not be summed.
   Lifecycle-script control: **2,670 executions on 101 devices** in the window, **0** carrying a
   campaign artifact name. Counted by aggregation, not by reading a capped row set — the first
   version of that query returned exactly its 1,000-row limit oldest-first, which would have
   truncated a late campaign hook away and reported it as absent. What stays open: none of the 2,670
   can be attributed to a package, because `DeviceProcessEvents` records `node install.cjs` and the
   parent shell but not the working directory. Artifact: `exports/hunt/install_activity_r2.json`.
6. ~~**Sweep for the token-revocation monitor** (§6.1) across all onboarded hosts.~~ **DONE
   2026-08-10.** `ir/52-persistence-sweep.kql` had shipped without any `gh-token-monitor` term, so
   the estate's only persistence sweep could not have found the watchdog; the file now carries all
   four artifact names plus a `FolderPath` branch that still catches the unit and the plist after
   the script is deleted. First execution returned **0 rows over 30 days**, with both halves of the
   union separately controlled — `DeviceFileEvents` populated at 1,687,857 matching rows over 7 days,
   `DeviceRegistryEvents` at 87,432,862 rows of which 192,358 are Run/RunOnce keys — so the zero is a
   measured absence on both branches rather than a silent table. **What remains** is the ordering
   discipline, not the sweep: removal is confirmed on the host with `pgrep -af gh-token-monitor`,
   never from a quarantine alert (§6.1).
7. **Verify the npm major version on every builder** — npm ≥ 12 disables `preinstall` by default
   and may be the control that actually mattered (JFrog, single-source).
8. **Enumerate estate locales** (§0.1) so a behavioral-rule zero can be read. A Russian-locale host
   returns clean from every behavioral rule with the dropper on disk.
9. **Implement the lifecycle-script delta rule** (§6 check 6) as a standing control, including the
   same-day added-and-deleted test-file case (§1.5).
10. **Add a release-tooling-diff review gate** (§1.5) — flag any change relocating a version,
    channel or `latest`-tag decision from CI configuration into repository-controlled state. Applies
    to us as a publisher.
11. **Adopt a package-manager-native release-age gate** across the estate — npm 11.10+
    `min-release-age`, pnpm 10.16+ `minimumReleaseAge`, Yarn 4.10+ `npmMinimalAgeGate`, Bun 1.3+
    `minimumReleaseAge`, Dependabot `cooldown`. Every malicious version here was unpublished within
    hours, so a 24–72h gate makes the whole window a non-event without a registry proxy.
12. **CloudTrail detection for mass secret enumeration** (§6.2) — `ListSecrets` / `GetSecretValue`
    from one principal across many regions in a short window. Independent of endpoint telemetry.
13. **Obtain org `owner` on `sleepnumber`** — 3 private repos remain invisible.
14. `organization_self_hosted_runners:read` — not needed for hunting, useful for inventory hygiene.
