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
| **Last malicious publish / propagation close** | omitted | **09:38 – 13:20Z** | Socket implies ~10:14Z | **12:11:19.909Z** (`@thiennq/docs-viewer@1.6.4`) | **DISAGREEMENT → open, escalated to Tier 0.** 69 minutes unaccounted for. Either the oracle's candidate set is missing a package published between 12:11 and 13:20, or StepSecurity anchored on its last observed *artifact* rather than a publish timestamp. **Do not average.** Re-run `derive_malicious_set` across the second-wave namespaces (§1.4) with a bracket past 14:00Z. Until resolved, hunt to 13:20Z and report 12:11:19.909Z. |
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
   `@hubsync/web-sdk-react` remains unresolved at Tier 0 — unknown, not clean.
2. **Run the dead-drop repository sweep** (§6 checks 1–4) across all three orgs. Never performed.
3. **Enumerate non-default branches** in that sweep (§6 check 7) — up to 50 branches per repo are
   committed to, and a default-branch-only sweep reads a compromised repo as clean.
4. **Re-run Phase 3 against the full ~444-name campaign set**, not the 20 seed pairs (§1.4).
   Expand by **namespace** via `maintainer:` search, not by name list.
5. **Re-run the install-activity check against the registry-derived window** ending
   **12:11:19.909Z**, not 10:40Z or 12:00Z (§1.5). Specifically cover 12:00–12:20Z, which no hunt
   has examined; extend to 13:20Z pending item 1.
6. **Sweep for the token-revocation monitor** (§6.1) across all onboarded hosts — and confirm it is
   removed **before** any credential rotation in a future incident. It survives normal eradication.
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
