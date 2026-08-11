# npm Supply-Chain Campaign — Exposure Report

**Date:** 2026-08-11
**Scope:** SleepNumberInc and sleepnumberlabs GitHub organizations, plus endpoint telemetry via Microsoft Defender Advanced Hunting.
**Classification of this document:** internal. It names repositories and shared workflows. It contains no secrets and no indicator values.

> **This report is about exposure, not compromise.** The threat hunt found no evidence of
> compromise on any vector that could show it — no malicious package version present in any
> lockfile, no attacker-controlled branch, no credential exfiltration behavior, no
> anti-remediation activity. What follows is the door, measured. The hunt result and its
> coverage limits are recorded separately in `exports/hunt/reports/hunt-report-2026-08-11.md`.

Every figure below is read from a collector artifact and carries its denominator. Where a
population could not be measured, it is named as unmeasured rather than reported as zero.

---

## In plain language

Five things. The first three are configuration changes we can start this quarter. The last two
are the structural fixes that stop us having to do the first three again.

**Now — weeks, not quarters, and nothing to purchase:**

1. **Stop handing over the whole keyring.** Our build systems will pass only the one credential
   each job needs, instead of all of them. A configuration change to a small number of shared
   components — four build steps and forty-six shared workflows, which is why it reaches
   thousands of pipelines without thousands of edits. *(§1, §2)*

2. **Stop running supplier code on sight.** Every project will be told not to execute code that
   arrives with a software package unless we have approved it. A one-line change per project,
   and the cheapest protection in this entire report. *(§3)*

3. **Close the nine open doors.** Nine of our automated processes point at names anyone inside
   the company could claim; we repoint them and lock the names so they cannot be taken. Hours
   of work, and the sharpest risk we found. *(§4)*

**Next — the structural fixes:**

4. **Move to badges instead of keys.** Replace stored credentials with short-lived passes issued
   per job and expiring in minutes, so there is nothing durable left to steal. This is what makes
   item 1 permanent rather than a setting someone can undo. *(§6)*

5. **One front door for supplier software.** A managed internal library lets us block a bad
   package everywhere at once, and hold new versions for a few days before builds can use them.
   We already own the front door; almost nothing walks through it. *(§7)*

---

## The chain, in one paragraph

An attacker poisons a public package. Someone's build installs it. The install script runs —
that is the campaign's entry point, and we do not refuse it. The script executes on a runner
that is already holding **every secret the repository has**, because our shared build steps
take the whole secrets context rather than named values. Those secrets deploy to production.
Separately, the same shared steps are referenced by **moving tags**, so anyone who can move a
tag — or push a branch with a deleted name — gets code execution across thousands of pipelines
without needing a poisoned package at all.

Four links. We are exposed on all four.

---

## 1. The whole secrets store is handed to a handful of shared build steps — P1

**What.** Four shared steps receive `toJSON(secrets)`: the complete secrets object, not the
one credential the job needs.

**Where.** 1,924 pipeline references, concentrated almost entirely in one action:

| Sink | Pipeline refs | Via shared workflows | Deploys |
|---|---:|---:|---|
| `SleepNumberInc/terraform-setup-composite-action@v2` | **1,904** | 40 | yes |
| `SleepNumberInc/terraform-setup-composite-action@v1` | 18 | 8 | yes |
| `SleepNumberInc/secrets-to-tfvars-file-creator@v1` | 1 | 1 | yes |
| `Firenza/secrets-to-env@v1.3.0` | 1 | 1 | — |

**How it is exploited.** `@v2` is a tag, not a commit SHA. Moving the tag changes what runs in
1,904 pipelines simultaneously — and that code already holds every secret those pipelines use.
This is precisely the mechanism the worm used against npm, applied to our own internal registry
of build steps. No poisoned package is required; write access to one repository's tags is
enough.

**Mitigate.**
1. Pin each of the four sinks to a commit SHA at every call site.
2. Replace `toJSON(secrets)` with an explicit list of the secrets the step actually consumes.
3. Protect the tag — branch and tag protection on `terraform-setup-composite-action` so moving
   `v2` requires review.

Effort: days. Four files own the mechanism; the call sites are mechanical.
Owner: the platform team that owns `terraform-setup-composite-action`.

---

## 2. Bulk secrets exposure fans out across the estate — P1

**What.** 46 of 95 shared reusable workflow definitions pass the whole secrets context onward.
**37 of the 46 deploy.**

**Where.** 1,823 consumer repositories sit behind them, out of 2,630 total consumer references
across all 95 definitions:

| Shared workflow | Consumers | Deploys |
|---|---:|---|
| `terraform-delete-gha-workflow@v2` | 246 | yes |
| `terraform-unlock-gha-workflow@v2` | 246 | yes |
| `terraform-rename-gha-workflow@v2` | 246 | yes |
| `terraform-import-gha-workflow@v2` | 246 | yes |
| `verify-secrets-gha-workflow@v1` | 107 | no |
| `terraform-infra-ci-gha-workflow@v2` | 103 | yes |
| `terraform-infra-cd-gha-workflow@v2` | 96 | yes |
| `pr-comment-deploy-managed-api-gha-workflow@v2` | 67 | yes |

Four repositories are **confirmed production-reaching**:

- `azure-network-interconnect`
- `devops-github-org-webhook-processor`
- `terraform-infra-cd-gha-workflow`
- `terraform-infra-ci-gha-workflow`

A further 44 repositories have unresolved deployment reach. They are ranked lower on evidence,
not on safety — "we could not confirm it deploys" is not "it does not deploy."

**How it is exploited.** Compromise any step in the chain, or the runner itself, and the
attacker gets every secret rather than the one the job needed. On the 37 deploying definitions,
those secrets reach production.

**Mitigate.** The same narrowing as §1, applied at the *definition* rather than the consumer —
fixing one shared workflow fixes every repository behind it. Order: the four production-confirmed
repositories first, then the four 246-consumer terraform workflows.

Separately, three shared steps *serialize* the secrets context into the build shell in order to
read names off it (219 references; `verify-secrets-dev` and `verify-secrets-all-env` at 107 each).
Reading secret **names** never requires handling their **values** — rewrite these to enumerate
names without expanding the object into the shell.

---

## 3. Install-time scripts are allowed to run — P1

**What.** `ignore-scripts` is the single setting that refuses the campaign's entry point.
Almost nothing sets it.

**Where.** Across 364 npm-relevant repositories, of 2,811 swept; 1,745 workflow files read with
zero read failures:

| Measure | Count |
|---|---:|
| Workflows that install dependencies | 159 |
| …refusing lifecycle scripts at every install | **6** |
| Individual install commands | 187 |
| …carrying `--ignore-scripts` | **9** |
| Config files read (`.npmrc` / `.yarnrc.yml` / `.pnpmrc`) | 39 |
| …setting `ignore-scripts=true` | **1** |
| **Repositories installing with scripts enabled** | **94** |

**How it is exploited.** `preinstall` / `postinstall` is where every payload in this campaign
starts. It runs before any test, any scan, and any human sees the code — on a runner holding
the secrets described in §1 and §2.

**Mitigate.** Add `--ignore-scripts` to the CI install command, or commit an `.npmrc` with
`ignore-scripts=true`. Hours per repository, batchable across the 94. Expect a small number of
packages that genuinely need a build step; record those as named exceptions rather than
skipping the other ninety.

**Two things this sweep cannot answer, stated rather than assumed:**

- In **193** repositories the install may live inside a called action whose definition was not
  read. Closing this needs one read per distinct called action, not per repository.
- **265** repositories show no CI install at all, **73** of which have no workflow file. Their
  dependencies are only ever installed on a developer workstation — which is the surface most
  of this campaign's actual victims were hit on, and which this sweep does not cover.

Neither is a clean result. Both are coverage gaps, not zeroes.

---

## 4. Build steps track moving targets, and nine point at nothing — P3, with an escalation path

**What.** 8,115 action references are on mutable refs (tags or branches). Only **960 are pinned
to a commit SHA** — a 10.6% pinning rate across 5,077 workflows in 999 repositories.

**Where.** The most-referenced unpinned third-party actions:

| Action | Refs |
|---|---:|
| `FranzDiebold/github-env-vars-action@v2.1.0` | 233 |
| `hashicorp/setup-terraform@v1` | 162 |
| `c-py/action-dotenv-to-setenv@v3` | 111 |
| `chrnorm/deployment-action@releases/v1` | 92 |
| `ncipollo/release-action@v1` | 73 |
| `Azure/docker-login@v1` | 70 |

**The sharp edge.** Eleven `uses:` targets resolve to nothing. **Nine of them point at deleted
branches** of central workflow repositories — the repositories exist, the branches were verified
deleted:

`initi` · `use-environment` · `add-copilot-blocker` · `feat/extra-node-ca-cert` ·
`update-to-node-24-actions` · `multipe-primary-image-versions` · `update-provider-inputs` ·
`dependabot-fixes`

**How it is exploited.** Anyone who can push a branch with one of those names into the central
workflow repository gets immediate code execution in every consumer that calls it, with the
consumer's secrets — and these contracts receive `toJSON(secrets)` or `secrets: inherit`.
Consumer repositories are readable organization-wide, so the branch names are discoverable by
reading the callers. **Treat this as an org-member → CD privilege-escalation path, not a broken
build.**

Non-sandbox affected consumers: `snip-iics-mft-ops`, `dot-env-to-env-var-action`,
`eslint-config-azure-integrations`.

The remaining two dangling targets are ordinary breakage: `snip-iics-mft-ops` calls
`iics_cd_workflow.yaml@main` where the file is now `iics_cd.yaml`, and one reference uses
`pr_lint.yml` where the file is `pr_lint.yaml`.

**Mitigate.** Repointing alone is not enough — the name has to be taken off the board as well,
or it stays claimable by the next person who reads the callers.

1. **Repoint** the nine dangling references at a commit SHA on a branch that exists.
2. **Lock the names.** In each central workflow repository, add branch protection rules matching
   the nine deleted branch names so they cannot be re-created by an ordinary org member, and
   restrict branch creation to the repository's maintainers. Steps 1 and 2 are one change; doing
   only the first leaves the door shut but unlocked.
3. Pin the top-referenced third-party actions to SHAs, starting with the six above (741 refs).
4. Add `fetch_status = 'not_found'` as a recurring check after each topology sync, so a
   reference to a deleted branch is caught when it appears rather than at the next hunt.

Hours of work, and the sharpest risk in this report for the least effort.

---

## 5. Secondary findings, each worth a ticket

| Finding | Count | Why it matters to this campaign |
|---|---:|---|
| Workflows with no `permissions:` block | 4,933 of 5,077 | Default token scope, so a compromised step gets more than the job needs |
| Workflows interpolating secrets into `run:` | 838 | Values land in the shell environment and in logs |
| Workflows piping remote code to a shell | 4 | Arbitrary remote code by design — see below |
| Self-hosted runner workflows | 95 | Persistence survives the job; this campaign's watchdog is built for exactly that |
| `id-token: write` with no publish step | 6 | OIDC minting capability that nothing uses |
| Repositories with no identified owner | 33 | Nobody to route a fix to |

The four workflows piping remote code to a shell:

- `SleepNumberInc/sleep-number-claude-code-plugins/.github/workflows/ci.yaml` (2 occurrences)
- `sleepnumberlabs/sdna-new-databricks/.github/workflows/1-sync-databricks-jobs.yml`
- `sleepnumberlabs/sdp-databricks-pytest-poc` (2 files)

---

## 6. Badges instead of keys — the structural fix behind §1 and §2

**What.** Narrowing `toJSON(secrets)` to named values (§1, §2) is a configuration change, and
configuration changes get undone. The durable version is to stop storing the credential at all:
each job asks our identity provider for a short-lived token, scoped to that job, expiring in
minutes. Nothing durable is left on the runner for a poisoned install script to read.

**Where we already stand.** The capability is present and effectively unused. **6** workflows
request `id-token: write` — the permission that mints these tokens — and none of them have a
publish step, so the capability is provisioned and idle. Against that, **1,924** pipeline
references hand over a stored secrets object, and **838** workflows interpolate stored secret
values into a shell.

**How it changes the attack.** With a stored credential, a payload that runs for one second
takes something that is valid for months and usable from anywhere. With a per-job token, it
takes something that expires before the incident call starts and is scoped to one repository's
one job. It does not prevent the install script from running — §3 does that — it removes the
prize.

**Mitigate.** Migrate the deploy path first, since that is where §2's 37 deploying definitions
concentrate: configure OIDC federation between GitHub Actions and the cloud tenant, convert the
four production-confirmed repositories, then the shared workflow definitions. Delete the stored
secrets as each path is converted — an unrotated leftover is the same exposure with a longer
lifetime. Retire the 6 idle `id-token: write` grants if they are not folded into this work.

Effort: a quarter, phased. No purchase required; this is federation configuration, not a product.

---

## 7. One front door for supplier software

**What.** Today, builds resolve packages straight from the public registry. That means there is
no single place to block a known-bad package, and no delay between a version being published and
a build consuming it. A managed internal feed that proxies the public registry gives us both: one
blocklist that applies everywhere at once, and a hold-back window so a new version must sit
unused for a few days before any build can pull it.

**Where we already stand — we own the front door and almost nothing walks through it.** Across
the two Azure DevOps organizations swept (`sn-tim`, `SleepNumberIndigo`), 5 feeds checked and 4
readable:

| Measure | Value |
|---|---|
| Feeds with a `registry.npmjs.org` upstream configured | 3 |
| **npm packages listed across all feeds** | **0** |
| Packages present, all protocols | 523, all NuGet |
| Retention on the one feed that has a policy | 20 versions, 30 days for recently downloaded |

The npm proxy exists and is wired up. Nothing is using it. NuGet, by contrast, does flow
through it — so the pattern is proven inside our own estate; it simply was never applied to npm.

**Why the hold-back window is worth having, measured rather than asserted.** Of **2,208**
malicious version specs from this campaign, **2,097 were no longer resolvable on npm** when we
swept on 2026-08-10 — the ecosystem withdrew roughly 95% of them. A hold-back window converts
that takedown latency into protection: if a build cannot touch a version until it is several
days old, most of these versions are already gone before they are reachable. The remaining
**111 suspected not yet withdrawn** are the residue the window does not catch, which is what the
blocklist half is for.

**Mitigate.**
1. Point CI npm installs at the existing Azure Artifacts feeds rather than `registry.npmjs.org`.
2. Enable an upstream hold-back window on those feeds; start at 3 days and tune on friction.
3. Wire the campaign's package list into the feed blocklist, so a known-bad name is refused
   estate-wide from one place.
4. Request `ReadPackages` on `SleepNumberIndigo/k8s-manifests` — the one feed we could not read
   (see access gap below), so this section's zero covers every feed rather than four of five.

Effort: a quarter. The feeds, the licences and the upstream configuration already exist.

**Access gap blocking full coverage of §7:**

| Field | Value |
|---|---|
| `api` | Azure DevOps REST |
| `endpoint` | `GET https://feeds.dev.azure.com/SleepNumberIndigo/_apis/packaging/Feeds/aa276ed1-83f6-4194-8f07-bebc80762c75/packages` |
| `permission` | `ReadPackages` on feed `SleepNumberIndigo/k8s-manifests` |
| `grant_type` | feed-level permission on the identity already in use |
| `granted_by` | the Azure DevOps administrator of that feed |
| `proves` | whether the feed holds any campaign package name at any version. It has no `registry.npmjs.org` upstream, so it cannot hold a version cached from the public registry; what stays unread is a package published directly into it. |

---

## Order of work

| # | Action | Scope | Effort |
|---|---|---|---|
| 1 | Fix the 9 dangling `uses:` refs | closes an active escalation path | hours |
| 2 | Pin and narrow `terraform-setup-composite-action` | 1,904 pipeline refs | days |
| 3 | Narrow the 4 production-confirmed bulk-secrets repos | then the four 246-consumer terraform workflows | days |
| 4 | Add `--ignore-scripts` across the 94 repos | cheapest control in this report | hours each, batched |
| 5 | Read the 193 called-action definitions | converts an unknown into an answer | one read per distinct action |
| 6 | Estate-wide pinning program | 8,115 references | a program, not a ticket |
| 7 | Per-job short-lived credentials (§6) | removes the prize rather than the access | a quarter, phased |
| 8 | Route npm through the internal feed, with hold-back (§7) | one blocklist, one delay, estate-wide | a quarter |

Items 1–6 reduce what an attacker reaches. Items 7 and 8 change what there is to reach, and are
what stop items 1–4 from being work we repeat after the next campaign.

Two prevention items need no Microsoft or GitHub approval and are not in the table above:

- An egress allowlist on build agents.
- Removing passwordless `sudo` from runner service accounts — verify no build step depends on
  it first.

---

## Provenance

Every figure in this report is read from a collector artifact under `exports/hunt/`
(gitignored). No figure is quoted from recollection.

| Section | Artifact | Collected |
|---|---|---|
| §1, §2 | `reusable_workflow_targets.json` | 2026-08-07 |
| §2 (dangling refs), §4 | `docs/playbooks/deployment-topology.md` §"Dangling references" | 2026-08-07 |
| §3 | `install_prevention_r1.json` | 2026-08-10 |
| §4, §5, §6 | `actions_posture_r5_coverage.json` (read rate 1.0, no truncation) | 2026-08-10 |
| §5 (owners) | `repo_owners_r5.json` | 2026-08-10 |
| §7 (feeds) | `azure_artifacts_feeds_r2.json` | 2026-08-11 |
| §7 (withdrawal rate) | `advisory_coverage.json` | 2026-08-10 |
| hunt result | `exports/hunt/reports/hunt-report-2026-08-11.md` | 2026-08-11 |

**Known coverage limits of the sweeps behind this report:** default branch only; two repository
trees truncated by the GitHub API; developer workstations outside the Defender-onboarded estate
are not covered; the 193 called-action definitions in §3 were not read. These limit what the
report can claim, not what an attacker can reach.
