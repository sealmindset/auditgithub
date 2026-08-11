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

**Mitigate.**
1. Fix the nine dangling references first. It is the cheapest item in this report and carries
   the worst upside for an attacker.
2. Pin the top-referenced third-party actions to SHAs, starting with the six above (741 refs).
3. Add `fetch_status = 'not_found'` as a recurring check after each topology sync, so a
   reference to a deleted branch is caught when it appears rather than at the next hunt.

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

## Order of work

| # | Action | Scope | Effort |
|---|---|---|---|
| 1 | Fix the 9 dangling `uses:` refs | closes an active escalation path | hours |
| 2 | Pin and narrow `terraform-setup-composite-action` | 1,904 pipeline refs | days |
| 3 | Narrow the 4 production-confirmed bulk-secrets repos | then the four 246-consumer terraform workflows | days |
| 4 | Add `--ignore-scripts` across the 94 repos | cheapest control in this report | hours each, batched |
| 5 | Read the 193 called-action definitions | converts an unknown into an answer | one read per distinct action |
| 6 | Estate-wide pinning program | 8,115 references | a program, not a ticket |

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
| §4, §5 | `actions_posture_r5_coverage.json` (read rate 1.0, no truncation) | 2026-08-10 |
| §5 (owners) | `repo_owners_r5.json` | 2026-08-10 |
| hunt result | `exports/hunt/reports/hunt-report-2026-08-11.md` | 2026-08-11 |

**Known coverage limits of the sweeps behind this report:** default branch only; two repository
trees truncated by the GitHub API; developer workstations outside the Defender-onboarded estate
are not covered; the 193 called-action definitions in §3 were not read. These limit what the
report can claim, not what an attacker can reach.
