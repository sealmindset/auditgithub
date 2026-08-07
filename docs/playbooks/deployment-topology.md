# Deployment topology — which repo reaches which environment

Answers "if this repo is compromised, what can the attacker push, where, and with whose
credentials?" Built as **coverage-as-data**: every repository is either resolved with
evidence or is an explicit, counted unknown. A repository with no rows is **not** a
repository that deploys nowhere.

| Artifact | Path |
|---|---|
| Schema (2 tables + coverage view) | `migrations/020_deployment_topology.sql` |
| Schema (P2 indexes / upsert target) | `migrations/021_deployment_observation.sql` |
| ORM models | `src/api/models.py` (`ReusableWorkflowTarget`, `RepoDeploymentMap`, `Deployment`, `DeploymentTarget`) |
| Workflow parser (deterministic, no LLM) | `src/api/utils/reusable_workflow_parser.py` |
| Shared GitHub HTTP layer (throttle vs denial, budget, gaps) | `src/api/utils/github_reader.py` |
| P1 resolver | `src/api/utils/deployment_topology_service.py` |
| P2 observer | `src/api/utils/deployment_observation_service.py` |
| CLI | `scripts/sync_deployment_topology.py`, `scripts/sync_deployment_observations.py` |
| API | `src/api/routers/cicd.py` → `GET/POST /cicd/topology/*` |
| Tests (74) | `tests/test_reusable_workflow_parser.py` (55), `tests/test_deployment_observation.py` (19) |

---

## 1. Why this works at all in this estate

Deployment logic is **not** in the 2500 consumer repos. It lives in a handful of
centrally-shared reusable workflows (`on: workflow_call`) that consumer repos call by ref:

```yaml
jobs:
  cd:
    uses: SleepNumberInc/node-function-app-cd-gha-workflow/.github/workflows/node-function-app-cd.yaml@v3
```

So P1 parses ~dozens of central contracts once, then propagates each contract to every
consumer repo found in the already-populated `dependencies` table
(`package_manager = 'github-action-workflow'`). The per-repo work is only the small part
that is repo-specific: its GitHub Environments and its Actions variables.

Two facts about this estate drove the resolution rule, and both were verified live:

- The `plan` job is gated by `vars.CD_PLAN_ENVIRONMENTS`, but `apply-terraform` and
  `deploy-function-app` are **not**. So the deployable set is **all** of a repo's GitHub
  Environments, not the contents of that gate variable. Reading the gate variable alone
  would undercount production reach.
- Function App name is derived deterministically from the repo slug by the workflow's own
  `sed "s/\-fna//"`, so `snint-fedex-proxy-fna` → Function App `snint-fedex-proxy`
  (`evidence.rule = repo_slug_minus_fna_suffix`).

---

## 2. Capability, not observation

Every P1 row carries `evidence.claim = "deployment_capability_not_observation"`.

P1 says *this repo's CD contract is wired to push to this environment with this identity*.
It does **not** say a deploy happened. Observation is P2's job (GitHub Deployments API →
the existing `deployments` table). Treat a P1 production row as blast radius, not as
evidence of a release.

---

## 3. Methods and confidence

`repo_deployment_map.method` is never overwritten by another method — each method adds its
own rows, so a low-confidence static inference and a high-confidence observed deployment
coexist and can be compared.

| method | Source | Base confidence |
|---|---|---|
| `reusable_workflow` (P1) | Central `workflow_call` contract + consumer's Environments/variables | 0.75 |
| `github_deployment` (P2) | Deployments API — actually happened | (P2) |
| `in_repo_workflow` (P3) | Workflow living in the consumer repo itself | (P3) |
| `iac` (P4) | Terraform/Bicep/manifests in the repo | (P4) |

P1 confidence adjustments, clamped to `[0.10, 0.95]`:

| Signal | Δ |
|---|---|
| Environment-scoped or repo-scoped subscription/account id resolved | +0.10 |
| Deploying identity (`CLIENT_ID`) resolved for that environment | +0.05 |
| Org-scope Actions variables unreadable (rights gap) | −0.15 |
| No cloud identifier resolvable at all | −0.10 |

Variable precedence when resolving an environment: **environment > repo (env-qualified) >
repo > org**. A repo variable carrying a *different* environment token is skipped, so
`TF_DEV_BACKEND_RESOURCE_GROUP` can never be attributed to `prd`.

Unresolved rows are written with `is_resolved = false`, `environment = '__unresolved__'`
and a `unresolved_reason` (`no_environments_defined`, `environments_forbidden`,
`org_variables_forbidden`). The `repo_deployment_coverage` view buckets every repository
into `resolved` / `unresolved` / `unknown`; `unknown` is an unbounded gap, never a zero.

---

## 4. Rights

**P1 needs no new rights.** It runs on the existing PAT (`GITHUB_TOKEN`), verified scopes
`repo`, `workflow`, `admin:org`, `audit_log`. Endpoints used, all read-only:

| Endpoint | Purpose |
|---|---|
| `GET /repos/{o}/{r}/contents/{path}` (raw) | Central workflow YAML |
| `GET /repos/{o}/{r}/environments` | Environment names + protection rules |
| `GET /repos/{o}/{r}/environments/{env}/variables` | Per-environment subscription id, `CLIENT_ID` |
| `GET /repos/{o}/{r}/actions/variables` | Repo-scope variables |
| `GET /repos/{o}/{r}/actions/secrets` | Secret **names** only |
| `GET /orgs/{org}/actions/variables` | Org-scope fallback — **currently 403** |
| `GET /rate_limit`, `GET /user` | Budget accounting |

### Open rights gap

`GET /orgs/SleepNumberInc/actions/variables` → **403**
`"You must be an org admin or have the actions variables fine-grained permission."`

Impact: org-level `TF_BACKEND_*` / `AZURE_TENANT_ID` values cannot be resolved, so affected
rows are written with `unresolved_reason = 'org_variables_forbidden'` and −0.15 confidence.
Request: org admin, or the fine-grained `organization_actions_variables: read` permission on
a GitHub App / fine-grained PAT for `SleepNumberInc`. Not blocking — it lowers precision,
not coverage.

Later phases need rights P1 does not: P2 none, P4 none, **P5 (run logs) is
feature-flagged off** because logs can contain live secrets and must be redacted at ingest
before any DB write, and the cloud-side confirmation phase needs Azure Reader at
management-group scope + Container Registry Repository Reader + AKS RBAC Reader.

---

## 5. Data classification

`repo_deployment_map.evidence` and `reusable_workflow_targets.referenced_secrets` hold
secret and variable **names** plus cloud resource identifiers — subscription ids, resource
groups, service-principal client ids. **Never secret values.** Classify these tables at the
same level as findings exports.

---

## 6. Rate limit is not a rights gap

A throttled run must never be filed as an access request. Two protections:

- `_is_rate_limited()` treats a 403 as throttling only when `X-RateLimit-Remaining: 0` or
  the body mentions a (secondary) rate limit; everything else is a real denial and gets
  recorded as a rights gap with its endpoint.
- `/rate_limit` **cannot be trusted on its own** — observed reporting 4990 remaining while
  the very next real request returned 403 with `X-RateLimit-Used: 5019`. So
  `rate_limit_status()` cross-checks against the headers of a real `GET /user` and takes the
  smaller number (`source: response_headers`).

The PAT's 5000/hr is **shared by every GitHub consumer in the deployment** — org import,
repo sync, scheduled scans, this sync. An org import at 14:37 exhausted the window
(`X-RateLimit-Used: 5019`) and the first P1 run consequently wrote nothing. Arbitration is
now explicit — see §10.

---

## 7. Running it

```bash
# dry run — parses contracts, resolves, writes nothing
docker exec -w /app auditgh_api python3 scripts/sync_deployment_topology.py \
    --org SleepNumberInc --min-consumers 9 --dry-run

# real sync
docker exec -w /app auditgh_api python3 scripts/sync_deployment_topology.py \
    --org SleepNumberInc --min-consumers 9
```

`--min-consumers` skips shared workflows below that consumer count (the long tail of
one-off refs); skipped contracts are counted in `skipped_low_consumers` so the cap is never
silent. `--repo-limit` caps resolutions for incremental runs and sets `truncated` in stats.

API equivalents:

| Route | Returns |
|---|---|
| `POST /cicd/topology/sync` | Runs the sync; `status = "incomplete"` when rate-limited |
| `GET /cicd/topology/workflows` | Parsed central contracts, consumer counts, bulk-secret exposure |
| `GET /cicd/topology/repositories/{repository_id}` | That repo's environments, clouds, identities |
| `GET /cicd/topology/coverage` | Coverage by state, by method, by environment kind, unresolved reasons |

---

## 8. What P1 cannot see

- Anything deployed outside GitHub Actions (manual portal pushes, Azure DevOps pipelines,
  ARM/Bicep applied by hand).
- Environments that exist in the cloud but have no GitHub Environment object.
- Whether a wired deployment path is actually used — that is P2.
- Runtime resource names not derivable from repo slug or Actions variables; those rows carry
  an environment but a null `resource_identifier`.
- Which cloud subscription an org-scope variable points at while the org-variables 403
  stands.

---

## 9. Blast-radius observation from parsing (worth fixing independently)

The central Function App CD contract hands **every** secret to a third-party-shaped
composite action:

```yaml
- uses: SleepNumberInc/terraform-setup-composite-action@v2
  with:
    secrets_json: ${{ toJSON(secrets) }}
```

and `promote` jobs use `secrets: inherit`. Both are recorded per contract in
`reusable_workflow_targets.secrets_bulk_exposure` with mechanism and sink. Consequence: a
compromise of that composite action's ref, or of any called workflow that inherits, exposes
the full secret set for every consumer repo — not just the secrets the job needs. Mitigation
is scoping `with:` to named secrets and pinning composite actions to a commit SHA rather
than a moving `@v2` tag.

---

## 10. Shared rate-limit governance

`src/api/utils/github_budget.py` arbitrates the one PAT between three priority tiers.
State lives in Redis so the API process, CLI scripts and scan subprocesses share one view;
without Redis it degrades and **background work is refused rather than allowed blind**.

| Tier | Who | Floor (calls it must leave) | Gated on idle? |
|---|---|---|---|
| `interactive` | UI requests, a human waiting | 0 — never gated | no |
| `on_demand` | Operator-triggered batch: topology sync, single repo scan | 400 | no |
| `background` | Cron: scheduled repo scans, annealing | 2000 | **yes** |

Rules:

- **Observed, not asserted.** `remaining` comes from `X-RateLimit-*` headers of the last
  real GitHub response, published by `GitHubAPI._make_request` and the topology service.
  `GET /rate_limit` is only a cross-check because it has been seen reporting a full budget
  while real calls were already 403ing.
- **Background yields.** A cron scan is refused while any `interactive`/`on_demand` lease is
  held, or within `GITHUB_IDLE_SECONDS` (default 300s) of such activity, or when
  `remaining - 150 < 2000`.
- **Refusals are visible.** A deferred scan is written to the schedule as
  `last_execution_status = 'deferred_rate_budget'` and logged with the reason. Never a
  silent skip.
- The topology sync holds an `on_demand` lease for its whole run, so cron scans stand down
  while it works.

Inspect live: `GET /scheduler/github-budget` (needs `admin:manage`) returns the snapshot
plus a would-admit decision and reason per tier.

### Scheduler deprioritization

Repository scan cron jobs are **no longer registered at startup**. `SchedulerService` builds
the executor (so on-demand runs work) but skips registering the ~2500 per-repo cron jobs
unless `SCHEDULER_AUTO_REGISTER_REPO_SCANS=true`. Schedules stay in the database and are
runnable via `POST /schedules/{id}/run`, which executes at `on_demand` tier.

When auto-registration is turned on, three further protections apply:

- **Spread**: each schedule's minute is `sha256(schedule_id) % SCAN_SPREAD_MINUTES`
  (default 55) instead of `hh:00`, plus `SCAN_JITTER_SECONDS` (default 600) of jitter.
- **Serialized**: `SCAN_MAX_CONCURRENCY` (default 1) scans at a time.
- **Non-blocking**: scans run via `asyncio.create_subprocess_exec`. The previous
  `subprocess.run` call blocked the API event loop for up to the 2-hour scan timeout, so one
  scheduled scan stalled every request in the process.

| Env var | Default | Effect |
|---|---|---|
| `SCHEDULER_AUTO_REGISTER_REPO_SCANS` | `false` | Register per-repo scan cron jobs |
| `GITHUB_BUDGET_FLOOR_BACKGROUND` | `2000` | Calls cron scans must leave |
| `GITHUB_BUDGET_FLOOR_ON_DEMAND` | `400` | Calls operator runs must leave |
| `GITHUB_IDLE_SECONDS` | `300` | Quiet period before background work may run |
| `GITHUB_SCAN_COST_ESTIMATE` | `150` | Assumed API cost of one repo scan |
| `SCAN_MAX_CONCURRENCY` | `1` | Concurrent scheduled scans |
| `SCAN_SPREAD_MINUTES` | `55` | Window the deterministic minute spreads across |
| `SCAN_JITTER_SECONDS` | `600` | Per-fire random offset |

Tests: `tests/test_github_budget.py` (12) covers floors, priority yielding, window expiry,
and that a zero observation is a real value rather than a missing one.

---

## 11. Dangling workflow refs (finding produced by P1 as a side effect)

`reusable_workflow_targets.fetch_status = 'not_found'` means a consumer repo calls a central
workflow at a ref that does not resolve. Query:

```sql
SELECT r.name AS consumer, d.name AS target, d.version AS ref, d.locations
FROM dependencies d
JOIN repositories r ON r.id = d.repository_id
WHERE d.package_manager = 'github-action-workflow'
  AND (d.name, COALESCE(d.version, '')) IN (
      SELECT source_repo || '/' || workflow_path, ref
      FROM reusable_workflow_targets WHERE fetch_status = 'not_found');
```

As of the 2026-08-06 run: 11 targets / 12 consumer references, dependency inventory dated
2026-08-05. Three causes, and they are not equally serious:

- **9 refs point at deleted feature branches** (`initi`, `use-environment`,
  `add-copilot-blocker`, `feat/extra-node-ca-cert`, `update-to-node-24-actions`,
  `multipe-primary-image-versions`, `update-provider-inputs`, `dependabot-fixes`). The
  central repos exist; the branches were verified deleted. **Two consequences.** The
  consumer's CI/CD is broken today. Worse, the ref is *dangling*: anyone able to push a
  branch of that name in the central workflow repo gets immediate code execution in every
  consumer that calls it, with the consumer's secrets — and these contracts receive
  `toJSON(secrets)` / `secrets: inherit` (§9). Consumer repos are readable org-wide, so the
  branch names are discoverable. Treat as a privilege-escalation path from org member to CD,
  not merely as a broken build.
- **1 renamed path**: `snip-iics-mft-ops` calls
  `snip-iics-ops/.github/workflows/iics_cd_workflow.yaml@main`, but the file is now
  `iics_cd.yaml` (same for the `_ci_` pair).
- **1 stale filename extension**: two repos call
  `pr-lint-workflow/.github/workflows/pr_lint.yml@v1`; tag `v1` exists but the file is
  `pr_lint.yaml`.

Most affected consumers are sandbox/POC repos (`cldsvcs-test-*`, `devops-sandbox-*`,
`ss_gh_poc`, `chads-github-actions-playground`); the non-sandbox ones are
`snip-iics-mft-ops`, `dot-env-to-env-var-action`, `eslint-config-azure-integrations`.

Fix direction: pin `uses:` to a tag or commit SHA rather than a feature branch, and treat
`fetch_status = 'not_found'` as a recurring check after each sync.

---

## 12. Size of the remaining gap (measured, not assumed)

After the uncapped run (`--min-consumers 1`): 333 repositories resolved, 41 unresolved,
**2,166 unknown** (all non-archived, of 2,540 total).

Only 399 repositories have any `github-action-workflow` dependency row at all, so the
unknown bucket is dominated by repos that call no central contract. A deterministic random
sample of 60 unknown repos, probed against the Contents API:

| Result | Count | Extrapolated to 2,166 |
|---|---|---|
| No `.github/workflows` directory at all | 54 | ~1,950 |
| Has workflows | 6 (10%, 95% CI ≈ 4–21%) | ~90–450 |
| Has a deploy-named workflow (`deploy`/`cd`/`release`/`terraform`) | 1 | wide interval; ~35, CI includes single digits |

So P1's coverage of the *centrally-shared contract* path is effectively complete, and the
residual invisible deployment capability is in-repo workflows — phase P3. Example found in
the sample: `snint-cxcomm-proxy-apim` (`terraform_cd.yaml`, `pr_comment_deploy.yaml`), plus
`auditgithub` itself (`deploy-ecs.yml`, an AWS path P1 cannot see).

**Caveat on that estimate**: the ad-hoc probe script used a raw `requests` session, so it did
not publish observations to the budget governor. Any one-off GitHub script should go through
`GitHubAPI` or the topology service, or the shared budget view silently drifts stale.
