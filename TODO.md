# TODO — AuditGH

## Deployment topology (branch `deployment-topology-p1-p2`)
- [x] P1 — capability map from centrally-shared reusable workflows (2026-08-06): 4207 rows / 374 repos / 288 reaching production, 84 contracts parsed
- [x] Shared GitHub budget governor + scheduler deprioritization (2026-08-06)
- [x] P2 — deployment observation service, migration 021, CLI, 2 API routes, 19 tests (2026-08-06, code complete)
- [ ] Apply `migrations/021_deployment_observation.sql` — **P2 writes fail without it** (upsert needs `uq_deployments_repo_external_id`)
- [ ] Finish P2 docs in `docs/playbooks/deployment-topology.md`: §2 converse warning, §3 `github_deployment` confidence rubric, new §13
- [ ] Verify in container once Docker responds: 86 tests, and `POST /cicd/topology/observe` + `GET /cicd/topology/activity` registered (resolve via `original_router.routes`; `/openapi.json` is auth-protected)
- [ ] Run P2: `--dry-run` to size cost, then `--repo-limit 25`, then the full mapped set; re-run to prove resume skips completed repos
- [ ] Decide on P3 (in-repo workflow parsing, ~2200 calls, closes the measured ~90–450 repo gap)

## Security
- [ ] **File ticket: 9 consumer repos call central workflows at deleted branches.** Dangling ref = org member who can push that branch name gets code execution in every consumer, with the consumer's secrets. Detection SQL in playbook §11
- [ ] **File ticket: pin `terraform-setup-composite-action@v2` to a commit SHA.** 46 contracts hand it `toJSON(secrets)`; a moving tag means one action compromise exposes every consumer's full secret set (playbook §9)
- [ ] Request org-variables read: `GET /orgs/SleepNumberInc/actions/variables` returns 403. Ask for org admin or fine-grained `organization_actions_variables: read`. Lowers precision, not coverage
- [ ] Address Dependabot alerts: 5 high + 11 moderate on SleepNumberInc remote, 3 high + 10 moderate on sealmindset remote
- [x] Run `/fix-it medium` — 15 of 18 MEDIUM findings resolved (2026-05-22)
- [ ] postcss XSS vulnerability (transitive via next) — awaiting Next.js patch, no safe upgrade path
- [ ] Run `/fix-it all` to clear remaining LOW (5) + INFO (2) findings
- [ ] Fix pre-existing TypeScript error in `components/APIAuditView.tsx:1052` (`external_url` property)
- [ ] Merge `security-workstation` branch to `main` when ready

## Docs
- [ ] Review and commit `docs/EA_Design_Pattern_AWS_Bedrock.md` and `docs/EA_Design_Pattern_MakeIt.md` (untracked)

## Cleanup
- [ ] Review `.scan_resume_state.pkl` — commit or add to .gitignore
- [x] `.cache/` (431 npm scan JSONs) added to .gitignore (2026-08-06)
- [ ] Docker Desktop was unresponsive at wrap-up (`docker info` timed out) — restart before next session
