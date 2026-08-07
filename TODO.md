# TODO — AuditGH

## Report rendering (uncommitted, working tree only)
- [x] Markdown → HTML → PDF renderer in `src/reporting/`, wired into the six zero-day export endpoints, the scan-report generator, `ReportFormat.PDF`, and a `scripts/report/md2pdf.py` CLI (2026-08-07). 32 tests green
- [x] Three-part report structure — Part 1 Situation / Part 2 Action Plan / Part 3 Evidence, with 3.1 Proof, 3.2 Target Resources, 3.3 Mitigations (2026-08-07). Ordering and every figure computed in code, phrasing model-authored under a no-digits rule; effort as a second axis that never reorders across waves. 43 tests in `tests/test_briefing.py`
- [ ] **Exercise `_author_zda_briefing` against a live provider.** `POST /ai/zero-day` now calls it, but the host cannot import `ai.py` (loguru, psycopg2) so the model path has only been tested against a fake. Confirm: the model's prose survives validation on real output, a rejected first attempt is retried with the reason attached, and the `briefing` object round-trips through the export endpoints unchanged
- [ ] **Check what the briefing costs per analysis.** It adds one LLM call to every zero-day run, with up to one retry. If the retry rate is high the prompt needs work, not the validator — the digit rule is the guarantee the design rests on
- [ ] **Verify the six export endpoints in a container.** They have never been called. The host cannot import `src/api/routers/ai.py` (loguru, psycopg2 absent) and Docker was down, so the wiring is written and unit-tested but unexercised end to end. Check `POST /zero-day/export/{pdf,docx,md}` and `/zero-day/export/repos/{pdf,docx,md}`
- [ ] Saved reports in `localStorage` predating the briefing have no `briefing` key. They export via the deterministic fallback, which is correct but silent about *why* — consider saying "this report predates the written summary" rather than "no language model was configured"
- [ ] `src/api/routers/api_audit.py` and the scan-report path in `src/reports/generator.py` build findings from their own shapes; the reach classifier only reads `environment`/`environments`/`archived`. Wire the P1 deployment-topology data in so `reach` is a lookup rather than an inference — it is the multiplier the whole ranking turns on and it is `unknown` for most findings today
- [ ] **Rebuild `Dockerfile.api` and render one PDF inside it.** The added fonts are the untested part: on a fontless image WeasyPrint emits a PDF of empty boxes rather than failing, so a passing import proves nothing. Confirm emoji verdict marks are glyphs, not tofu
- [ ] Decide staging — shares the working tree with the CHAINDROP work and another session's KQL edits, so `git add -A` is unsafe here too
- [ ] Optional: retire `reportlab` once the API-audit PDF export in `src/api/routers/api_audit.py:4228+` moves to the shared renderer. It is the only remaining consumer

## npm supply-chain hunt / CHAINDROP (uncommitted, working tree only)
- [x] Fold the StepSecurity CHAINDROP analysis into all four hunt surfaces (2026-08-06): new per-source IOC file, 8 TTP edits, 10 ids-ips edits, ~13 handover edits, rules 6 → 9
- [x] Reorder incident response so the token-revocation watchdog is removed *before* credentials are rotated — revocation is the payload's trigger (2026-08-06)
- [ ] **Decide staging.** Nothing is committed. Three of the four modified files also carry another session's in-flight KQL edits, so `git add -A` would sweep up work that is not mine. `handoff.md` §2 lists what belongs to whom
- [ ] **Resolve the open Tier 0 escalation.** StepSecurity says propagation closed 13:20 UTC; the registry oracle bounds the last malicious publish at 12:11:19.909Z. Do not average them — re-run `derive_malicious_set` across the second-wave namespaces with a bracket past 14:00Z. Interim rule in force: hunt to 13:20Z, report 12:11:19.909Z
- [ ] **Write shape proofs for the three new rules.** The KQL library covers 6 of 9; there is no `detections/`, `backlog/` or `poc/` file for the watchdog, the Bun fetch or the memory scrape, so their 30-day history is unexamined rather than clean. `github_conf/detections/kql/` is the other session's uncommitted directory — coordinate before adding to it
- [ ] **Run `coverage/07` to confirm `SHA1` is populated** on `DeviceFileEvents` for the `gh-token-monitor.*` filenames. `stopAndQuarantineFiles` alerts without quarantining if it is empty. Sole blocker on arming `token-monitor`, which is the new rule most worth arming — an alert does not disarm a watchdog
- [ ] Run the hunt checks added 2026-08-06 that have **never been executed**: all branches (up to 50/repo), the `${{ toJSON(secrets) }}` primitive rather than the workflow filename, npm publisher-side abuse (`bypass_2fa: true` tokens, self-minted attestations), the persistence sweep, and the wide credential-rotation scope
- [ ] Enumerate `LANG` / locale across the estate — the payload declines to run under a Russian locale and those hosts read clean on every behavioural rule
- [ ] Prevention needing no Microsoft approval: package-manager-native release-age gate rollout; egress allowlist on build agents; remove passwordless `sudo` from runner service accounts (verify no build step depends on it first)

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
- [x] Merge `security-workstation` branch to `main` — its tip `dc87754` is now an ancestor of `origin/main`. The local branch is merged and safe to delete; `origin/security-workstation` still lags by 4 commits

## Docs
- [ ] Review and commit `docs/EA_Design_Pattern_AWS_Bedrock.md` and `docs/EA_Design_Pattern_MakeIt.md` (untracked)

## Cleanup
- [ ] Review `.scan_resume_state.pkl` — commit or add to .gitignore
- [x] `.cache/` (431 npm scan JSONs) added to .gitignore (2026-08-06)
- [ ] **Docker Desktop still down** — `docker info` returned no server version and `docker compose ps` exited 1 at wrap-up on 2026-08-06 (second session in a row). Restart it before any container work; the 86-test container run and migration 021 are both blocked on it
- [ ] Worktree `../auditgithub-deps` (branch `deps-webui-safety`, clean, unmerged) left in place deliberately — another session's. Do not remove it
