# TODO — AuditGH

## Report rendering (uncommitted, working tree only)
- [x] Markdown → HTML → PDF renderer in `src/reporting/`, wired into the six zero-day export endpoints, the scan-report generator, `ReportFormat.PDF`, and a `scripts/report/md2pdf.py` CLI (2026-08-07). 32 tests green
- [x] Three-part report structure — Part 1 Situation / Part 2 Action Plan / Part 3 Evidence, with 3.1 Proof, 3.2 Target Resources, 3.3 Mitigations (2026-08-07). Ordering and every figure computed in code, phrasing model-authored under a no-digits rule; effort as a second axis that never reorders across waves. 43 tests in `tests/test_briefing.py`
- [ ] **Exercise `_author_zda_briefing` against a live provider.** `POST /ai/zero-day` now calls it, but the host cannot import `ai.py` (loguru, psycopg2) so the model path has only been tested against a fake. Confirm: the model's prose survives validation on real output, a rejected first attempt is retried with the reason attached, and the `briefing` object round-trips through the export endpoints unchanged
- [ ] **Check what the briefing costs per analysis.** It adds one LLM call to every zero-day run, with up to one retry. If the retry rate is high the prompt needs work, not the validator — the digit rule is the guarantee the design rests on
- [x] **Verify the six export endpoints in a container** (2026-08-07). All six answer; `tests/test_export_endpoints.py` needed `AUTH_REQUIRED=false` as well as `AUTH_DISABLED=true` — `AuthenticationMiddleware` returns 401 before any dependency resolves, so `dependency_overrides` alone could never reach the route
- [ ] Saved reports in `localStorage` predating the briefing have no `briefing` key. They export via the deterministic fallback, which is correct but silent about *why* — consider saying "this report predates the written summary" rather than "no language model was configured"
- [ ] `src/api/routers/api_audit.py` and the scan-report path in `src/reports/generator.py` build findings from their own shapes; the reach classifier only reads `environment`/`environments`/`archived`. Wire the P1 deployment-topology data in so `reach` is a lookup rather than an inference — it is the multiplier the whole ranking turns on and it is `unknown` for most findings today
- [x] **Rebuild `Dockerfile.api` and render one PDF inside it** (2026-08-07). Rasterised and inspected, which is the only check that finds any of this: every digit in every report was invisible (colour emoji fonts own the ASCII digits and their CBDT bitmaps draw as nothing), and the ✅/⚠️/🔴 marks were blank for the same reason. Fixed with `unicode-range` fences, `fonts-symbola` + `fonts-noto-core`, and a text-presentation rewrite; 133 tests green in the container
- [ ] **`pip install -U weasyprint` on the host.** `requirements.txt` now floors at 69.0 because 69 rejects CSS that 68 silently accepted; the host still resolves 68.1, so it renders a different document from the container and `test_the_stylesheet_has_no_declarations_weasyprint_discards` cannot see the regressions it exists to catch
- [ ] The four severity markers 🔴🟠🟡🔵 differ only by colour, and the outline fonts that make them visible are monochrome — they now render as four near-identical hatched circles. The Severity column next to them carries the meaning, so nothing is lost, but the marker column no longer marks anything. Either drop it from `report.md.j2` or give the severity cell a CSS colour and a shape that survives greyscale
- [ ] Decide staging — shares the working tree with the CHAINDROP work and another session's KQL edits, so `git add -A` is unsafe here too
- [ ] `_offline_url_fetcher` calls `weasyprint.urls.default_url_fetcher`, which warns on every render that it is going away. Move to the `URLFetcher` class before the version that removes it. Fails closed if it is missed — the import raises and the export returns an error rather than reaching the network — but it is the one function standing between LLM-authored report text and an outbound request, so it should not be the thing that breaks on an upgrade
- [ ] Optional: retire `reportlab` once the API-audit PDF export in `src/api/routers/api_audit.py:4228+` moves to the shared renderer. It is the only remaining consumer

## npm supply-chain hunt / CHAINDROP (uncommitted, working tree only)
- [x] Fold the StepSecurity CHAINDROP analysis into all four hunt surfaces (2026-08-06): new per-source IOC file, 8 TTP edits, 10 ids-ips edits, ~13 handover edits, rules 6 → 9
- [x] Reorder incident response so the token-revocation watchdog is removed *before* credentials are rotated — revocation is the payload's trigger (2026-08-06)
- [ ] **Decide staging.** Nothing is committed. Three of the four modified files also carry another session's in-flight KQL edits, so `git add -A` would sweep up work that is not mine. `handoff.md` §2 lists what belongs to whom
- [ ] **Resolve the open Tier 0 escalation.** StepSecurity says propagation closed 13:20 UTC; the registry oracle bounds the last malicious publish at 12:11:19.909Z. Do not average them — re-run `derive_malicious_set` across the second-wave namespaces with a bracket past 14:00Z. Interim rule in force: hunt to 13:20Z, report 12:11:19.909Z
- [ ] **Write shape proofs for the three new rules.** The KQL library covers 6 of 9; there is no `detections/`, `backlog/` or `poc/` file for the watchdog, the Bun fetch or the memory scrape, so their 30-day history is unexamined rather than clean. `github_conf/detections/kql/` is the other session's uncommitted directory — coordinate before adding to it
- [x] **Endpoint hunt run for the first time** (2026-08-07). The report's "Could not check - no access" was false: `GraphClient.from_db` reads the encrypted store, which held an active `ThreatHunting.Read.All` registration the whole time. New `scripts/hunt/hunt_endpoint_defender.py`; control passed (11.5M events / 3,229 devices in an hour), node→bun **0**, `bun.exe` **0** on all three tables, one Homebrew Bun on one macOS device triaged and explained. Vector is now `INCOMPLETE` on 5 named gaps, not `BLOCKED`
- [x] **Doctrine §0.6 enforced in `render_hunt_report.py`** (2026-08-07). `validate_vectors` aborts the render (exit 2) on a status with no coverage evidence, an `INCOMPLETE` with no named residue, a `BLOCKED` with no six-field `access_required`, or a `FINDINGS` naming nothing. Also fixed: the repo-tree sweep's bucket arithmetic, the delta's self-hedged rename warning, and three "Every…" overclaims in Section 1. 34 tests
- [x] **Renderer was reading a stale round artefact** (2026-08-07). `--trees` defaulted to `repo_trees_r3_coverage.json` while `repo_trees_r4_coverage.json` sat beside it three hours newer with the accounting that resolved r3's 50 `tree_failed` entries as empty repositories (49 × `HTTP 409: Git Repository is empty`, 1 × `file_count: 0`). The report claimed 50 repos unread; nothing was unread. `latest_round()` now picks the highest round numerically and the run prints which artefact it read. Files-on-disk is `CLEAR`, buckets sum
- [ ] **Audit the other `--*` defaults for the same staleness class.** `--branches`, `--code-search`, `--ioc` and `--posture` are all pinned to `_r3` filenames. Only trees had an r4, so nothing else is wrong today — but the failure mode is silent and the next re-run creates it
- [ ] **Onboard the 1,380 devices Defender sees but does not receive telemetry from** — 571 "Can be onboarded", 555 "Unsupported", 254 "Insufficient info", against 3,424 reporting. They cannot produce a hit either way, so they are the entire distance between this vector and `CLEAR`. Renders as action P2 in the hunt report
- [ ] **`SHA256` is empty on every Linux `DeviceProcessEvents` row** (0 of 111,867). Provenance triage on any future Bun or payload binary is a hash comparison, so Linux is blind to it no matter how suspicious the path looks. Windows and macOS are fully populated
- [ ] **Request `AuditLog.Read.All`** so `GET /auditLogs/signIns` works app-only. Until then sign-in analysis must come from `AADSpnSignInEventsBeta` / `IdentityLogonEvents`, which `ThreatHunting.Read.All` does cover — a workaround, not a gap, but it should be written down where the next person looks. Now emitted by the collector as a structured §0.6 `access_required` entry and rendered in Section 3 as a request forwardable to a tenant admin as-is
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
