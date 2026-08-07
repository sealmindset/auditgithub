# Handoff -- AuditGitHub (CHAINDROP threat-hunting corpus)
_Written 2026-08-06 15:32 by /clear-it. Read this file in full before continuing work._

> The previous handoff (deployment topology P1/P2) is archived in `.handoff-history.md`.
> That work is now **committed** (`5b749b9`, `9e27efc`) but its next steps are still open —
> see §6 item 6 below. This session went somewhere else entirely.

## 1. Goal

Rob's ask: *"Review the following analysis — https://www.stepsecurity.io/blog/chaindrop-npm-worm
and determine what should be incorporated or included in the NDA/Threat Hunting"*, then
**"Yes plus All four hunt docs"** — i.e. write the determination into the whole npm
supply-chain corpus, not just one playbook.

Four write targets:
- `docs/playbooks/supply-chain-hunt-ttp.md` (hunt methodology)
- `docs/playbooks/npm-supply-chain-ids-ips.md` (technical playbook)
- `docs/playbooks/npm-supply-chain-rollout-handover.md` (approval/rollout doc)
- `github_conf/detections/npm_supply_chain_rules.json` + the `github_conf/ioc/` files

Acceptance: every new claim attributable to a named source, contradictions recorded rather
than averaged, and no new rule presented as coverage before its plumbing is proven.

Constraints from Rob, still in force:
- Use only existing credentials (`GITHUB_TOKEN`, `DATABASE_URL`). Any permission denial is
  reported as a rights gap with the exact endpoint so an access request can be filed.
- Do not drain the shared 5000/hr GitHub budget.
- Deployer invariant: **dry run is the default; `--force` does NOT override
  `killSwitch.armed: false`** — that would collapse the two-key control into one key.

## 2. Current State

Branch `deployment-topology-p1-p2`. **This session's work is COMPLETE and verified.
Nothing was committed** — deliberately; see §5.

`git status`:
```
 M docs/playbooks/npm-supply-chain-ids-ips.md
 M docs/playbooks/npm-supply-chain-rollout-handover.md
 M docs/playbooks/supply-chain-hunt-ttp.md
 M github_conf/detections/npm_supply_chain_rules.json
?? github_conf/ioc/chaindrop_stepsecurity_2026_08.json
?? github_conf/IOC_KQL.zip
?? github_conf/detections/kql/
?? nmptemp
?? scripts/ioc/run_kql_poc.py
```
Diffstat vs HEAD: 4 files, +1406 / −178.

**Verified:** `npm_supply_chain_rules.json` parses; `python3 scripts/ioc/deploy_detection_rules.py`
(dry run is the default) reports **9/9 rules validated, nothing sent** — 5 `[skip: no --arm]`
for the armed-in-file rules, 4 `[skip: armed=false in file]` for the unarmed ones. Two-key
control intact.

**The last four `??` entries and three of the four `M` files carry ANOTHER SESSION's
uncommitted work.** `github_conf/detections/kql/`, `scripts/ioc/run_kql_poc.py`,
`github_conf/IOC_KQL.zip` and `nmptemp` are entirely theirs — I never touched them. My edits
to the two npm playbooks and the rules JSON are layered on top of their in-flight edits to
the same files. **Staging is Rob's call.**

Not done, and never claimed as done: the three new detection rules are undeployed, unarmed,
and have no proof-of-concept/shape-proof coverage.

## 3. Active Files

- `github_conf/ioc/chaindrop_stepsecurity_2026_08.json` — NEW. StepSecurity assertions,
  one source per file so a claim can be attributed and contradicted. **First file in the
  corpus with a non-empty `contradicts` array** (2 entries, both unresolved).
- `github_conf/detections/npm_supply_chain_rules.json` — 6 → 9 rules. Patched via a
  throwaway Python script, not by hand-editing JSON.
- `docs/playbooks/supply-chain-hunt-ttp.md` — 8 edits. §1.1 source tiering, §1.3 round-2
  arbitration table, §1.4 namespace expansion, §1.5 both ends of the window, §6 checks 7–9,
  new §6.1 (persistence sweep) and §6.2 (rotation scope), §7 verdicts, §9 rewritten as 14
  numbered items.
- `docs/playbooks/npm-supply-chain-ids-ips.md` — 10 edits. §4.1 nine rules with a Status
  column, §4.6 arming count, §4.7 library-coverage caveat, §5.1 indicators, §5.2 six
  prevention controls, §6 third structural gap, §7 step 1.5.
- `docs/playbooks/npm-supply-chain-rollout-handover.md` — ~13 edits. Revision block, §2
  five-things, §6 Step 5, §7 containment table + two GAP subsections, **§8 reordered**,
  Appendix A (6)→(9) with A7–A9, Appendix C rebuilt, Appendix D items 5–10, Appendix E
  de-staled, Related documents.
- `scripts/ioc/deploy_detection_rules.py` — NOT modified. Used only as the validator.

## 4. Changes Made

All uncommitted.

**Three new rules, all `armed: false`:**

| Rule | Severity | Tier | Why it exists |
|---|---|---|---|
| `npm-shaihulud-token-monitor` | high | quarantine-only | The watchdog is the only artefact that survives deleting `setup.mjs`, `math_init.js`, `.claude/` and `.vscode/` |
| `npm-shaihulud-bun-fetch` | medium | isolate-selective | Earliest network event in the chain — fires *before* credential collection, where `c2-contact` fires after |
| `npm-shaihulud-runner-mem-scrape` | high | isolate-full | Writes no file, opens no connection; the hash/C2/exfil rules are all blind to it |

**Fixed a pre-existing factual error** in `npm-shaihulud-c2-contact`'s `recommendedActions`:
it described "the four attacker-controlled domains (npm-cache.com, js-mirror.com,
pypi-get.com, and the `/router` path)" — counting a URL *path* as a domain. The fourth
domain is `awqhnjewqjkl.icu`, and `/router` is separately the exfil path.

**The safety-critical change.** `npm-supply-chain-rollout-handover.md` §8 step 1 was
*"Rotate credentials before eradication."* CHAINDROP's watchdog polls
`https://api.github.com/user` every 60s for 24h and **executes the payload when the token
stops authenticating** — revocation is its trigger, not its remedy. A new step 1 (watchdog
removal, with runnable Linux/macOS commands) now precedes rotation, matching
`npm-supply-chain-ids-ips.md` §7 step 1.5. Order is **remove watchdog → rotate → eradicate**.
Written explicitly as a narrow carve-out that does *not* reverse "rotate before eradicate" —
the payload still exfiltrates first, so cleaning everything before rotating still destroys
evidence while credentials stay live.

**Content added across the corpus:** two `setup.mjs` loader hashes with byte sizes
(29,918 / 11,017) instead of one; stage-2 hash at 727,680 B; `awqhnjewqjkl.icu` → `Block`;
Bun release CDN marked explicitly **do not create an indicator** (blocking it breaks
legitimate installs — detect via A8); 75-endpoint on-chain RPC fallback, so the three RPC
hostnames are telemetry not a chokepoint; bidirectional exfil (`code` field → `eval()`),
therefore a contacted host is scoped as arbitrary code execution; `gh-token-monitor.*`
artefact table; AI credential paths (`.claude/credentials.json`, `.codex/auth.json`,
`.cursor/credentials.json`, `.openai/auth.json`, `.anthropic/auth.json`, `.gemini/.env`);
two exfil-workflow variants (`codeql_analysis.yml` **and** a `Run Copilot` push workflow),
both keyed on the `${{ toJSON(secrets) }}` primitive; `bun-dl-*` staging dirs and
`tmp.dpkg_<pid>.lock`; 10 second-wave namespaces and 8 publishers; the pre-publish timeline
(09:02:37 `ee2681a` → 09:35:00.763 `keyv@6.0.0` via the project's own legitimate release
workflow); package-manager-native release-age gates (npm 11.10+, pnpm 10.16+, Yarn 4.10+,
Bun 1.3+, Dependabot `cooldown`).

Design decisions worth not re-litigating:
- **One source, one file.** StepSecurity claims went into their own file rather than being
  merged into `shai_hulud_2026_08.json`, so a claim can be attributed and a contradiction can
  be recorded instead of averaged away.
- **Namespaces, not names.** Expansion is by npm scope (`@servicetitan` 141,
  `@onereach` 78, `@or-sdk` 74, …) and by `maintainer:` search, because namespaces are stable
  while the token is live and both enumerate from Tier 0.
- **Version deliberately omitted** from `bun-fetch`'s predicate so a Bun version bump does
  not blind the rule.
- **`runner-mem-scrape` must be `--scope`d** to the CI device group, never tenant-wide. Its
  third predicate (shell-initiated python touching `/proc/`) is admitted in the file as the
  weakest of the three.
- **All three new rules unarmed**, but for three *different* reasons, each recorded in its
  own `justification`: `token-monitor` only awaits a baseline cycle and a `SHA1` check;
  `bun-fetch` has a real benign population; `runner-mem-scrape` needs CI-owner sign-off
  because isolating a shared runner takes out every pipeline on it.

## 5. Failed Approaches -- DO NOT RETRY

**From this session:**

- **The worktree instinct.** Standard discipline says branch/worktree for new work. Caught
  before acting: the files to edit were *uncommitted in this checkout and shared with
  another live session*, so a worktree would branch from the last commit and silently drop
  their in-flight edits. Conclusion: when targets are uncommitted and shared, **edit in
  place and commit nothing**. Verify by diffing the other session's changes first — theirs
  were confined to KQL-PoC material (§4.7, Appendix E, Step 0/Step 2), which did not overlap.
- **Asking two AskUserQuestion questions at once.** Rob interrupted the tool call, then
  answered `"1"`. He answers terse and will combine answers across earlier option lists
  ("Yes plus All four hunt docs"). Conclusion: one question, fewer options.
- **Assuming a presented menu constrains him.** He redirected off the offered
  deployment-topology P2 menu entirely via free text. Do not treat option lists as
  exhaustive.
- **Believing a zero-result grep over the corpus.** A coverage matrix returned 0 for all 55
  patterns including `keyv`; `grep -c "keyv" docs/playbooks/supply-chain-hunt-ttp.md`
  returned 23. Cause: unparenthesized `find … -name '*.kql' -o -name '*.md'` feeding
  `grep -ril --`. Conclusion: **grep was broken, not the corpus.** Write the file list to
  `/tmp/corpus.txt` with a properly parenthesized `find` first, and prove any zero with a
  single-file positive control before reporting it.
- **Treating "the IOC file has it" as coverage.** `awqhnjewqjkl.icu` sat in an ingested
  source file while every rule and every indicator list omitted it, for an unknown period.
  Conclusion: **ingesting a source file creates the appearance of coverage.** Encoded in
  three places so it cannot recur silently — the §7 "adding a new campaign" 3-step process
  (step 2 is *diff the new source file against the indicator list and the deployed rules,
  and record the diff*), the §1.3 round-2 process-failure note, and `_ioc_source_files_note`
  in the rules JSON.
- **Trusting a behavioural zero.** The malware declines to run under a Russian `LANG`, so
  those hosts read clean on every behavioural rule. Conclusion: a control proves the query
  *could* find the thing, not that the malware *would have run* — a behavioural zero needs a
  control **and** an evasion-condition check. Recorded in §0.1 of the TTP doc.
- **Provenance/SLSA as a control.** Defeated twice in this campaign: self-minted
  attestations, and the project's *own legitimate release workflow* publishing `keyv@6.0.0`
  at 09:35:00.763. Conclusion: attestation proves *who built it*, not *that it is safe*. The
  usable control is review-time diffing of release tooling (`release-publish.ts`), not
  verification at install time.

**Carried forward (still relevant, from the archived deployment-topology handoff):**

- **Trusting `GET /rate_limit`** *(carried forward)* — it reported 4990 remaining while the
  next real request 403'd with `X-RateLimit-Used: 5019`. Only `X-RateLimit-*` on real
  responses is authoritative. Do not "simplify" `rate_limit_status()`'s cross-check away.
- **Letting tests share governor Redis keys** *(carried forward)* — a test run flushed the
  live estate's budget state. Fixed with `GITHUB_BUDGET_KEY_PREFIX` plus an import-time
  assertion. **Never remove that assert.**
- **Ad-hoc scripts using raw `requests`** *(carried forward)* — ~60 calls bypassed the budget
  governor and the shared view drifted stale. Any one-off GitHub script must go through
  `GitHubAPI` or a `GitHubReader` subclass.
- **`docker exec` / `docker ps`** *(carried forward)* — both hung past 120s last session
  (Docker Desktop unresponsive). Check daemon health first; host fallback is
  `python3 -m pytest --noconftest` (conftest imports `src/api/main.py`, which needs `loguru`).
- **Editing playbooks by long multi-line `old_string`** *(carried forward)* — one edit failed
  on exact string mismatch. Avoided entirely this session by reading the exact lines
  immediately before each edit. Keep doing that.

## 6. Next Steps

1. **Rob decides staging.** Nothing is committed. Three modified files and the working tree
   are shared with another live session, so `git add -A` would sweep up their in-flight KQL
   work. Ask before staging anything; a targeted `git add` of the four files I touched is
   the safest option, and even that stages their edits to three of them.
2. **Resolve the open Tier 0 escalation.** StepSecurity puts the propagation close at
   13:20 UTC; the Tier 0 registry oracle bounds the last malicious publish at
   `@thiennq/docs-viewer@1.6.4`, 12:11:19.909Z. Per §1.2 this is a DISAGREEMENT and escalates
   to Tier 0 — **do not average the two.** Resolve by re-running `derive_malicious_set` across
   the second-wave namespace list in `chaindrop_stepsecurity_2026_08.json` with a bracket
   extending past 14:00Z. Interim rule now written into all four docs: **hunt to 13:20Z,
   report 12:11:19.909Z.**
3. **Write shape proofs for A7/A8/A9** (Appendix D item 5). The KQL library covers 6 of 9
   rules — there is no `detections/`, `backlog/` or `poc/` file for the watchdog, the Bun
   fetch or the memory scrape, so their 30-day history is *unexamined*, not clean. Note
   `github_conf/detections/kql/` is the other session's uncommitted directory; coordinate
   before adding files to it.
4. **Run `coverage/07` to confirm `SHA1` is populated** on `DeviceFileEvents` for
   `gh-token-monitor.*` filenames. `stopAndQuarantineFiles` silently alerts-without-
   quarantining if `SHA1` is empty. This is the single blocker on arming `token-monitor`,
   which is the new rule most worth arming — an *alert* does not disarm a watchdog.
5. **Run the never-performed hunt checks.** §6 checks 7–9 and §6.1–§6.2 of
   `supply-chain-hunt-ttp.md` were added 2026-08-06 and have **never been executed**: all
   branches (up to 50/repo), the `toJSON(secrets)` primitive rather than the filename, npm
   publisher-side abuse (`bypass_2fa: true` tokens, self-minted attestations), the
   persistence sweep, and the wide credential-rotation scope.
6. **Deployment topology P2 is still outstanding** — unblocked and unchanged since it was
   committed. In order: apply `migrations/021_deployment_observation.sql` (P2 writes fail
   without `uq_deployments_repo_external_id`); verify the container once Docker responds
   (86 tests, two new `/cicd/topology/*` routes); `--dry-run`; `--repo-limit 25`; then the
   full mapped set. Full detail in `.handoff-history.md`.
7. **Still awaiting Rob's direction, from P1**: file tickets for the 9 dangling `uses:` refs
   to deleted branches (org member → CD privilege escalation) and for pinning
   `terraform-setup-composite-action` to a commit SHA instead of the moving `@v2` tag. The
   CHAINDROP work sharpened the second one: 46 central contracts hand `${{ toJSON(secrets) }}`
   to that moving tag, which is exactly the primitive this worm's exfil workflows use.
