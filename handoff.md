# Handoff -- AuditGitHub (npm supply-chain threat hunt)
_Rewritten 2026-08-11. Read this file in full before continuing work._

> The 2026-08-06 version of this file described the CHAINDROP corpus work as uncommitted.
> **That was true when it was written and is false now** -- the rules JSON, the per-source IOC
> file and both npm playbooks landed in `874bd0f` on 2026-08-07, and the reporting work in
> `0ee72c3`. Verified with `git log -- github_conf/ioc/chaindrop_stepsecurity_2026_08.json
> github_conf/detections/npm_supply_chain_rules.json`. Older handoffs are in
> `.handoff-history.md`.

## 1. Goal

Extend the npm supply-chain hunt so that every advisory-named technique is either measured or
declared unmeasured, and so that a clean result is only reported where a control proves the
query could have found the thing.

Constraints from Rob, still in force:
- Use only existing credentials (`GITHUB_TOKEN`, `DATABASE_URL`). Any permission denial is
  reported as a rights gap with the exact endpoint so an access request can be filed.
- Do not drain the shared 5000/hr GitHub budget.
- Deployer invariant: **dry run is the default; `--force` does NOT override
  `killSwitch.armed: false`** -- that would collapse the two-key control into one key.

Two rules that govern everything written here:
- **Prove it or do not report it.** No claim without an artifact behind it; every access gap
  in the six-field form (api, endpoint, permission, grant_type, granted_by, proves).
- **American English.** `artifact`, not `artefact`. Never rewrite a vendor field name, a JSON
  key a consumer reads, or a quoted error.

## 2. Current State

Branch `deployment-topology-p1-p2`, tip `9dc46dc`. Round 6 of the hunt is **committed**.

Working tree at the time of writing:
```
 M scripts/hunt/hunt_commit_messages.py     <- this session, described in section 4
?? tests/test_hunt_commit_messages.py       <- this session
?? github_conf/IOC_KQL.zip                  <- another session's; leave it
?? nmptemp                                  <- another session's; leave it
```
`exports/` is gitignored (`.gitignore:93`), so hunt artifacts never enter a commit. The
worktree `../auditgithub-deps` (branch `deps-webui-safety`) belongs to another session --
do not remove it.

Tests, run on the host as `python3 -m pytest --noconftest` (the repo conftest imports
`src/api/main.py`, which needs `loguru`):
- `tests/test_hunt_report.py` -- **49 passed**
- `tests/test_hunt_commit_messages.py` -- **11 passed** (new this session)
- Deployment topology 74/74; budget governor 7 of 12 on the host; detection rules 9/9
  validate with nothing sent; 30 KQL queries lint clean and **none executed**; NeMo 26/26.

Docker Desktop is **down** -- `Cannot connect to the Docker daemon at
unix:///Users/rob.vance@sleepnumber.com/.docker/run/docker.sock`. Third session running.
It blocks migration 021, the 86-test container run, and every P2 verification step.

Report renders exit 0, **AMBER**, 14 vectors, 13 actions, to
`exports/hunt/reports/hunt-report-2026-08-11.md`.

## 3. Vector status -- what is closed and what each open one waits on

Fourteen vectors: **5 CLEAR / 5 INCOMPLETE / 3 FINDINGS / 1 CORROBORATING.** Taken from the
rendered summary table, row by row -- see the last entry in section 5 for why that sentence is
in this document.

`INCOMPLETE` has a specific meaning here, set in the report itself: *found nothing in what was
read, and a named, counted set of items was not read -- items we have the access to read and
have not.* It is unfinished work, not a blind spot. Anything that no privilege and no query
can reach belongs on the coverage axis instead, and the four below are each written against
that distinction.

**Closed this session.** *Commit-message sweep* (report section 4.8) moved `INCOMPLETE` ->
`CLEAR`. See section 4.

**Open, with what each is waiting on:**

1. **Internal package registry (proxy of npmjs)** -- section 4.11. The feed listing returned
   0 npm packages across 5 feeds, 3 of which proxy `registry.npmjs.org`, so the zero against
   the campaign set is not a measured absence: the listing did not enumerate npm, so it could
   not have matched. The artifact says so itself -- `coverage_supports_negative_finding:
   false`.
   *Waiting on:* an Entra ID access token for the Azure DevOps resource at `/tmp/.ado_tok`.
   There is none on disk and `.env` holds no Azure DevOps credential. Rob acquires it
   interactively -- in this session, `! az account get-access-token --resource
   499b84ac-1321-427f-aa17-267ca6975798 --query accessToken -o tsv > /tmp/.ado_tok` -- then
   re-run `scripts/hunt/check_azure_artifacts.py` listing npm specifically per feed. Feeds
   needing it: `sn-tim/sn-tim`, `sn-tim/sn-tim-packages`,
   `SleepNumberIndigo/SleepNumberIndigo`.
   *Plus one true access gap*, six-field: api `Azure DevOps REST`, endpoint
   `GET /_apis/packaging/Feeds/{feedId}/packages`, permission `ReadPackages` on feed
   `SleepNumberIndigo/k8s-manifests`, grant_type feed-level permission on the existing
   identity, granted_by the feed's Azure DevOps administrator, proves whether that feed
   carries any campaign package. It has no npmjs upstream configured, which bounds the
   consequence but does not close it.

2. **Endpoint install activity (Microsoft Defender)** -- section 4.12. A contradiction, not a
   clean result: 69 package-manager install command lines ran in the window while
   `DeviceNetworkEvents` recorded 0 tarball fetches, so package downloads are not observable
   on that table and matching against 2,208 specs could not happen. Separately, 2,670
   lifecycle-script executions on 101 devices cannot be attributed to a package, because
   `DeviceProcessEvents` records `node install.cjs` without the package that owns it.
   *Waiting on:* a proxy or web-gateway log source. This is **not** grantable inside Defender
   -- `RemoteUrl` carries no path on the platforms that install npm packages (measured: 3 of
   5 devices that ran an install in the window are macOS), so no permission on any Defender
   role changes the answer. Identify the egress proxy's log owner and file for read access
   there; until that exists this vector cannot answer and must not be read as though it does.

3. **Endpoint / identity (Microsoft Defender)** -- section 4.17. Five named residue items:
   571 devices in onboarding state `Can be onboarded`, 554 `Unsupported`, 254 `Insufficient
   info` -- none reporting, so none can produce a hit; `SHA256` empty on every Linux
   `DeviceProcessEvents` row, so hash-based provenance triage is blind there; sign-in history
   read from hunting tables rather than the audit log.
   *Waiting on*, in two parts. The device half is an onboarding program, not a query: the
   honest figure is **807** (516 unmonitored Workstation/Server plus 291 `DeviceType:
   Unknown`), not 1,379 -- and the caveat that must travel with it is that excluding the 557
   network/printer/IoT/mobile devices rests on Defender's own `DeviceType` classification,
   not on a query proving they lack a node toolchain. The sign-in half is a permission, and
   the artifact already carries it six-field: api `Microsoft Graph`, endpoint
   `GET /auditLogs/signIns`, permission `AuditLog.Read.All`, grant_type application (app-only)
   with admin consent, granted_by a Microsoft 365 Global Administrator or Privileged Role
   Administrator. The Linux `SHA256` emptiness is a vendor telemetry gap -- no permission
   fills that column.

4. **Advisory IOC sweep -- campaign infrastructure and file hashes** -- section 4.18. Eleven
   hunting queries, none failed. The residue is one indicator that cannot be matched at all:
   the advisories name a User-Agent, `Bun/1.3.13`, and `DeviceNetworkEvents` carries no
   User-Agent column.
   *Waiting on:* the same proxy or web-gateway source as item 2 -- and stated in the artifact
   in exactly those terms, that this indicator "cannot be matched on endpoint telemetry by
   anyone with any permission." Requesting a Defender role would not close it. The two
   coverage gaps beneath it (macOS `RemoteUrl`, Linux hashes) are the population bounds on the
   domain and hash sweeps, not residue.

5. **Anti-remediation watchdog sweep** -- section 4.19. The sweep itself is clean: the
   `gh-token-monitor` watchdog was swept by name and independently by shape, 13 queries, none
   failed. The residue is not unread data -- *a clean watchdog sweep does not make the
   remediation ORDER safe.* The watchdog is triggered by revocation, so the control is a
   runbook that removes persistence from every affected host before the first credential is
   rotated. That ordering **is written** -- `docs/playbooks/supply-chain-hunt-ttp.md` §6.3,
   six steps, removal verified on the host with `pgrep -af gh-token-monitor` rather than from
   an alert, matching `npm-supply-chain-ids-ips.md` §7 step 1.5.
   *Waiting on:* an incident-response process change. No IR process here requires that step
   before a rotation, and the sweep cannot establish that it would be followed. This one
   closes by a human gate being added, not by a query being run -- so if it stays `INCOMPLETE`
   it will stay `INCOMPLETE` forever. Worth deciding whether it belongs as an action with the
   vector reading `CLEAR`, which is what the sweep result actually supports.

Two coverage gaps that are correctly *not* residue, because no privilege reaches them: 98
macOS devices populate no `RemoteUrl` at all over 30 days (2,965,542 rows), and 311 Linux
devices carry neither `SHA1` nor `SHA256` on effectively any `DeviceFileEvents` row.

**The shape of what is left.** Of the five open vectors, exactly one -- the registry proxy --
closes with a credential we already hold the right to. Three (endpoint install activity,
advisory IOC sweep, and the sign-in half of endpoint/identity) wait on a log source or a
permission that has to be requested from someone outside this work. One (anti-remediation)
waits on a human process gate and no query will ever move it. That is worth saying plainly to
anyone who reads the report as a to-do list: the remaining work is mostly not hunting.

## 4. Changes Made This Session

**`scripts/hunt/hunt_commit_messages.py`** -- new `sweep_side_branch_messages()` and
`read_range_commits()`, plus `MESSAGE_MARKERS`, wired into `main()` behind
`--skip-side-branch-sweep` and `--max-ranges`.

The vector was `INCOMPLETE` for one measured reason: commit search does not index commits that
exist only on a non-default branch -- proven, not cited, by the existing control (0 of 5
off-default commits returned, 3 of 3 on-default returned). This campaign pushes to up to 50
side branches per repository, so that gap decided whether the vector's zero meant anything.
Two passes now close it:

- **Free pass.** `branches_r5.json` already holds `message_first_line` for every in-window
  commit the branch collector inspected. Matching the marker set against text already on disk
  read **112 messages, 75 of them on a ref that is not the default branch** -- the exact
  population the index misses -- for zero requests. The matcher is proven on that text rather
  than assumed: control token `feat(snip-2048):` matched 3 messages.
- **Range pass.** The branch collector reads the *head* commit of each in-window push; a push
  carries a range. `GET /repos/{o}/{r}/compare/{before}...{after}`, paginated, read **118 of
  141 in-window push events and 786 commits** with their full message text. A branch creation
  has no `before`, so its range is measured from the default branch.

Result: **0 marker hits**, and the vector renders `CLEAR`.

Two things deliberately did *not* get swept under it. Three pushes exceeded the compare
endpoint's own 250-commit ceiling; for those the ref's history is listed instead, bounded to
the campaign window, and the substitution is recorded in the artifact rather than left silent.
And 15 commits plus 23 deletion events are on refs deleted inside the window -- HTTP 422, the
object is gone. That is a coverage gap owned by the repository owners (a fork, a backup or a
local clone is the only thing that holds them), not unfinished work of ours.

**`tests/test_hunt_commit_messages.py`** -- 11 probes, all on the offline half so they need no
network: the extortion string matches on a side branch, matching survives case, a benign
message matches nothing, an HTTP 422 placeholder is counted unreadable rather than clean, a
hit carries the ref it was pushed to, the matcher control is drawn from data the sweep really
read, a deleted ref is an unreadable range rather than one that read clean, a branch creation
compares against the default branch, a cap reports what it dropped, and a missing token makes
a range an error rather than a clean read.

Artifact is now `exports/hunt/commit_messages_r3.json`; the renderer's `latest_round()` picks
it up with no flag change.

## 5. Failed Approaches -- DO NOT RETRY

**From the CHAINDROP session (2026-08-06), all still binding:**

- **The worktree instinct.** Standard discipline says branch/worktree for new work. When the
  files to edit are *uncommitted in this checkout and shared with another live session*, a
  worktree branches from the last commit and silently drops their in-flight edits. When
  targets are uncommitted and shared, **edit in place and commit nothing**, and diff the other
  session's changes first.
- **Asking two AskUserQuestion questions at once.** Rob interrupted the tool call, then
  answered `"1"`. He answers terse and combines answers across earlier option lists ("Yes plus
  All four hunt docs"). **One question, fewer options.**
- **Assuming a presented menu constrains him.** He redirects off offered menus with free text.
  Option lists are not exhaustive.
- **Believing a zero-result grep over the corpus.** A coverage matrix returned 0 for all 55
  patterns including `keyv`; `grep -c "keyv"` on one file returned 23. Cause: unparenthesized
  `find ... -name '*.kql' -o -name '*.md'`. **grep was broken, not the corpus.** Write the
  file list to `/tmp/corpus.txt` with a properly parenthesized `find` first, and prove any
  zero with a single-file positive control.
- **Treating "the IOC file has it" as coverage.** `awqhnjewqjkl.icu` sat in an ingested source
  file while every rule and indicator list omitted it. **Ingesting a source file creates the
  appearance of coverage.** Encoded in three places so it cannot recur silently.
- **Trusting a behavioral zero.** The malware declines to run under a Russian `LANG`, so those
  hosts read clean on every behavioral rule. A control proves the query *could* find the
  thing, not that the malware *would have run* -- a behavioral zero needs a control **and** an
  evasion-condition check.
- **Provenance/SLSA as a control.** Defeated twice in this campaign: self-minted attestations,
  and the project's *own legitimate release workflow* publishing `keyv@6.0.0` at 09:35:00.763.
  Attestation proves *who built it*, not *that it is safe*.

**Carried forward, still relevant:**

- **Trusting `GET /rate_limit`** -- it reported 4990 remaining while the next real request
  403'd with `X-RateLimit-Used: 5019`. Only `X-RateLimit-*` on real responses is authoritative.
  Do not "simplify" `rate_limit_status()`'s cross-check away.
- **Letting tests share governor Redis keys** -- a test run flushed the live estate's budget
  state. Fixed with `GITHUB_BUDGET_KEY_PREFIX` plus an import-time assertion. **Never remove
  that assert.**
- **Ad-hoc scripts using raw `requests`** -- ~60 calls bypassed the budget governor. A one-off
  GitHub script goes through `GitHubAPI` or a `GitHubReader` subclass; the hunt collectors'
  own shared helpers in `hunt_code_search.py` are the established pattern inside `scripts/hunt`.
- **`docker exec` / `docker ps`** -- both hung past 120s. Check daemon health first; host
  fallback is `python3 -m pytest --noconftest`.
- **Editing playbooks by long multi-line `old_string`** -- read the exact lines immediately
  before each edit.

**New, from this session:**

- **Believing a count I published rather than the render.** I reported "5 INCOMPLETE" and wrote
  it into `CHANGELOG.md`; the render listed six. Rob then repeated my number back to me, which
  is exactly how a wrong figure becomes load-bearing. **Take vector counts from the rendered
  report, never from an earlier message.**
- **Assuming an artifact reflects the current source.** `antiremediation_r1.json` still carries
  `behaviour` in its scope string; `hunt_antiremediation.py:780` says `behavior`. The artifact
  predates the spelling pass and the report renders the artifact. A stored artifact is a
  record of a past run, not a view of the code -- it clears on the next collector run, which
  needs Defender access.

## 6. Next Steps

1. **Decide the anti-remediation vector's shape** (section 3 item 4). Its residue is an IR
   process gate, not unread data, so as written it can never reach `CLEAR`.
2. **Get an Azure DevOps token and finish the registry proxy** (section 3 item 1). One
   interactive `az` command from Rob, then a re-run. This is the only open vector whose
   closure is entirely in our hands today.
3. **Resolve the open Tier 0 escalation.** StepSecurity puts the propagation close at
   13:20 UTC; the Tier 0 registry oracle bounds the last malicious publish at
   `@thiennq/docs-viewer@1.6.4`, 12:11:19.909Z. **Do not average them.** Re-run
   `derive_malicious_set` across the second-wave namespaces with a bracket past 14:00Z.
   Interim rule in force in all four docs: **hunt to 13:20Z, report 12:11:19.909Z.**
4. **Write shape proofs for A7/A8/A9.** The KQL library covers 6 of 9 rules -- the watchdog,
   the Bun fetch and the memory scrape have no `detections/`, `backlog/` or `poc/` file, so
   their 30-day history is *unexamined*, not clean. `github_conf/detections/kql/` is the other
   session's uncommitted directory; coordinate before adding to it.
5. **Run `coverage/07` to confirm `SHA1` is populated** on `DeviceFileEvents` for
   `gh-token-monitor.*`. `stopAndQuarantineFiles` alerts without quarantining if it is empty.
   Sole blocker on arming `token-monitor`, the new rule most worth arming -- an alert does not
   disarm a watchdog.
6. **Run the never-executed hunt checks**: §6 checks 7-9 and §6.1-§6.2 of
   `supply-chain-hunt-ttp.md` -- all branches (up to 50/repo), the `${{ toJSON(secrets) }}`
   primitive rather than the workflow filename, npm publisher-side abuse (`bypass_2fa: true`
   tokens, self-minted attestations), the persistence sweep, the wide rotation scope.
7. **Audit the other `--*` renderer defaults** for the staleness class that bit `--trees`:
   `--branches`, `--code-search`, `--ioc` and `--posture` are pinned to `_r3` filenames.
   Nothing is wrong today; the failure mode is silent and the next re-run creates it.
8. **Deployment topology P2**, blocked on Docker: apply
   `migrations/021_deployment_observation.sql` (P2 writes fail without
   `uq_deployments_repo_external_id`), verify the container (86 tests, two `/cicd/topology/*`
   routes), then `--dry-run`, `--repo-limit 25`, the full mapped set.
9. **Still awaiting Rob's direction, from P1**: file tickets for the 9 dangling `uses:` refs to
   deleted branches (org member -> CD privilege escalation) and for pinning
   `terraform-setup-composite-action` to a commit SHA. The CHAINDROP work sharpened the second
   -- 46 central contracts hand `${{ toJSON(secrets) }}` to that moving tag, exactly the
   primitive this worm's exfil workflows use.
