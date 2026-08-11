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

Branch `deployment-topology-p1-p2`, tip `83595fa` (the Kodem ingestion). Rounds 6 and 7 of the
hunt are **committed**.

Working tree at the time of writing:
```
 M scripts/hunt/hunt_advisory_iocs.py       <- this session, section 4
 M CHANGELOG.md / TODO.md / handoff.md      <- this session
?? tests/test_hunt_advisory_iocs.py         <- this session
?? github_conf/IOC_KQL.zip                  <- another session's; leave it
?? nmptemp                                  <- another session's; leave it
```
`exports/` is gitignored (`.gitignore:93`), so hunt artifacts never enter a commit. The
worktree `../auditgithub-deps` (branch `deps-webui-safety`) belongs to another session --
do not remove it.

Tests, run on the host as `python3 -m pytest --noconftest` (the repo conftest imports
`src/api/main.py`, which needs `loguru`) -- **82 passed** across the four hunt files:
- `tests/test_hunt_report.py` -- **50**
- `tests/test_hunt_commit_messages.py` -- **13**
- `tests/test_check_azure_artifacts.py` -- **10**
- `tests/test_hunt_advisory_iocs.py` -- **9** (new this session)
- Deployment topology 74/74; budget governor 7 of 12 on the host; detection rules 9/9
  validate with nothing sent; 30 KQL queries lint clean; NeMo 26/26.

**Docker is up as of 2026-08-11** -- all eight containers running (`auditgh_api`, `auditgh_db`,
`auditgh_ui`, `auditgh-redis`, `auditgh_minio`, `auditgh_mailpit`, `auditgh_mock_oidc`,
`auditgh_session_cleanup`). That unblocked the Defender half of the hunt, which ran, and it
also unblocks migration 021 and every P2 verification step -- **none of the P2 work has been
done yet.** Run the Defender collectors from inside the container, not the host: the host
python has no `psycopg2` and cannot reach the credential store, so
`docker exec -w /app auditgh_api python scripts/hunt/<collector>.py` is the invocation.

Report renders exit 0, **AMBER**, 14 vectors, **14 actions**, to
`exports/hunt/reports/hunt-report-2026-08-11.md`. Estate-wide unread residue 9 -> 5,
unobservable populations 11 -> 15 -- both moved because four endpoint items changed axis, not
because coverage changed. See section 4.

## 3. Vector status -- what is closed and what each open one waits on

Fourteen vectors: **6 CLEAR / 4 INCOMPLETE / 3 FINDINGS / 1 CORROBORATING.** Taken from the
rendered summary table, row by row -- see the last entry in section 5 for why that sentence is
in this document.

`INCOMPLETE` has a specific meaning here, set in the report itself: *found nothing in what was
read, and a named, counted set of items was not read -- items we have the access to read and
have not.* It is unfinished work, not a blind spot. Anything that no privilege and no query
can reach belongs on the coverage axis instead, and the four below are each written against
that distinction.

**Closed this session.** Two vectors moved `INCOMPLETE` -> `CLEAR`: the *commit-message sweep*
(report section 4.8) and the *internal package registry* (section 4.11). See section 4.

**Open, with what each is waiting on:**

1. **Endpoint install activity (Microsoft Defender)** -- section 4.12. A contradiction, not a
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

2. **Endpoint / identity (Microsoft Defender)** -- section 4.17. Five named residue items:
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

3. **Advisory IOC sweep -- campaign infrastructure and file hashes** -- section 4.18. Eleven
   hunting queries, none failed. The residue is one indicator that cannot be matched at all:
   the advisories name a User-Agent, `Bun/1.3.13`, and `DeviceNetworkEvents` carries no
   User-Agent column. Re-run 2026-08-11 against live Defender: it first returned **FINDINGS at
   critical severity on five rows that were this hunt testing this collector** -- see section 4.
   After the classifier fix the command-line population is 0 egress / 0 text / 5 ours, every one
   of the five written verbatim to `command_line_analysis_references`, and the vector is back to
   `INCOMPLETE` on the User-Agent.
   *Waiting on:* the same proxy or web-gateway source as item 1 -- and stated in the artifact
   in exactly those terms, that this indicator "cannot be matched on endpoint telemetry by
   anyone with any permission." Requesting a Defender role would not close it. The two
   coverage gaps beneath it (macOS `RemoteUrl`, Linux hashes) are the population bounds on the
   domain and hash sweeps, not residue.

4. **Anti-remediation watchdog sweep** -- section 4.19. The sweep itself is clean: the
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

**The shape of what is left.** Nothing among the four open vectors can be closed by running
anything. Three (endpoint install activity, advisory IOC sweep, and the sign-in half of
endpoint/identity) wait on a log source or a permission that has to be requested from someone
outside this work; one (anti-remediation) waits on a human process gate and no query will ever
move it. The two that *were* ours -- the commit-message sweep and the registry proxy -- are
both closed. That is worth saying plainly to anyone who reads the report as a to-do list: the
remaining work is not hunting.

One access request still stands even though its vector reads `CLEAR`, and it is in the
report's access table for that reason: `ReadPackages` on `SleepNumberIndigo/k8s-manifests`.
The feed has no `registry.npmjs.org` upstream, so it cannot hold a version *cached* from the
public registry -- which is the question the vector asks and answers. What it leaves unread is
a package *published directly* into that feed. Different question, still open, named.

## 4. Changes Made This Session

### The Defender half ran, and the first thing it found was us (2026-08-11)

Docker came back up, so the four Defender collectors ran for the first time in four days --
from inside `auditgh_api` (`docker exec -w /app auditgh_api python scripts/hunt/…`), which has
`psycopg2` and reaches the encrypted credential store. The host interpreter still cannot; treat
the container form as the invocation, not a workaround for one afternoon. The repo is mounted
rw at `/app`, so the artifacts land on the host where the renderer reads them.

**`hunt_advisory_iocs.py` returned FINDINGS, severity critical.** Five rows, one device,
`usffhg6x7jh4` -- Rob's workstation. Every one was a Claude Code shell invocation from
2026-08-07 or 2026-08-10 running a `python3` heredoc that imports this very module to exercise
`classify_command_line`, and the heredoc carries `curl -s https://npm-cache.com/x` as a **test
fixture**. `curl` is an egress tool, the scan is over the whole command line as flat text, and
the classifier checked the tool before the path. A quoted string inside a test for this
detection was promoted into a critical finding by the detection it was testing.

Worth being precise about the mechanism, because the obvious reading is wrong: it is *not*
that python is egress-capable. `python3 -c` classifies as a read tool. The tool that matched
was `curl`, and it really was in the text -- which is exactly why the tool cannot be the
discriminator and the path can.

The defect underneath is duplication, not classification. `hunt_antiremediation.py` had already
solved this and, in the same cycle on the same estate, correctly demoted **247** rows of this
exact kind while this collector was calling five of them critical. Two divergent copies of one
judgement. `ANALYSIS_MARKERS` and the path-before-tool ordering are now ported across verbatim.

It **demotes, it does not delete** -- the line that keeps this from being suppression:

- the class is named `analysis_corpus_reference` and counted, and the three buckets provably
  sum to the population (0 + 0 + 5 = 5);
- all five rows are written verbatim to `command_line_analysis_references`, so a reader who
  disagrees can re-read exactly what was demoted;
- an unrecognized shape still defaults to `egress_capable` -- unseen means reported, not clean;
- the markers are **paths, not a device allowlist**. A bare `curl https://npm-cache.com` on
  that same laptop is still a finding, and `tests/test_hunt_advisory_iocs.py` pins it.

Residual risk, stated rather than buried: an attacker running their fetch from inside a
directory named `auditgithub` is demoted too. Accepted -- the alternative is reporting our own
instrumentation as critical every cycle, and a vector nobody reads detects nothing. The two
copies of this judgement can still drift; lifting them into one shared module is in TODO.

**Endpoint collector: 6 queries -> 16.** Two ran for the first time. The `ir/52` persistence
sweep returned 0 rows over 30 days across `DeviceFileEvents` and `DeviceRegistryEvents`, with
each half separately controlled as non-empty -- so that zero survives §0.1. And `coverage/07`
answered the `token-monitor` arming blocker in the negative: `SHA1` is not populated
estate-wide (Windows10 **81.7%**), so `stopAndQuarantineFiles` no-ops silently while the alert
fires. Detail and the resulting decision are in section 8, item 5.

**The four "blind spot newly registered" lines in the delta are a reclassification, not a
regression** -- and the report demands by name that whoever changed the collector say which.
This is that line. The three Defender onboarding states and the Linux `SHA256` absence were
sitting in `unresolved_items`, which means *items we have the access to read and have not*,
when in fact no privilege reaches them at all. They are coverage. Estate-wide residue falls
9 -> 5 and unobservable populations rise 11 -> 15 because the same four items moved axis.
Nothing went dark and nothing was measured for the first time. Report stays **AMBER**, 14
actions.

### Kodem ingested, and the failure mode it exposed (2026-08-11)

**`github_conf/ioc/kodem_2026_08.json`** -- new. Kodem had been in the §1.1 source table since
the reference run and credited in the consensus matrix for the `Math_Symbol.js` hash, with **no
file in `github_conf/ioc/`**. This corpus already recorded the inverse desync -- Elastic and
StepSecurity ingested as files before they had rows -- and treated it as the embarrassing one.
It is the harmless one. **A citation reads as coverage**, and this direction leaves a source
looking consumed when it was only seen.

Fixed-string diff against the whole corpus. Most of Kodem is relay: three hashes, `npm-cache`,
`104.21.35`, `router_runtime.js`, `bun-dl-*`, the OIDC exchange endpoint, `Bun/1.3.13`, the
persistence set, all seven second-wave scopes -- all already held from primary sources. Three
things were not:

1. **`169.254.169.254`.** A keyword audit would have called this covered: `IMDSv2` is in
   StepSecurity's file, "cloud instance metadata service endpoints" in Elastic's, Alibaba and
   Tencent metadata in Cycode's, IMDSv2 in the playbook and in `npm_supply_chain_rules.json`.
   **Every one of those is on the response side** -- what to reissue once you already know a
   host was hit. The address was in no rule, no KQL file and no collector, so nothing here
   could have *surfaced* the contact. New `kql/backlog/23-imds-contact-from-install-lineage.kql`,
   deliberately a backlog **question** and not an armed rule -- see section 6 item 4a for the
   three preconditions on promoting it, and why arming on the address alone kills the rule.
2. **The first marker for the wrong direction of infection.** Every marker
   `hunt_commit_messages.py` held is text the worm writes *on a victim*. `add setup.mjs and
   Math_Symbol.js to all @keyv/* packages` is what the **operator** wrote on the repository
   being poisoned. A hit means a repository here was used as the *source*. Held as two
   fragments, because the scope glob differs per namespace: the payload-file half is decisive
   and is now also an org-wide query (`source_side_plant_message`); the scope half is a lead
   only and stays out of the org-wide search, because a keyv maintainer could write it about
   anything.
3. **A runbook that would detonate the watchdog.** Kodem rotates at step 1 and hunts
   persistence at step 7. §6.3 inverts that on purpose -- `gh-token-monitor` fires *when the
   token stops authenticating*, so revocation is its trigger. Recorded in the file as an
   explicit conflict rather than silently not adopted.

Its Socket 14:05 / 15:39-15:44Z timeline is refuted by our own bracket-independence proof and
does not reopen the window closed on 2026-08-10. Its blast-radius counts (353 to 868 depending
on vendor) are not reconciled with ours: we derive the set, we do not cite it.

**Hunt re-run, same day.** `commit_messages_r5.json`: 3 orgs x **7** indicators (was 6), 0
decisive hits, 0 leads, positive controls 16,998 / 44,206 / 7,430. Offline sweep unchanged at
112 stored messages (75 off-default) and 118 of 141 ranges / 786 commits, now matched against
8 markers. Vector stays `CLEAR`; report stays **AMBER**. The 23 unreadable ranges are the
deleted-ref coverage gap, unchanged and still named.

**The Defender half did not run, and it is not an access gap.** Measured:
`hunt_endpoint_defender.py:209` -> `src/api/database.py:22` -> `ModuleNotFoundError: No module
named 'psycopg2'`, and the Postgres holding the encrypted credential store is in Docker, which
is down. Two independent blockers. **Do not file an access request** -- the registration in the
store carries `ThreatHunting.Read.All` and the 2026-08-07 run proved it. `endpoint_hunt.json`
is four days stale and the report's own "re-run 8 stale collectors" action already carries it.

`vector_endpoint()` now appends the IMDS line on **both** paths -- artifact present and
artifact absent -- because the collector does not ask that question either way. Attaching it
only to the `NOT RUN` fallback would have let a successful run silently drop it, which is the
same shape as "the artifact exists, so the vector is covered".

### Earlier this session

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

**`scripts/hunt/check_azure_artifacts.py`** -- new `classify_feed_coverage()`,
`blocking_feeds()` and `access_required_for()`; `coverage_supports_negative_finding` is now
`bool(proved_rows) and not blocking_feeds(...)`.

This vector was not waiting on data. It was waiting on its own verdict expression, which
carried a blanket `not feeds_with_errors` term beside the narrower rule stated three
paragraphs above it in the same file -- *an unreadable feed matters only where it has an
npmjs upstream to cache from*. The one 403 on this estate is
`SleepNumberIndigo/k8s-manifests`, which has no such upstream, so a feed that structurally
cannot hold a cached withdrawn version was voiding the reading of the other four. The token
was needed to re-run, and Rob acquired it, but the token was never what stood in the way.

Also wrong, and repeated in the renderer's docstring: the claim that "the listing did not
enumerate npm". `list_packages()` has always sent `protocolType=npm`. The listing enumerated
npm and returned nothing.

The coverage verdict is now per feed and has three states, because these zeros are not
equally strong:
- `measured_with_positive_control` -- ReadPackages held and a row came back from the same
  endpoint, host and token, either from this feed or from a sibling in the same organization.
  That is what makes `sn-tim/sn-tim`'s empty list an answer: `sn-tim/sn-tim-packages`
  returned 520 rows on the same call shape moments earlier.
- `measured_by_permission_probe_only` -- ReadPackages proven by the retention endpoint (it
  403s without it), but no feed in that organization returned any row.
  `SleepNumberIndigo/SleepNumberIndigo` is the only one, and it is named in the report rather
  than folded into the good case.
- `unmeasured_no_read_packages` -- the 403. Emitted six-field into the artifact's
  `access_required`, which the renderer now carries onto the vector *even though it reads
  `CLEAR`*.

An empty feed is deliberately **not** treated as a failed control. It cannot produce a row,
and the only act that would make one appear is publishing into production infrastructure --
which this collector's own limits forbid.

Renderer: `--registry-proxy` now defaults through `latest_round()` instead of the pinned
`azure_artifacts_feeds.json`, which is the staleness class already flagged for `--branches`,
`--code-search`, `--ioc` and `--posture`. Without it the re-run's artifact
(`azure_artifacts_feeds_r2.json`) would have sat on disk unread.

**`tests/test_check_azure_artifacts.py`** -- 10 probes, all pure functions over records, no
Azure DevOps calls: a sibling feed is a control and a cross-organization feed is not, a denial
is unmeasured rather than weakly measured, an unreadable feed without the upstream does not
block while one with it does, a readable feed that errored still blocks, an empty feed is not
a failed control, and each access request names the endpoint that was denied and says what
stays unread.

## 5. Failed Approaches -- DO NOT RETRY

**From 2026-08-11:**

- **Reading the §1.1 source table as an inventory of what was ingested.** It is an inventory of
  what was *cited*. Kodem had a row for a week and no file. When auditing that table, check
  **both** directions -- a file with no row has no tier and cannot be arbitrated; a row with no
  file is a source nobody read while the table said otherwise.
- **Treating a technique's presence in the rotation scope as detection coverage.** `IMDSv2`
  appeared in four IoC files and two playbooks, and the estate still could not see a single
  metadata contact. Response-side text and detection inputs are different corpora; grep does
  not distinguish them.
- **Widening a hunt window on a vendor timeline when a registry oracle already answered.**
  Kodem relays a Socket 15:39-15:44Z publish. Round 4's brackets at 18:00Z and 2026-08-05T00:00Z
  return the identical 2,208 specs, so nothing published at 15:39Z exists. Derive, do not cite.
- **Attaching a new coverage caveat to a vector's `NOT RUN` fallback only.** The first
  `vector_endpoint()` edit put the IMDS line in the fallback, and the artifact existed -- so the
  line never rendered. If the caveat is a property of the *query set*, it belongs on every path.
- **Classifying a command line on the tool before the path.** `hunt_advisory_iocs.py` scans the
  whole command line as flat text, so a `curl` quoted inside a heredoc counts as a `curl`. The
  hunt's own test fixtures came back as five critical C2 contacts. The path being worked in is
  the discriminator; the tool never is. Sibling collectors already knew this, which is the
  second lesson -- **when a judgement exists in one collector, port it rather than re-derive
  it.** Two copies drifted, and the drift is what shipped a critical false positive.
- **Reading `python3 -c` as egress-capable.** It classifies as a read tool and that is correct.
  Chasing that premise cost a wrong test and a wrong docstring before the actual match -- a
  quoted `curl` -- turned up. Read the row that fired before theorizing about why it fired.

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
- **Believing a collector's residue text over its code.** The registry-proxy vector said for
  two rounds that "the listing did not enumerate npm", and I repeated it into `handoff.md` and
  `TODO.md` as the thing a token would fix. `list_packages()` sends `protocolType=npm` and
  always did. The residue sentence was written from a plausible theory about why the number
  was zero, and once written it was quoted rather than checked. **A collector's own prose
  about why it failed is a claim like any other -- read the function before repeating it.**
- **Treating a coverage flag as ground truth because a collector set it.**
  `coverage_supports_negative_finding: false` was correct output from an expression that
  contradicted the rule stated in the same file. The flag was not lying about what it computed;
  it was computing the wrong thing. **A self-reported coverage flag still has to be read
  against the doctrine it claims to implement.**
- **Assuming an artifact reflects the current source.** `antiremediation_r1.json` still carries
  `behaviour` in its scope string; `hunt_antiremediation.py:780` says `behavior`. The artifact
  predates the spelling pass and the report renders the artifact. A stored artifact is a
  record of a past run, not a view of the code -- it clears on the next collector run, which
  needs Defender access.

## 6. Next Steps

1. **Decide the anti-remediation vector's shape** (section 3 item 4). Its residue is an IR
   process gate, not unread data, so as written it can never reach `CLEAR`. This is now the
   only open vector where a decision -- rather than somebody else's grant -- changes anything.
2. **File the two access requests** the other three open vectors depend on: read access to the
   egress proxy / web-gateway logs (endpoint install activity, and the `Bun/1.3.13` User-Agent
   in the advisory IOC sweep), and `AuditLog.Read.All` on Microsoft Graph. A third is filed
   against a vector that reads `CLEAR`: `ReadPackages` on `SleepNumberIndigo/k8s-manifests`.
   All three are six-field in the report's access table.
3. ~~**Resolve the open Tier 0 escalation.**~~ **CLOSED 2026-08-10, in StepSecurity's favor.**
   This entry stayed open here and in `TODO.md` for a day after `supply-chain-hunt-ttp.md`
   row 315 recorded the resolution, which is its own lesson: the doc that carries the
   decision and the doc that carries the work list drifted. Round 4 re-derived against the
   live registry with brackets at 18:00Z and at 2026-08-05T00:00Z and got the **identical**
   2,208 specs across 442 names, latest publish 13:18:41.376Z -- 79 seconds from 13:20Z.
   **Bracket-independence is the result**, not the 79 seconds: widening the window does not
   move the set. The interim "hunt to 13:20Z, report 12:11:19.909Z" rule is **withdrawn**;
   scope runs to 13:30:46.398Z. Kodem relays a Socket 15:39-15:44Z publish claim, which the
   same proof refutes -- a version published then would have been inside both brackets and
   would have appeared. Do not reopen this on a vendor timeline.
4. **Write shape proofs for A7/A8/A9.** The KQL library covers 6 of 9 rules -- the watchdog,
   the Bun fetch and the memory scrape have no `detections/`, `backlog/` or `poc/` file, so
   their 30-day history is *unexamined*, not clean. The "other session's uncommitted
   directory, coordinate first" caveat is **withdrawn**: `github_conf/detections/kql/` is
   tracked and clean as of 2026-08-11, and `backlog/23` was added to it directly.

   4a. **Promote `backlog/23-imds-contact-from-install-lineage.kql`, or leave it in backlog
   deliberately.** Three preconditions, in order, none of them a permission: (a) Defender
   reachable from the collector at all -- **met as of 2026-08-11**, via `docker exec` into
   `auditgh_api`; (b) two assumptions
   *measured* rather than assumed -- that `InitiatingProcessParentFileName` is populated for
   lifecycle scripts on the runners, and that `DeviceNetworkEvents` records link-local traffic
   in this tenant at all. The second is the same failure class as rule 14's `RemoteUrl`
   prerequisite, which deploys cleanly, validates cleanly and can never fire; (c) a `poc/`
   shape proof of the **joined** condition, not of the raw address. **Do not arm on the
   address.** kubelet, cloud-init, the guest agents and every SDK credential chain contact
   `169.254.169.254` correctly and constantly, so an address-keyed rule fires estate-wide on
   day one and is disarmed within a day -- and a disarmed rule is worse than no rule, because
   the shelf it sits on reads like coverage.
5. **Decide `token-monitor`'s arming.** `coverage/07` ran 2026-08-11 and answered the blocker
   in the negative rather than clearing it: `SHA1` is **not** populated estate-wide --
   Windows11 97.5% of 1,767,800 rows, **Windows10 81.7%**, WindowsServer2025 95.7%, macOS the
   only platform at 100%. So `stopAndQuarantineFiles` silently no-ops on roughly one Windows10
   row in five *while the alert still fires*, which is the worst combination available: an
   operator reads a quarantine action on an alert that quarantined nothing. Arm it for the
   alert, not for the action. Two facts must travel with that decision -- quarantining the
   binary would not remove its systemd unit or launchd plist in any case, and §7 step 1.5
   already requires removal be confirmed on the host with `pgrep -af gh-token-monitor`. Put
   both in the rule's own comment or the next reader re-derives them.
6. **Run the never-executed hunt checks**: §6 checks 7-9 and §6.1-§6.2 of
   `supply-chain-hunt-ttp.md` -- all branches (up to 50/repo), the `${{ toJSON(secrets) }}`
   primitive rather than the workflow filename, npm publisher-side abuse (`bypass_2fa: true`
   tokens, self-minted attestations), the wide rotation scope. **The persistence sweep is off
   this list**: `ir/52` ran 2026-08-11 for the first time -- 0 rows over 30 days across
   `DeviceFileEvents` and `DeviceRegistryEvents`, each half separately controlled as non-empty,
   so that zero is a zero rather than an empty table.
7. **Audit the other `--*` renderer defaults** for the staleness class that bit `--trees`:
   `--branches`, `--code-search`, `--ioc` and `--posture` are pinned to `_r3` filenames.
   Nothing is wrong today; the failure mode is silent and the next re-run creates it. It
   very nearly created it this session -- `--registry-proxy` was pinned to
   `azure_artifacts_feeds.json` and would have rendered the old artifact while the re-run's
   sat beside it. That one is now on `latest_round()`; these four are not.
8. **Deployment topology P2**, blocked on Docker: apply
   `migrations/021_deployment_observation.sql` (P2 writes fail without
   `uq_deployments_repo_external_id`), verify the container (86 tests, two `/cicd/topology/*`
   routes), then `--dry-run`, `--repo-limit 25`, the full mapped set.
9. **Still awaiting Rob's direction, from P1**: file tickets for the 9 dangling `uses:` refs to
   deleted branches (org member -> CD privilege escalation) and for pinning
   `terraform-setup-composite-action` to a commit SHA. The CHAINDROP work sharpened the second
   -- 46 central contracts hand `${{ toJSON(secrets) }}` to that moving tag, exactly the
   primitive this worm's exfil workflows use.
