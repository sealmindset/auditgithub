# Threat-Hunt Report Template — the contract every supply-chain hunt report must meet

**Playbook ID:** `template-hunt-report`
**Applies to:** any report produced by a repeated hunt against a named campaign — registry-borne
supply-chain worms first, but the shape holds for any hunt that runs on a cycle and is read by
people who did not run it
**Implemented by:** `scripts/hunt/render_hunt_report.py` — this document explains the contract; the
script enforces it
**Reference run:** CHAINDROP / "Shai-Hulud: Here We Go Again", run r5, 2026-08-10 —
`exports/hunt-report-2026-08-10.{md,docx,pdf}`
**Companion:** [`supply-chain-hunt-ttp.md`](supply-chain-hunt-ttp.md) — that playbook says how to
*run* the hunt; this one says how to *report* it
**Owner:** Security Engineering

---

## 0. Why this is a template and not a document

A hunt report written by hand is correct on the day it is written and quietly wrong a week later:
counts get restated from memory, a gap that closed stays on the page, a gap that opened never
reaches it. So the report is **rendered from the coverage artifacts every cycle** by
`render_hunt_report.py`, and this document is the contract that renderer implements.

Two consequences worth stating plainly, because they are the whole design:

1. **Every number in the report is read from an artifact at render time.** No figure is typed into
   prose. If a figure cannot be read from an artifact, the sentence containing it does not exist.
2. **The renderer refuses to produce a report that breaks the contract.** A missing coverage-gap
   field or an evidence-free control claim is a non-zero exit and no output file — not a warning
   in a log nobody reads. See §5.

---

## 1. The three axes

A single status letter cannot carry a hunt result, and the failure is specific: fold the estate's
dark third into the color and the color says AMBER every day for a reason no hunt result can
change, which is how a RAG letter stops being read. So a report carries three answers, reported
next to each other and never merged.

| Axis | The question it answers | What moves it |
|---|---|---|
| **RESULT** | In the population we can observe, is there evidence of compromise? | findings on a compromise-evidence vector, and nothing else |
| **COVERAGE** | How much of the estate is that population? | named, counted, enumerable populations that emit no telemetry |
| **CONTROL** | If it arrives tomorrow, what is in its way? | artifacts that measure a control, not a list of controls we believe we operate |

**RESULT does not include COVERAGE, and COVERAGE does not lower RESULT.** A clean result over a
partial population is stated as exactly that, twice, in both directions: the verdict is true, and
it is true about something smaller than the estate.

**CONTROL is not derivable from RESULT.** A hunt measures arrival. It does not measure defense, so
a clean hunt is silent on whether anything was actually stopping the thing — which is precisely the
question the reader has after reading a clean result. The reference run's clean result came from
*which packages the attacker chose*, not from a control the estate operates; a report that omitted
the CONTROL axis would have let a reader infer the opposite.

---

## 2. The four sections — one per state of attention

The reader is not one person. They are the same person in four different states, arriving in this
order, and each state wants a different document. Sections are ordered so that a reader can stop at
the end of any one of them and not be misled by what they did not read.

| Section | The reader's state | What it must contain | What it must not contain |
|---|---|---|---|
| **1 — The situation** | "My boss just asked me about this." | one verdict, the coverage table, what changed since the last report, where we looked in plain terms | jargon, vector names as headings, any number without a plain-language gloss |
| **2 — Could it happen to us** | "Fine, we are clean. Could we not have been?" | the campaign's chain link by link, each link's control state, why today's result came back clean | a list of controls we hold (see §3), any state without an artifact behind it |
| **3 — What to do, in order** | "Right, I have to do something." | ranked actions with scope, owner, effort, affected resources, and the GREEN gate | an action whose resources cannot be enumerated |
| **4 — Evidence** | "Engineering wants proof and targets." | per-vector detail, the coverage register, access requests, target lists, queries, reproduction command | anything a reader in state 1 needs |

**Section 1 rules.**

- The verdict sentence answers "are we breached" in the first clause and bounds it in the second.
  The reference run's: *"No evidence of compromise anywhere we read — and a specific, named, finite
  list of things we did not read. Read them and this becomes a yes or a no."*
- The coverage table is in Section 1, not buried in Section 4. A blind spot a director never sees
  is a blind spot nobody has accepted.
- **What changed** is rendered every cycle, and a new *check* is reported separately from a moved
  *count*. A hunt that gains a check and finds nothing otherwise produces no delta line at all,
  which reads as "we did not look at anything new".
- A newly registered blind spot must not be reported as lost visibility unless the state file can
  prove it. When a gap appears because a check ran for the first time, the line says so: *the hunt
  widened, the estate did not go dark*. Where the state file cannot tell the two apart, the report
  says that too, and names who owes the one line that settles it.

**Section 3 rules.**

- Every action names its **affected resources by identifier**, not by count. An action whose
  population cannot be enumerated is not an action, it is unease.
- Effort is stated in the units the owner will plan in: hours, days, weeks-batched, program of
  work, or *a decision, not an engineering task*.
- The GREEN gate is part of Section 3, not an appendix. See §4.

---

## 3. The CONTROL axis: a chain, ordered by the attacker

Section 2 is the chain the campaign has to complete, **ordered by the attacker's steps, not by the
controls we happen to hold.** This ordering is the entire point:

> A list of the controls we operate cannot show a reader that a link has nothing in it, because a
> link with nothing in it produces no row in that kind of list.

The reference run's chain, which is the reusable skeleton for any registry-borne worm:

| # | The step | Reference-run state |
|---|---|---|
| 1 | Getting a poisoned version into one of our builds | PARTLY CONTROLLED — pinning is real; 36 repos have no lockfile |
| 2 | Running its code during the install | UNMEASURED — 2,670 lifecycle-script executions on 101 devices, none attributable |
| 3 | Fetching a separate runtime to hide the payload | DETECTION ONLY |
| 4 | Reaching our credentials once it is running | OPEN — the numbers *are* the finding |
| 5 | Getting the credentials out | DETECTION ONLY |
| 6 | Using our credentials to infect others | CONTROLLED — because a precondition is absent, not because a control was built |
| 7 | Staying after we clean up | DETECTION ONLY |

### 3.1 The five states, and why there are five

| State | Means | Evidence required |
|---|---|---|
| **CONTROLLED** | A control we operate stands in the way, and the artifact and number behind that claim are named. A measured obstacle, not a guarantee. | required |
| **PARTLY CONTROLLED** | A control covers most of the step and has a named, counted hole. The hole is the work item and it is listed. | required |
| **DETECTION ONLY** | We would see this step happen, and the control proving we would see it is named. Nothing prevents it. | required |
| **OPEN** | We looked for something in the way and found nothing. **A decision with a cost, not an oversight.** | required |
| **UNMEASURED** | We have not established whether anything is in the way. | **the only state that may have none** |

The **OPEN / UNMEASURED split is the same distinction as INCOMPLETE-versus-coverage-gap on the
RESULT axis**, and it exists because the two cost different amounts to close. OPEN needs a decision
and a budget. UNMEASURED needs somebody to spend an afternoon finding out, and it might turn out to
be a control we already had. Fusing them into "gap" prices an afternoon like a program of work.

### 3.2 Rules for stating a control

1. **Every non-UNMEASURED state carries its evidence.** A claim about what stands in an attacker's
   way is worth exactly the number behind it — and UNMEASURED is available and honest.
2. **A control held because a precondition is absent says so.** Reference run link 6 is CONTROLLED
   only because zero workflows combine an OIDC token with a publish step. That can reappear the
   week somebody adds a publish workflow, which is why the check runs every cycle rather than once.
   Reporting it as a built control would be a false reassurance with a known expiry date.
3. **Detection is not prevention and the report never lets one read as the other.** Both are worth
   having; a single word "clean" fuses two different sentences.
4. **Do not total the links.** They are not equally weighted and they do not sum: a control on the
   first link prevents the attack, a control on the last one only limits what an attacker keeps. A
   count of held links says less than *which* links are held.
5. **Say what made today clean.** If the answer is "the attacker did not choose our packages", the
   report says that, and says which control would have helped and did not decide the outcome.

---

## 4. The GREEN gate

Two questions follow every AMBER report — *when does this go green* and *when can development
resume* — and a report that answers neither gets the cautious answer inferred, which is how a clean
hunt holds delivery for weeks on the strength of posture work that was never a blocker.

So the gate is rendered, ordered, and split.

**First, what GREEN cannot mean.** Where the coverage register holds a permanently unobservable
population — the reference run has 586 devices on platforms Defender does not support — GREEN can
never mean "proven absent everywhere". Saying so first is what makes the rest of the gate credible.

**The reachable definition:**

> **GREEN** = every vector clear, zero unread items, and every remaining blind spot carries a named
> owner who has accepted it in writing.

**Second, and separately: exposure findings are not a reason to pause development.** The gate says
this explicitly, in Section 3, next to the P1 items. Conflating "we have hardening to do" with "we
may be breached" is the single most expensive misreading this report can produce.

**Gate categories, derived — never typed:**

| # | Gate | Source | Ours? |
|---|---|---|---|
| 1 | Unread items per vector | `unresolved_items` on any INCOMPLETE vector | yes |
| 2 | P1 exposure work | FINDINGS vectors that are not compromise evidence | yes |
| 3 | Coverage-gap decisions | the coverage register | **no — a decision** |
| 4 | UNMEASURED chain links | the CONTROL axis | yes, and cheapest |
| 5 | OPEN chain links | the CONTROL axis | yes |
| 6 | Stale artifacts | artifact freshness against the as-of date | yes |
| 7 | Vectors that did not run | NOT RUN status | yes |

Each gate carries `ours: true|false`. That flag is what lets the closing line separate engineering
work from decisions nobody has been asked to make — on the reference run, seven gates were days of
work and one was the only real blocker.

---

## 5. What the renderer refuses to print

The validator is the reason this template survives contact with a deadline. All of these are
**refusals** — non-zero exit, no output file:

| Refusal | Rule |
|---|---|
| A coverage gap missing any of `gap`, `population`, `named_by`, `cannot_confirm_or_deny`, `closed_by`, `owner` | §0.6(b) — a population nobody can enumerate is not a gap, it is unease |
| A finding, action or gap with no enumerable resources | §0.6 — prove it or do not report it |
| A chain link missing any of `link`, `worm_needs`, `state`, `closed_by`, `owner` | §3.2 |
| A chain link in any state but UNMEASURED with no `evidence` | §3.2 rule 1 |
| A cleared disposition with no `reason` and `evidence` | a judgement is not a measurement; see `exports/hunt/dispositions.json` |
| An access gap that does not name the exact privilege and endpoint | so an access request can be filed from the report alone |

**Collector-side corollary.** A collector that emits a gap must emit all six fields. When an
artifact predates the contract, patch that artifact in place and stamp the patch with a
`_correction` note stating what was renamed and that no measured value changed — then fix the
collector so the next run reproduces the shape without patching. Both halves, every time: patching
only the artifact means the next run breaks the render again.

**Adjudications live in their own file.** `exports/hunt/dispositions.json` records what a human
*concluded*; the coverage artifacts record what a collector *observed*. They are separate files so
a judgement can never be mistaken for a measurement, and a cleared item is still printed with its
reason — a disposition changes whether an item counts as evidence, it never hides the item.

> **Operational trap, learned the hard way.** `exports/` is gitignored (`.gitignore:93`).
> `dispositions.json` must be committed with `git add -f`. Losing it silently reopens every cleared
> flag and restores a false RED on the next render.

---

## 6. Rendering a cycle

```bash
python3 scripts/hunt/render_hunt_report.py \
  --branches   exports/hunt/branches_r5_coverage.json \
  --code-search exports/hunt/code_search_r5.json \
  --ioc        exports/hunt/ioc_match_r5.json \
  --posture    exports/hunt/actions_posture_r5_coverage.json \
  --registry   exports/hunt/rederive_window_0000z_aug5.json \
  --endpoint   exports/hunt/endpoint_hunt_r9.json \
  --owners     exports/hunt/repo_owners_r5.json \
  --as-of 2026-08-10 \
  --out exports/hunt-report-2026-08-10.md
```

Artifacts not passed explicitly are resolved to the **highest round number present**, so a new
collector run is picked up without editing the command. Round resolution reads `_r<N>` followed by
`.`, `_`, or end of name — `install_activity_r2.json` and `lockfiles_r5_coverage.json` both parse.

`--no-state-write` renders without updating the delta state file. Use it while iterating; omit it
on the run that ships, or the next cycle's "what changed" compares against the wrong baseline.

Document conversion, for the executive audience:

```bash
docker exec auditgh_api python3 -c "from src.reporting.md_to_pdf import render_file; \
  render_file('/app/exports/hunt-report-2026-08-10.md')"
```

---

## 7. Adapting this to a different campaign

The four sections, three axes, five control states, GREEN gate and validator are **campaign
independent** — keep them verbatim. Three things change:

1. **The chain.** Re-derive it from the campaign's own TTPs, still ordered by the attacker. A
   credential-phishing campaign's chain is not seven links about package installs; it is still a
   chain, still ordered by the attacker, and still has to show which links have nothing in them.
2. **The vectors.** One per population you can independently observe, each with its own control
   (§0.1 of the TTP playbook) and its own coverage gaps.
3. **The plain-language gloss in Section 1.** The reference run's paragraph explains a package
   worm. Rewrite it for the campaign in front of you, to the same standard: no jargon, no vector
   names, and no number without a meaning attached.

Everything else is the contract. The point of a template is that the argument about what a report
owes its reader is settled once, in code, and does not get relitigated at 6pm the day it ships.
