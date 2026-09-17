# How security problems get written up — status briefing

**Date:** 17 September 2026
**Audience:** anyone who needs to understand or fund this work. No technical background assumed.
**Technical companion:** `docs/GRC_Filing_Grouping_Status_Technical.md`
**Names behind every count:** `docs/GRC_Filing_Grouping_Appendix.md`, produced by `scripts/generate_grouping_appendix.py`

---

## 1. What are we talking about?

We have an internal tool, AuditGitHub, that reads our own software. It looks
through 2,540 projects — a project is one body of code that a team owns — using
ten different automated checkers. Each checker is good at spotting a different
kind of problem: out-of-date software components, passwords accidentally typed
into a file, a server set up with the wrong permissions.

Together those ten checkers have produced **767,974 individual observations**.
An observation is one checker saying "this specific line, in this specific
file, in this specific project, looks wrong."

Separately, we have AuditBoard. That is the company's official register of
issues — the place where a problem gets recorded, given an owner, tracked, and
funded. Anything we intend to actually fix needs to appear there.

Normally what happens is that a person looks at what the checkers found,
decides what is real, and writes it up in the register. The question this work
answers is: *what exactly does one entry in the register cover?*

## 2. What is the problem?

767,974 observations cannot become 767,974 register entries. Nobody could read
that, let alone assign it.

They cannot be lumped together either, and that is the less obvious half. Until
this month, the tool grouped observations by which file they were found in. That
sounds sensible and is badly wrong in both directions at once.

Take the single largest group. One checker, looking at a file called
`package-lock.json` — a file listing which outside software components a project
uses — accounts for **11,517 observations across 110 projects**. Grouped by
file, that is one register entry. But inside it sit **386 genuinely different
problems**: 386 separate outside components, each with its own flaw, each
needing its own fix, each on its own release schedule. One entry claiming to
cover 386 unrelated problems is not a record of anything. Whoever it lands on
cannot close it, because there is no single thing to do.

The same grouping fails the opposite way too. A component flaw that appears in
137 projects gets written up 137 times, once per project, as though it were 137
discoveries. It is one flaw. It usually has one fix.

So the register either gets flooded, or it gets entries nobody can act on. Both
end with people ignoring it.

There is a second, quieter version of the same problem. Different checkers name
the same problem differently. One calls a flaw `GHSA-M7JM-9GC2-MPF2`, another
calls the identical flaw `CVE-2024-21538`. Left alone, that is two register
entries for one problem, and the second one wastes a real person's afternoon.

## 3. What happens if we don't fix it?

The register stops being trusted, and that is expensive in a specific way.

An entry in AuditBoard **cannot be deleted, and its description cannot be edited
after it is created.** We tested this against the live system. So a bad entry is
not a draft to tidy up later; it is permanent. Every entry that claims to cover
386 unrelated problems stays on the books, saying so, for as long as the record
exists. An auditor reading it later is entitled to take it at face value.

The clean-up cost is not a software cost. It is people reading entries one at a
time, working out which of the 386 problems inside it were actually fixed,
deciding what to do with the rest, and creating replacement entries by hand
because the original cannot be corrected. At several hundred entries that is
weeks of somebody's attention, and it produces no security improvement at all —
it only restores an accurate record.

Meanwhile the real work does not get prioritised, because you cannot see it. A
list of 767,974 observations tells you nothing about what to fix first.

## 4. Are there benefits beyond this?

Yes, and they arrive whether or not the risk above ever materialises.

The 767,974 observations turn out to be **2,638 distinct problems**. Of those,
**2,397 are serious enough to be worth filing** — we set a floor and do not file
low-severity noise — after setting aside the 546,977 observations the tool had
already flagged as not worth acting on. That is the first time we have had a
number a person can hold in their head.

Of those 2,397, **241 appear in more than ten projects each**. That is the list
you actually want: problems where one central decision fixes many teams' code at
once, instead of 241 separate conversations repeated across dozens of projects.
It is a prioritisation list we did not previously have.

And each register entry now carries, inside it, the list of exactly where the
problem sits in that project — which files, how many times each. An owner can
begin work from the entry itself without asking us for a follow-up export.

## 5. What is involved in resolving it?

Most of it is already done, and nothing needs to be purchased. No new software,
no new licence, no new vendor. The work used tools we already run.

What is built and working now:

The tool groups by *problem* rather than by file, and offers three scopes when
someone files to the register: just this one observation, everything of this
problem inside one project, or everything of this problem across the
organisation. It recommends which to use based on how widely the problem has
spread — more than ten projects and it suggests raising it for the whole
organisation. Filing is always one deliberate press by a person; there is no
bulk button, by design.

Where two checkers report the same problem under different names, an automated
pass proposes that they be treated as one, and **a person has to approve each
one before it changes anything**. Until approved, the proposal has no effect
whatsoever. We chose that direction deliberately: a missed merge produces a
visible duplicate that somebody can close, while a wrong merge permanently
claims an entry covers something it does not, and cannot be undone.

What remains is review time, not build time. We have identified **478 pairs of
differently-named problems worth checking**. Three have been checked so far;
**475 are waiting**. Each one is a short read — two names, the reason, and the
evidence — and one press. There is a screen for it. A reviewer can work through
them in batches at whatever pace suits; nothing degrades while they wait,
because an unreviewed pair simply stays separate.

One decision is outstanding and it is a cost question, not a technical one:
checking the remaining 475 pairs means 475 short requests to our AI service.
Nobody needs to approve the building; somebody should say yes to that spend,
which is small but real.

Finally, five entries were filed to AuditBoard before this change, under the old
grouping. They are listed by number in the appendix. They cannot be corrected,
for the reason given above. One of them refers to observations that have since
been deleted, so it now covers nothing and should be closed by hand.

## 6. What we are not claiming

This section is part of the report, not a disclaimer.

**We are not claiming the automated pass is right.** It is a proposal engine. Of
the three pairs checked so far it judged all three to be *different* problems,
which is the answer we expect most of the time. Its judgement is why a person
approves each one; its confidence in itself is not evidence.

**We are not claiming to have found all the duplicate naming.** We only check
pairs where two checkers reported findings *in the same file in the same
project*. That is 478 pairs at the severity floor, 834 if we ignore severity
altogether. Two checkers that describe the same problem but never land on the
same file are invisible to this method. "We found no duplicate" is not the same
statement as "there is no duplicate."

**We are not claiming the 2,638 problem count is a count of real problems.** It
is a count of distinct things the checkers reported. Some will be false alarms.
Deciding that is human triage work and is not what this change does.

**We are not claiming existing register entries were fixed.** Nothing filed
before this change was altered, because the system will not permit it.

**We are not claiming severity ratings are correct.** Where two checkers
disagree about how serious something is, we record the more serious rating and
show both, on the basis that understating a problem in an official register is
the more expensive mistake. That is a choice, not a measurement.

**We are not claiming this is deployed.** It is built, tested and running on one
machine — the workstation it was written on. It has not been installed anywhere
the wider team reaches. The screens and the grouping work there today; moving
them to a shared environment is a separate, small step that has not been taken
and is not costed here. Along the way we found the running program had to be
restarted before it picked up the new code, which it now has.

**We are not claiming any of this reduces the number of problems in our code.**
It changes what we can see and what we can honestly write down. Fixing is
separate work.

**On secret values:** where a checker's finding *is* a password or key, the
value itself is deliberately kept out of register entries, out of this report
and out of the appendix. One entry filed before that rule existed does contain
a live key in plain text; the key needs replacing, and that is tracked
separately. Withholding these values is not a statement that no secrets are
exposed in our code — it is only a statement that we do not copy them into more
systems.

---

Every count in this briefing comes from the same measurement, taken on 17
September 2026, and every one of them can be traced to named files, projects
and problem identifiers in `docs/GRC_Filing_Grouping_Appendix.md`. The technical
companion, `docs/GRC_Filing_Grouping_Status_Technical.md`, gives the method,
the exact definitions behind each number, and the locations to act on.
