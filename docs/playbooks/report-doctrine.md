# Report Doctrine — every report ships as a pair

**Playbook ID:** `doctrine-report-pair`
**Applies to:** every report this program publishes — hunts, exposure assessments, topology
reviews, audits, post-incident writeups. Not only security work.
**Status:** standing principle
**Owner:** Security Engineering
**Worked example:** the `npm-supply-chain-exposure-*` set in this directory

---

## The rule

**A report is two documents, not one.** A leadership briefing and a technical companion, written
as a pair and published together. Delivering one without the other is an incomplete deliverable,
not a first draft.

This is not a summary bolted onto a technical document. It is two documents with two audiences,
two vocabularies and two structures, carrying one set of numbers.

## Why

The technical report is correct and unreadable to the people who fund the work. A briefing they
cannot follow gets approved on trust or not at all, and neither of those is a decision — it is
a signature. Findings that never convert into funded work are findings that changed nothing.

The reverse fails just as hard. A briefing with no technical companion cannot be checked, and an
unverifiable claim is worth nothing to the engineers who have to act on it. "Nine open doors" is
a slogan until someone can name the nine.

The pair is what makes the work simultaneously **fundable** and **verifiable**. Either document
alone gives up one of those.

---

## 1. The leadership briefing

**Audience:** anyone who needs to understand and fund this. Non-technical, non-developer,
non-DevOps, non-Security. **No technical background assumed.**

**Jargon rule:** minimum technical jargon. Use a technical term only when no other wording or
phrase can carry the explanation — and when you do, define it in place. Do not use a term because
it is precise if the reader will not parse it; find the analogy that is precise enough to act on.
A closing glossary is permitted and is not a substitute for plain wording in the body.

**Structure** — the questions this audience actually asks, in this order:

| Section | Answers |
|---|---|
| What are we talking about? | The domain, in terms that assume nothing. What normally happens, before anything went wrong. |
| What is the problem? | The findings, plainly. Counts, not identifiers. |
| What happens if we don't fix it? | The consequence, specific rather than dramatic. Say what the clean-up costs, not that the company falls over. |
| Are there benefits beyond this? | What the work buys even if nobody ever attacks us. This is the section that gets the work funded. |
| What is involved in resolving it? | Effort, sequence, and whether anything must be purchased. Split near-term from longer-term. |
| What we are not claiming | The limits. Not optional — see §3. |

**Register.** Short sentences. Concrete analogies carried consistently rather than swapped mid-
document. Numbers rounded only where the technical companion says the same figure — never rounded
in a direction that flatters the argument.

## 2. The technical companion

**Audience:** the people who want and need this level of detail — engineers, platform owners,
whoever will do the work or has to check it.

**Register:** thorough and comprehensive. All the measurements. All the technical description.
Jargon used properly, not avoided — this is the document where precision beats accessibility.

**Structure** — three questions:

| Section | Answers |
|---|---|
| What is the problem? | Mechanism. Not just that it is wrong, but what makes it wrong and under what conditions it bites. |
| Where is the problem? | Every location, by an identifier the owner acts on. Repository, file, line, ref, count. |
| How do we address the problem? | The specific edit. What to look for, what to replace it with, in which file, and in what order. |

**Distinct mechanisms get distinct counts.** If two findings look the same to a reader but need
different edits, they are two findings. Rolling them together hides which change a team is
supposed to make — and produces a total that is right for a slide and useless for the work.

---

## 3. Rules that bind both documents

**(a) One set of figures.** Both documents carry the same numbers with the same denominators.
The briefing does not get to round, soften, or drop a figure to read more cleanly. Where the
briefing states a count, that exact count is derivable from the companion.

**(b) The briefing cites the companion by filename.** A skeptical reader must be able to cross-
check any number without asking. State it near the top: *"the detailed version with all the
measurements is `<file>`. Everything here comes from there."*

**(c) The limits are a section of the briefing, not a footnote in the companion.** Whatever the
technical report says about coverage — populations not read, telemetry not held, permissions not
granted — appears in the briefing in its own named section, in the briefing's own vocabulary. A
briefing that overstates its confidence is worth less than one that does not, and this audience
has no way to catch us at it. *"No evidence of a break-in" is written out as not the same claim
as "no break-in."*

**(d) Both are governed by prove-it-or-do-not-report-it.** Every claim carries its proof or is not
made; every access gap names the exact privilege that closes it. Simplifying the language never
licenses simplifying the evidence.

**(e) Write them together, not in sequence.** Do not write the technical report and retrofit a
summary. Retrofitting is where the numbers drift — the summary gets written from recollection of
the report rather than from the artifacts, and recollection is where "workflows" quietly becomes
"repositories".

---

## 4. Names belong in a generated appendix, never dropped

The briefing uses counts because names crowd out the argument for a reader who owns none of the
repositories. But "94 projects" is unactionable to the person who has to fix 94 projects and
unverifiable to anyone who wants to check us.

The resolution is an appendix that both documents carry, **generated from the same artifacts the
technical report reads** — not typed. A hand-copied list of 94 repositories is wrong within a
month, and a stale list is worse than a count because it looks authoritative.

Two obligations on the appendix:

- **It states what it deliberately omits, and why.** A population the collector truncates does not
  get listed at all: a truncated list under a complete-sounding heading reads as complete. Name it
  as an omission instead.
- **It is regenerated, never hand-edited.** Say so in the file, in the generator's docstring, and
  in the build script.

---

## 5. Build products

Publish formats the audience actually opens. The markdown is the source of truth; PDF, slides and
any other rendering are build products, produced by a committed script and committed alongside —
because the readers who need them have no toolchain and should not need one.

Where a deck is produced, its PDF prints the speaker notes under each slide. A deck that gets
forwarded to people who were not in the room is otherwise a set of assertions with the reasoning
removed.

---

## 6. Worked example — the npm supply-chain exposure set

| Document | Role |
|---|---|
| `npm-supply-chain-exposure-plain-language.md` | Leadership briefing |
| `npm-supply-chain-exposure-report.md` | Technical companion |
| `npm-supply-chain-exposure-appendix.md` | Generated names, carried by both |
| `npm-supply-chain-exposure-slides.md` | Deck, same content as the briefing |
| `scripts/report/build_appendix.py`, `scripts/report/build_briefing.sh` | Generator and build |

**What the pair caught that a single document would not have.** The technical report was written
first and the briefing derived from it — the sequence §3(e) now forbids. Generating the appendix
from the collector artifacts, rather than from the report's prose, exposed three errors that had
already survived review in the technical document:

- §1 counted **four** components handed the whole secrets context. The artifacts show **five**.
- §2 counted **three** inline steps. There are **two**.
- An entire mechanism was never named: `secrets: inherit` on a called workflow — **11 targets,
  1,363 pipeline references**. The headline moved from *1,924 places* to **3,506 places across 18
  shared components**.

Separately, both plain-language documents said *repositories* where the underlying figure counted
*workflows*, turning 5 protected repositories into 6.

Every one of those is a number an executive would have repeated in a meeting. None of them were
caught by rereading the prose; all of them were caught by regenerating from the artifacts.

---

## Checklist

- [ ] Both documents exist, and were planned together
- [ ] The briefing assumes no technical background, and every technical term left in it is defined in place
- [ ] The briefing answers all five questions, in order, plus its limits section
- [ ] The companion answers what / where / how, with distinct mechanisms counted separately
- [ ] Every figure in the briefing is derivable from the companion, with the same denominator
- [ ] The briefing names the companion file
- [ ] Coverage limits appear in the briefing, in the briefing's own vocabulary
- [ ] Names are in a generated appendix, and the appendix states what it omits
- [ ] Build products are produced by a committed script and committed with the source
