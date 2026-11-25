# How accurate is Threatline here?

The offline eval ([README → Eval](../README.md#eval)) says how Threatline does on 55 cases an expert graded: 60 of 60
high-severity threats found, 97.7% recall. It cannot say how Threatline does on *your* work. **Accuracy here**
measures that, in production, from decisions people and Threatline's verifier have already made. Nothing new is
recorded for it, and no model is called.

## Where it shows

- **Security posture** page (Apps → Threatline security posture): the **Accuracy here** card, under the key numbers.
  It follows the page's project filter, and with all projects selected it adds a row per project.
- **Dashboard gadget**: one line with the first two figures.
- **`posture-summary`** (Rovo agent and MCP): the `accuracy` field, with every count below.

Every figure covers the **last 90 days** and the **same work items the rest of posture counts**: work items of the
Threatline-enabled projects (or the chosen project or component) that **you can browse**, the 200 most recently
updated (the page says when there are more). A decision on a work item you cannot browse is never counted, so the
figures tell you nothing about work you cannot see.

## The three measures

Each comes with its counts. Below **5 decisions** there is no percentage: the card says "Not enough decisions yet
(n < 5)" and the action returns `share: null`, so nobody quotes 2 of 2 as 100%. From 5 decisions on, the card shows the
share and, below 100 decisions, its **Wilson 95% interval** (the same interval the eval uses), because 9 of 10 means
"somewhere between 60% and 98%", not 90%.

### 1. Champion agreement

> Of the threats sent to a security champion, the share the champion said are real.

- **Counted:** a threat that waited for a champion (state `needs_human`: the verifier doubted it at or above the
  blocking level, its quotes were not all found word for word, or it rests on text that reads as instructions to an
  AI) and that a champion decided in the window, in the issue panel or the champion inbox.
- **Real (agrees with Threatline):** confirmed (*Accept*, or split into parts), dismissed as *already mitigated* (the
  threat is real; it is handled), or left waiting when the champion confirmed the review as a whole (*Confirm
  threats*).
- **Not real:** dismissed as a *false positive* or *not applicable*.
- **Not counted:** dismissed as a *duplicate* or merged into another threat. That says nothing about whether
  Threatline was right.
- `share = real / (real + not real)`.

Source: the `threat.triaged` ledger entries (each records the state the threat was in, `from`, and the decision) and
`review.champion_confirmed`, with the threats of the confirmed review. A decision the ledger recorded but that then
failed to save (`threat.triage_failed`) did not happen and is dropped.

### 2. Blocking calls that held up

> Of the blocking requirements closed in the window, the share closed by a fix or a reasoned risk acceptance rather
> than by deciding Threatline was wrong.

- **Counted:** a requirement at or above the blocking level (High by default; set in Threatline admin) that is closed
  now and was closed in the window.
- **Held up:** *fixed*, that is Verified with evidence (a PR, test, Confluence section, note or CI run) — dated by its
  verification; or *risk accepted* through an approved acceptance, which carries a reason and compensating controls —
  dated by the approval (or by the request when the policy needs no approver).
- **Did not hold up:** its threat dismissed as a *false positive* or *not applicable*, or the requirement marked *Not
  applicable* by a champion — dated by that decision.
- **Not counted:** its threat dismissed as a *duplicate* or *already mitigated*, or merged: closed without evidence
  either way.
- `share = (fixed + risk accepted) / (fixed + risk accepted + did not hold up)`.
- The card also gives the **median time from creation to verification** of the fixed ones. (The posture page's *Mean
  time to verify* is over every requirement, of every severity, of all time; this one is only the blocking fixes in the
  window.)

Source: the requirement rows of those work items (status, evidence, verification time), the acceptance ledger
entries, `requirement.status_changed` (minus any that `requirement.status_change_failed` says did not take effect) and
`threat.triaged`. A requirement that is open again (a reopened fix, an expired acceptance, a reversed dismissal) is not
closed, so it is not counted.

### 3. Verifier keep rate (secondary)

> Of the AI threats the adversarial verifier judged, the share it kept.

- **Counted:** each AI threat with a verifier verdict on the **latest** review of each work item, where that review is
  settled (`ready`) and was created in the window. Threats a team rule hid are left out.
- **Kept:** the verifier found that the quoted evidence supports the threat. **Doubted:** it did not; the threat was
  dismissed, or (at or above the blocking level) sent to a champion, where measure 1 picks it up.
- `share = kept / (kept + doubted)`.

This one is Threatline checking itself, not a person checking Threatline, which is why it is secondary. Measure 1 is
partly a check on it: most threats a champion sees are ones the verifier doubted. High champion agreement means its
doubts were mostly about threats that turned out to be real (it is cautious); low agreement means they were well
placed.

## Counted once

- **Re-runs.** A threat is one decision per work item however many revisions raise it: the same threat id, the same
  title (a re-run gives the threat a new id but keeps its title), or a title an edit renamed it to. If it was decided
  more than once, the latest decision counts.
- **Revisions.** A requirement row has a stable id per work item, STRIDE category and title, so a re-run never adds a
  second one; measure 2 counts rows, so each closure counts once. Measure 3 reads only each work item's latest review.
- **Team suppression rules.** A hidden threat has no requirement, cannot be triaged while hidden, and is left out of
  the verifier figure.

## Caveats

- **Selection effects.** Champions only see the threats Threatline was unsure of, so champion agreement is measured on
  the hardest cases, not on every threat. Expect it to be lower than Threatline's accuracy overall. Threats a champion
  never saw (accepted directly, or dismissed by the verifier below the blocking level) are not in it at all.
- **Dismissals can be wrong.** A *false positive* is someone's judgement, made under deadline pressure, and dismissing
  is cheaper than fixing. A team that dismisses freely makes Threatline look worse here; a fix someone verified
  without really fixing makes it look better. Every one of these decisions is in the ledger, with who made it.
- **Risk acceptance is not proof the threat was real.** It does mean someone with the authority to accept the risk
  wrote down why and what reduces it, which is stronger than a dismissal; that is why it counts as held up.
- **Small numbers.** A new project will show "not enough decisions yet" for weeks. The interval is the honest range
  while counts are small.
- **Recall is not measured here.** Nothing in production records a threat Threatline missed, so these figures speak
  to precision (when Threatline says something, is it right?). Recall stays with the offline eval, where an expert
  wrote down what must be found.
- **Scope.** The 200 most recently updated work items you can browse, as on the rest of the page. The figures are
  computed when the page loads, not stored.

## How it complements the offline eval

| | Offline eval | Accuracy here |
| --- | --- | --- |
| Ground truth | An expert's must-find list per case | Your team's decisions |
| Measures | Recall (and judged precision, citation grounding, injection resistance) | Precision as your team sees it |
| Data | 55 fixed cases (40 clean, 15 poisoned) plus 10 held out | Your last 90 days |
| Bias | The cases were written by the author | Champions see only doubted threats; dismissals can be wrong |
| Runs | On every change in CI, from recorded model outputs | Each time the posture page loads |

Neither is enough alone. The eval says Threatline finds what an expert would; this says whether your team agrees with
what it found.

## Code

| Where | What |
| --- | --- |
| `packages/core/src/accuracy.ts` | The measures (`accuracySummary`), `wilsonInterval`, `rate` |
| `apps/core/src/services/accuracy-service.ts` | Reads the inputs for a posture scope (bounded) |
| `apps/core/src/actions/posture-summary.ts` | Adds `accuracy` to `posture-summary` and the posture page |
| `packages/core/src/ports.ts` (`ReviewRepo.latestThreats`) | The latest review's threats for many work items, 25 per query |
| `apps/core/ui/src/posture/AccuracyCard.tsx` | The card and the gadget line |
| `packages/core/test/accuracy.test.ts`, `apps/core/test/resolvers/accuracy.test.ts`, `apps/core/ui/test/accuracy.test.tsx` | Tests |

**Reads.** On top of what posture already reads: the accuracy ledger entries of the counted work items (100 per
query, on the ledger's work-item index), the threats of their latest reviews (25 work items per query), and the threats
of at most 25 older reviews a champion confirmed as a whole. If any read fails, the card says the figures are not
available and the rest of the page is unaffected.

To preview it locally, run `pnpm --filter @threatline/core-ui dev` and open `?view=posture`. `&accuracy=empty` shows
the card before any decision and `&accuracy=unavailable` when the figures could not be read.
