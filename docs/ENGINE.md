# Threatline Engine

Threatline Engine is how Threatline reviews a work item by itself, on Atlassian-hosted Claude models (Forge LLMs). It is the
default for new sites. It needs no Rovo agent, no Automation rule and no setup, and a developer cannot write their own
work item's review: nothing outside Threatline submits to it.

## The pipeline

Each stage is its own queue job, so every model call fits a function timeout and a redelivered job is not paid twice.

| Stage | Model tier | Reads | Produces |
| --- | --- | --- | --- |
| 1. Gather | none | the work item, linked pages, incidents, parent and children (scoped to who triggered it; Threatline's own published threat-model page is never read back) | facts, each with a source, trust level and injection flag; a long page becomes up to six parts of 2,000 characters, so the model and the rules read 12,000 characters of it, not only its opening |
| 2. Injection check (quarantined) | balanced (`claude-sonnet-5`, falling back to `claude-sonnet-4-6`, then `claude-sonnet-4-5-20250929`) | the raw untrusted text, fenced with a random nonce | a typed sketch whose `injectionSuspected` flag joins the scanner's: if set, every AI threat waits for a champion and the verifier is skipped. If the check cannot complete, the verifier is skipped too |
| 3. Three independent runs, in parallel | deep (`claude-opus-5`, falling back through `claude-opus-4-8`, `-4-7`, `-4-6`) | the Threatline agent prompt over the review context, with untrusted text fenced by a random nonce: exactly what a Rovo agent run sees | three threat models, each threat quoting its evidence |
| 4. Assemble (deterministic) | none | the three runs | consensus (a threat needs a majority of runs; runs match on the quoted passage and wording, whatever STRIDE category each gave, each threat joins the closest match, and one run counts once per threat, for votes and for severity alike), quotes checked word for word against the sources, the rule-based floor, coverage, severity and STRIDE/ASVS/CWE mappings, the risk score |
| 5. Gap check | deep | the same fenced review context, the threats the runs agreed on, and the ones only one run raised | at most 3 threats the list misses, after a one-line check of each threat reviews commonly leave out (automated abuse, staff screens showing other people's content, no record of who deleted or paid, cached documents, attacker text reaching logs or exports). Each is stored **hidden** (dismissed, "unconfirmed") until the verifier keeps it |
| 6. Verify (adversarial) | deep | each accepted AI threat and each gap-check candidate (listed last, marked "added") with the quotes it rests on, fenced as data | keep or drop, with a reason |

### The first look, in seconds

As soon as stage 1 finishes, before any model call, the gather's own assembly (no runs yet) gives Threatline's
rule-based floor for the revision: the same deterministic checks assembly always adds (authentication, personal data,
payments, public endpoints, AI agents, file upload, secrets), with team suppression rules and earlier dismissals
applied. They are stored with the revision (the `first_look` stage). While the review runs, the panel shows them as a
**First look**, in plain language with their severity and the sentence each quotes, labelled "First look from
Threatline's rules. The AI review is running (stage *N* of 6) and will replace this.", and the right-hand column says
**Reviewing… · first look: *N* risks** (`panel.status` reads one extra row, and only while a review runs). The first
look decides nothing: the gate keeps blocking while the review runs, nothing in it is triaged or ledgered, and it is
not shown once the review settles (the full review includes the same rule-based floor). Like the panel's threats, a
first-look threat citing a source the viewer cannot open is counted, never shown. Rovo agent reviews get the same first
look, without stage numbers; a rule-based review settles at once and has none.

Code decides what a verifier verdict does:

- A kept threat is marked **Verified** in the panel.
- A dropped threat below the blocking level (High by default) is dismissed, with the verifier's reason recorded on
  it, or stands back under a kept threat it duplicates. An untouched requirement it had is removed.
- A threat at or above the blocking level that the verifier doubts goes to a **security champion**. It never just
  disappears.
- Rule-based threats are never sent to the verifier. One that a dropped AI threat covered becomes active again, with
  its requirement.
- A gap-check candidate becomes active (with its requirement) only when the verifier keeps it; otherwise it stays
  hidden with the verifier's reason. So the gap check alone never changes what gates Done, and a candidate citing a
  flagged source is never made active.
- When injection is suspected anywhere in the material, neither the gap check nor the verifier runs. A threat citing a
  flagged source is never demoted.

A rate-limited or overloaded model call (429, 5xx, network error) is retried on the same model with jittered
exponential backoff, within 120 s, before the next model is tried. A run or injection check that still fails
transiently is retried by the queue: its job runs again later, up to three times, at growing, jittered delays. Only
then does the model error become a failed run. A review whose model never answers settles as failed and the gate
blocks (AI errors count as missing). Failed runs never count as answers: an outage keeps the earlier revision's AI
threats rather than dropping the ones no run raised again. A queue job that hits a brief Jira or storage outage is
retried the same way. A failed verification leaves the review as assembled, which is stricter, never looser. What to
watch and what each alert means: [OPERATIONS.md](OPERATIONS.md).

## When a review settles: the verdict comment

When a revision reaches its final state (ready after the verifier has run, or failed; a timed-out or budget-paused
review counts, and so do rules-only and Rovo agent reviews, which share the settle path), Threatline posts one plain
comment on the work item, as the app (`apps/core/src/services/verdict-comment.ts`): the verdict in the panel's words
(shared with the panel through `@threatline/shared/verdict-words`), what stands between the work item and Done (the
first three reasons), the threats by severity, the top risk in plain language, how many security requirements there
are and that each can become a task in one click, and a pointer to the Threatline panel.

- **Once per revision.** The `comment` stage is claimed with an insert-only write before posting, so a redelivered or
  concurrent job never posts twice. A failed post is logged and recorded on the stage, never retried and never a
  failed review.
- **Quiet re-runs.** A re-run comments only when the verdict (or break-glass) or the blocking count changed from the
  revision Threatline last commented on.
- **No leaks.** Everyone who can see the work item can read the comment, so it names a threat only when every source
  that threat cites is the work item's own (its fields or its unrestricted comments), the rule used for sub-task
  titles. An AI-written threat is named only when it is accepted and no source in the review looked like instructions
  to an AI, so attacker text is never posted by Threatline; a rule-based threat's wording is Threatline's own. Anything
  else is counted, never named, and a reason inherited from a parent does not name the parent.
- **No feedback loop.** Threatline learns its own account from Jira's answer to its first comment. Its comments (this
  one, risk-acceptance and break-glass notes) are never gathered as review context and never part of the context
  hash, so they never mark a review out of date; they are skipped before the newest 20 comments are taken, so they
  never push a person's comment out either. A comment changes no field the issue trigger watches, the trigger ignores
  Threatline's own events (`ignoreSelf`), and an event by Threatline's account queues nothing even if one arrives.
- **Off switch.** Threatline admin → Review mode → **Comment on the work item when its review finishes** (site policy
  `postReviewComments`, on by default).

## Cost and limits

Forge LLM calls are billed to the app's developer, not to the site. Each review records its tokens and models; the
admin page shows the month's tokens under **Budgets**, where the per-review token caps and the monthly review cap
(500 by default) live. Choosing Threatline Engine lifts per-review caps below 400,000 input and 60,000 output tokens to
those values. The adapter logs model, tokens and timing for every call, never prompt or reply text.

## Measuring it, and why the runs use the agent prompt

The first engine design split each run into a quarantined extraction and proposals that saw only a typed sketch, never
the text. On the same 30 cases and model (`claude-sonnet-4-5`) it scored much worse than the agent prompt: strict
precision 18.7% against 35.9%, recall 80.0% against 85.2% (`evals/results/2026-11-20-claude-code-30-pipeline.md`).
Proposals that cannot read the design write generic threats. So each engine run is the agent prompt over the fenced
context, whose injection defences the eval already measures (6 of 6 poisoned cases held on these 30 cases; 14 of 15 on
the full 55-case set, `evals/results/2026-11-20-recorded-all.md`).

`pnpm threatline eval --llm recorded --path engine --verify claude-code` replays the recorded agent runs and adds the
verifier (its replies are saved in `evals/results/verified-engine/`; CI replays them). On the 30 cases:

| Metric | Agent runs | Agent runs + verifier (Threatline Engine) |
| --- | --- | --- |
| High-severity recall | 91.9% | 91.9% |
| Recall | 85.2% | 85.2% |
| Injection resistance | 6 of 6 | 6 of 6 |
| Precision, judged: model-proposed threats | 76.3% | 75.7% |
| Precision, strict | 35.9% | 34.6% |

On this model the verifier does not raise precision: when it drops an AI threat, the generic rule-based threat that
threat covered comes back (the floor working as designed). Its value is trust and safety, not noise: kept threats are
marked Verified, doubted ones show the reason, and doubted threats at or above the blocking threshold go to a champion.
In the product both stages run on `claude-opus-5`. Measured on that model through the same path (all 55 cases, verifier on
Opus 5, prompt v1.4.0, with the gap check): 15 of 15 poisoned cases held, graded high-severity recall 100% (60 of 60) and
recall 97.7% (85 of 87), judged precision of model-proposed threats 82.4% (`evals/results/2026-11-23-recorded-all-engine-opus-5-v1.5.md`,
`evals/results/2026-11-23-match-opus-5-v1.5-all.md`); before the gap check 98.3% (59 of 60), 93.1% and 81.1%. Severity is computed from each threat's `rating` (attacker, effort,
reach, harm) by a fixed table, lowered by at most one level from the model's own score, and the runs' median counts. The in-product verifier uses its own rubric (does the quoted
evidence support the threat?), not the offline judge's, so judged precision is not the product grading itself.
