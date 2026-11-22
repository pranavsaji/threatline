# Threatline Engine

Threatline Engine is how Threatline reviews a work item by itself, on Atlassian-hosted Claude models (Forge LLMs). It is the
default for new sites. It needs no Rovo agent, no Automation rule and no setup, and a developer cannot write their own
work item's review: nothing outside Threatline submits to it.

## The pipeline

Each stage is its own queue job, so every model call fits a function timeout and a redelivered job is not paid twice.

| Stage | Model tier | Reads | Produces |
| --- | --- | --- | --- |
| 1. Gather | none | the work item, linked pages, incidents, parent and children (scoped to who triggered it) | facts, each with a source, trust level and injection flag |
| 2. Injection check (quarantined) | balanced (`claude-sonnet-5`, falling back to `claude-sonnet-4-6`) | the raw untrusted text, fenced with a random nonce | a typed sketch whose `injectionSuspected` flag joins the scanner's: if set, every AI threat waits for a champion and the verifier is skipped. If the check cannot complete, the verifier is skipped too |
| 3. Three independent runs, in parallel | deep (`claude-opus-5`, falling back through `claude-opus-4-8`, `-4-7`, `-4-6`) | the Threatline agent prompt over the review context, with untrusted text fenced by a random nonce: exactly what a Rovo agent run sees | three threat models, each threat quoting its evidence |
| 4. Assemble (deterministic) | none | the three runs | consensus (a threat needs a majority of runs), quotes checked word for word against the sources, the rule-based floor, coverage, severity and STRIDE/ASVS/CWE mappings, the risk score |
| 5. Verify (adversarial) | deep | each accepted AI threat with the quotes it rests on, fenced as data | keep or drop, with a reason |

Code decides what a verifier verdict does:

- A kept threat is marked **Verified** in the panel.
- A dropped threat below the blocking level (High by default) is dismissed, with the verifier's reason recorded on
  it, or stands back under a kept threat it duplicates. An untouched requirement it had is removed.
- A threat at or above the blocking level that the verifier doubts goes to a **security champion**. It never just
  disappears.
- Rule-based threats are never sent to the verifier. One that a dropped AI threat covered becomes active again, with
  its requirement.
- When injection is suspected anywhere in the material, the verifier does not run. A threat citing a flagged source is
  never demoted.

Model errors become failed runs, so a review whose model never answers settles as failed and the gate blocks (AI
errors count as missing). A failed verification leaves the review as assembled, which is stricter, never looser.

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
Opus 5, prompt v1.4.0): 15 of 15 poisoned cases held, graded high-severity recall 96.7% and recall 92.0%, judged
precision of model-proposed threats 79.9% (`evals/results/2026-11-22-recorded-all-engine-opus-5-v1.4.md`,
`evals/results/2026-11-22-match-opus-5-v1.4-all.md`). Severity is computed from each threat's `rating` (attacker, effort,
reach, harm) by a fixed table, lowered by at most one level from the model's own score, and the runs' median counts. The in-product verifier uses its own rubric (does the quoted
evidence support the threat?), not the offline judge's, so judged precision is not the product grading itself.
