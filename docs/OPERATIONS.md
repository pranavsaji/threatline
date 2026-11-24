# Operations runbook

For the developer running Threatline in production: what to watch, what each alert means, how to get a stuck or
failed review moving again, and where the limits are. Everything here reads state; nothing in it needs a deploy.

Threatline's functions log one JSON object per line (`log(event, fields)` in `packages/shared`). Fields are ids,
counts, codes and flags, never page text, prompts or model output. `forge logs` shows only what the functions log, so
every failure path logs an event; the names below are the ones to search for.

## How a review moves

1. **Gather** (queue job `gather`): reads the work item and its sources, reserves one of the month's reviews, creates
   revision `rev_<issueId>_<n>` in `awaiting_agent`, and logs `review.created`.
2. **Runs.** In *Rovo agent* mode, the Automation rule's "Use agent" steps call `get-review-context` (log
   `action.context`) and `submit-threat-model` (log `sample.ingested`). In *Threatline Engine* mode, the app runs them:
   `engine` jobs `extract` (the injection check), then three `propose` jobs in parallel (log `engine.run`).
3. **Assemble** (job `assemble`, log `review.assembled`) after each run. A review settles `ready` when all runs are in
   and a majority are valid. It settles `failed` when all are in and too few are valid.
4. **Sweeper** (every 5 minutes): a review still `awaiting_agent` when the **agent timeout** (Budgets, 15 minutes by
   default) has passed **since it was created** becomes `agent_timeout` (log `review.agent_timeout`). Whatever arrived
   is assembled at once: 2 valid runs of 3 settle it `ready`; fewer leave it timed out, and the gate blocks.
5. **Engine only, after `ready`:** gap check (`engine.gaps`), then verifier (`engine.verified`).

The worst case for a review whose runs never all arrive is the agent timeout plus up to 5 minutes (the sweeper's
cadence) plus one assembly job. Before this runbook's fixes the timeout counted from the review's *last* run. A review
whose third run never came then waited the whole timeout again after its second run. That is how PAY-7 took
23 minutes.

## What to watch

```sh
# Everything from the last hour
forge logs -e production --since 1h

# Failures only (job failures, model failures, sweeper problems, alerts)
forge logs -e production --since 1h | grep -E '"event":"(job\.(failed|retries_exhausted)|llm\.(failed|gave_up|empty)|engine\.(retry_later|extract_failed|verify_failed|gaps_failed|token_budget_reached|usage_failed|checkpoint_failed)|sweep\.|alert\.|gather\.failed|action\.(submit|context)\.denied)'

# Slow or timed-out reviews
forge logs -e production --since 6h | grep -E '"event":"review\.(created|assembled|agent_timeout)"'

# One review end to end
forge logs -e production --since 1d | grep rev_10042_2
```

Add `--grouped` to group by invocation, or `-n 500` for more lines.

| Event | Meaning | Usually |
| --- | --- | --- |
| `llm.failed` | One Forge LLM call failed. `status` is the HTTP status (0 means a network error), `attempt` counts from 0, `retrying` says whether the adapter will try again after `delayMs`. | 429 or 529 when many reviews start together. One or two are normal. |
| `llm.gave_up` | Every model and retry of a tier failed. `code`: `upstream` or `timeout` (transient, the job is retried), `forbidden` (every model of the tier refused with 400 or 404: retired, or not enabled for the app), `validation` (a malformed request, which is a Threatline bug). | `forbidden` needs `ENGINE_MODELS` in `apps/core/src/adapters/forge-llm.ts` updated. |
| `engine.retry_later` | An Engine stage failed transiently. The queue runs it again later, after 60–90 s, then 120–150 s, then 180–210 s. | Rate limits. It recovers without action. |
| `job.retry` / `job.retries_exhausted` | Queue-level retry of any job on `upstream` or `timeout`, at most 3 times. When retries are exhausted, an Engine run is stored as a failed run. | A long Jira, storage or Forge LLM outage. |
| `job.failed` | A queue job returned an error (`kind`, `code`, `attempt`, `reviewId`/`issueId`, `stage`). | Look at the event logged just before it. |
| `engine.run` with `valid:false` | An Engine run failed (`code`: `schema`, `no_json`, `invalid_json` for unusable output; `upstream`, `timeout`, `forbidden` for model errors; `budget`). | Occasional `schema` is normal. Many in a row point to a prompt or model change. |
| `sample.ingested` with `valid:false` | A Rovo agent run was unusable (`code`). With `fitted:true`, it was over the contract (long wording, extra keys) and was repaired deterministically, then stored valid. | — |
| `action.submit.denied` / `action.context.denied` | The Rovo agent's call was refused (`reason`). | `not_review_author`: see the alert text. `engine_mode`: the site is in Engine mode but the Automation rule still runs. |
| `review.agent_timeout` | The sweeper timed a review out. `arrived` of `expected` runs had come, `minutes` since it started, `assembling` says whether what arrived is being assembled now. | `arrived:0` in Rovo mode means the Automation rule did not run the agent. In Engine mode it means the jobs never finished. |
| `sweep.*` | The sweeper could not read the policy or the review list, or could not write or queue. | Storage or queue outage. It runs again in 5 minutes. A review whose assembly could not be queued is put back to be swept again. |
| `engine.token_budget_reached` | A stage was refused by the per-review token cap (`stage`, `capIn`, `capOut`). | The caps are too low for the work item's material. |
| `alert.failrate`, `alert.budget`, `alert.credits_paused` | An ops alert fired (`notified` says whether the ops work item got a comment). These are logged even with no ops work item configured. | See below. |
| `alert.comment_failed`, `alert.state_unreadable` | An alert could not be posted or deduplicated. | Check that the ops work item exists and the app can comment on it. |

The admin page's **Recent runs** shows the last 50 reviews with each stage's time and error: *Agent runs timed out*
(`agent_timeout`), *Agent output was not valid* (`schema`), *Agent returned no threat model* (`no_json`), *Budget
reached*.

## Alerts and what to do

Alerts go to the **Ops alerts work item** (admin page → Notifications) as one comment that mentions its admins. Each
alert is deduplicated by its key, and each is also logged (see above).

| Alert (key) | Fires when | Do |
| --- | --- | --- |
| Fail rate (`alert:failrate:<hour>`, hourly) | More than 20% of the reviews **created in the last hour** failed, timed out, or were settled on only some of their runs after the agent timeout. The text breaks down how many were budget-paused, how many got no run at all, and how many runs were refused as not from a review author. | **No run at all, Rovo mode:** open Project settings → Automation → the Threatline rules → Audit log. Re-select Threatline in each Use agent step if it says the agent is deactivated (this happens after app updates). **No run at all, Engine mode:** search `llm.gave_up` and `job.retries_exhausted`. A Forge LLM outage passes; `forbidden` needs a model list update. **Partial:** usually rate limits or slow Rovo runs. Check `llm.failed` statuses and Rovo credits. **Refused runs:** admin → Review mode → Who can submit AI review runs must be the Automation rule owner. |
| Review budget warning (`alert:budget-warning:<month>`) | This month's reviews reach 80% of *Reviews per month*. | Raise it on Budgets if more are expected (up to the developer ceiling). |
| Review budget reached (`alert:budget:<month>`) | The month's reviews are used up. New reviews are created `failed` with reason `budget` and block until a champion confirms or a re-run after the budget is raised. | Raise *Reviews per month*, or raise the developer ceiling `THREATLINE_MAX_REVIEWS_PER_MONTH`. Then re-run the paused work items. |
| Token budget (`alert:token-cap:<day>`) | An Engine stage was refused by the per-review token cap. A refused run counts as failed; a refused gap check or verifier leaves the review as assembled. | Raise the per-review token caps on Budgets, or the developer ceilings (below). Then re-run the review. |
| Rovo credits (`alert:credits:<day>`) | The last 3 Rovo agent runs came back empty, so Rovo reviews are paused for up to 6 hours after the last run. | Check the site's Rovo usage. Or switch Review mode to Threatline Engine or Rule-based checks only. |
| Incident re-review paused (`alert:incident-budget:<incident>`) | An incident could not reopen a review because of the budget. | Raise the budget, then re-run from the work item's panel. |

## Re-running or replaying a failed review

- **Re-run** (creates the next revision): the work item panel's **Re-run review**, or the Rovo action `start-review`.
  Both are limited to 10 re-runs per person per hour. A re-run is refused while the latest review is still running
  (an Engine review, or a Rovo review with at least one run, younger than the agent timeout). After the timeout, the
  sweeper settles it within 5 minutes and re-running works. In Rovo mode the re-run re-adds the `threatline-review`
  label, which fires the Automation re-run rule (`apps/core/automation/threatline-review-rule.md`).
- **A Rovo review with no run at all** can be re-run at once: the rule may never have fired.
- **Replaying offline:** the Engine's stages are what the offline harness runs. Use
  `pnpm threatline review <caseId> --llm fake --path engine` to reproduce a pipeline behaviour without paid calls, and
  `pnpm threatline eval --llm recorded --path engine` to replay recorded runs (CI does this). Live model calls
  (`--llm claude-code`) cost money and ask first.
- **Do not** edit review rows by hand. Review state, samples and stages are insert-only or compare-and-set on purpose,
  and the ledger records triage.

## Budgets and caps

| Setting | Where | Default | Effect |
| --- | --- | --- | --- |
| Reviews per month | admin → Budgets | 500 | Reserved atomically at review creation. At the cap, new reviews pause (`failed`, `budget`). Rules-only reviews are not counted. |
| Input / output tokens per review | admin → Budgets | 400,000 / 60,000 | Every Engine model call reserves its estimate atomically on the review row and settles to actual use. A call that would cross the cap is refused (`budget`). |
| Agent timeout | admin → Budgets | 15 min | Counted from review creation. See "How a review moves". |
| Agent runs per review | admin → Budgets | 3 | 1, 3 or 5. A review needs a majority to be valid. |
| `THREATLINE_MAX_REVIEWS_PER_MONTH` | `forge variables set -e production ...` | unset | The developer's ceiling over every site's *Reviews per month*. Production is 10 (2026-11-22). |
| `THREATLINE_MAX_TOKENS_IN_PER_REVIEW` | Forge variable | unset | Ceiling over input tokens per review. |
| `THREATLINE_MAX_TOKENS_OUT_PER_REVIEW` | Forge variable | unset | Ceiling over output tokens per review. |

A ceiling value that is not a positive whole number is ignored. Admins cannot go above a ceiling: the admin page saves
the value, but the policy read is capped (`applyCeiling` in `apps/core/src/adapters/kvs-config.ts`). Changing a
Forge variable takes effect on the next deploy of the environment.

What one Engine review reserves: extract 6,000 output tokens, three runs at 16,000 each in parallel, gap check 7,000,
verifier 6,000. Reservations are settled to actual use after each call, so a review rarely uses its whole cap. A
per-review output cap below about 50,000 (three runs reserving 16,000 each at once, plus the injection check's actual
use) will refuse runs.

## Retries and idempotency

- **Inside one model call** (`apps/core/src/adapters/forge-llm.ts`): on 408, 425, 429, 5xx, 529 or a network error,
  the same model is tried up to 2 more times. Each wait is exponential backoff with full jitter (up to 2 s, then 4 s,
  capped at 15 s). A retry happens only while it can still finish within 120 s of the request's start, so it fits the
  queue function's 300 s limit. After that the tier's next model is tried. 400 and 404 mark a model refused for the
  runtime's life.
- **Per job** (`apps/core/src/consumers/retry.ts`): a job that returns `upstream` or `timeout` is redelivered up to 3
  times, 60–90 s, then 120–150 s, then 180–210 s later. The jitter keeps jobs that failed together from retrying
  together. Engine `extract` and `propose` return a transient model failure as an error while retries remain, so the
  queue retries them. On the last delivery the failure is stored as a failed run, and the review settles rather than
  waiting for the timeout.
- **Idempotency:** a run's model answer is checkpointed before it is stored. Samples are insert-only per slot. Token
  reservations are settled to zero on a failed call. Assemblies and the sweeper write with compare-and-set. So a
  redelivered job never pays twice, never stores a second sample, and never overwrites a newer assembly.
- **Invalid output:** an Engine run's reply and a Rovo agent's submission both get the same deterministic repair
  (`fitAgentModel`): long wording is trimmed, unknown keys are dropped, and quotes are only shortened, so they stay
  verbatim. Anything still invalid is a failed run; it is not retried, because a retry of a paid deep-tier call doubles
  the cost and rarely fixes the format. The Engine's extract, verifier and gap-check stages already make one repair
  call with the validation error (`callStage` in `packages/core/src/pipeline.ts`).

## Known limits

- **Sweeper cadence:** Forge's shortest scheduled interval is 5 minutes, so a timed-out review settles 0–5 minutes
  after its deadline.
- **Concurrency:** jobs of one work item run one at a time (key `issue-<id>`). Engine model calls run 3 at a time per
  work item (key `engine-<id>`). There is no cap across work items, so many reviews starting together (a bulk import,
  a seeded demo) all call Forge LLMs at once. The retries above absorb a rate limit, but a large burst can still push
  runs to their last retry. The first sign is `llm.failed` with status 429.
- **Rovo agent runs** happen inside Jira Automation. Threatline sees only the actions the agent calls. A run that
  never calls `submit-threat-model` (credits, Automation limits, a deactivated agent) shows up only as a missing run
  and then a timeout. The Automation audit log is the only place that says why.
- **Function time limit:** the queue consumer has 300 s. A deep-tier run that writes its full 16,000 tokens slowly can
  approach that limit. A run killed by the platform is redelivered by the queue (it was never checkpointed). If it is
  never redelivered, the review waits for the sweeper.
- **The hourly fail-rate window** counts reviews by creation time over the last hour, and looks at most 500 rows per
  status. A review that times out 15–20 minutes after creation is counted in the hour it was created.
- **Partial reviews** are counted only when the sweeper settled them with fewer runs than expected. A review whose
  three runs all arrived but one was invalid is `ready` and not counted. Search `engine.run` or `sample.ingested` with
  `valid:false` for those.
