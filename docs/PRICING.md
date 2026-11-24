# Pricing: cost per review and a recommended Marketplace price

For the **Paid via Atlassian** listing of Threatline for Jira planned for February 2027. Threatline Engine runs each
review on Forge LLMs, and Atlassian bills that usage to the app developer, not to the customer's site. This page works
out what one review costs, what a site can cost in a month, and what price keeps every tier above that cost.

This is a recommendation with its working shown, not financial advice. The owner sets the price. Prices and rates were
read from Atlassian's pages on 2026-11-23 (sources at the end). Recheck them before you set the price.

## Summary

| | Value |
| --- | --- |
| Tokens per review, measured from the repo's recordings (65 cases, characters ÷ 4) | input 11,447 median / 12,235 p90 / 12,525 max; output 9,012 / 10,764 / 11,801 |
| Cost per review from those recordings | **$0.27 median, $0.32 p90**, $0.35 max |
| Same, if the real tokenizer counts 35% more tokens than characters ÷ 4 | $0.37 median, $0.43 p90 |
| Planning cost per review, a real story plus one linked design page, calibrated to live logs | **about $0.65** |
| Heavy review (three full design pages) | about $0.81, so plan on **$1.00** |
| Measured in production (`llm.call` logs, 2026-11-21, six Engine reviews before the gap check existed) | **$0.54 to $0.64** per review; about $1.17 when agent runs were retried. Add about $0.10 to $0.15 for the gap check |
| Hard ceiling per review (400,000 input and 60,000 output tokens, all at Opus 5 rates; enforced in production by `THREATLINE_MAX_TOKENS_IN_PER_REVIEW` / `_OUT_PER_REVIEW` since 2026-11-24) | **$3.50** |
| Per site per month at the production cap of 5 reviews (since 2026-11-24) | **$3.24 (planning)** · $17.50 (ceiling) |
| Per site per month at a cap of 10 reviews (the cap this analysis was first written for) | $2.74 (recordings) · **$6.48 (planning)** · $35.00 (ceiling) |
| Recommended price | **$20 a month flat for 1 to 10 users; $2.50 per user for 11 to 100; $2.00 for 101 to 250; $1.50 for 251 to 1,000; $1.00 above that** |
| Tier that loses money first | 1 to 10 users: profitable at the 10-review cap on planning cost, loses money if every review hits the ceiling, or if the cap rises above about 25 reviews |

About 80% of the cost is output tokens from the three Opus 5 runs. Each review sends about 2,600 tokens of output per
run in the recordings, and about 6,500 tokens per run in the live logs.

## 1. What a review calls

From `docs/ENGINE.md` and the code (`apps/core/src/services/engine.ts`, `packages/core/src/pipeline.ts`,
`gaps.ts`, `verify.ts`):

| Stage | Model (Forge LLMs) | Calls | Output limit per call | Reads |
| --- | --- | --- | --- | --- |
| 1. Gather | none | 0 | | Jira, Confluence |
| 2. Injection check | balanced: `claude-sonnet-5` (then `-4-6`, `-4-5`) | 1, up to 3 with repair and fallback | 6,000 | the raw facts (`extractPrompt`) |
| 3. Three runs, in parallel | deep: `claude-opus-5` (then `-4-8`, `-4-7`, `-4-6`) | 3 | 16,000 | agent prompt (7,557 characters) plus the fenced review context |
| 4. Assemble | none | 0 | | |
| 5. Gap check | deep | 1, or 2 with a repair | 7,000 | the review context, agreed threats, up to 12 minority threats |
| 6. Verifier | deep | 1, up to 2 with a repair | 6,000 | each accepted AI threat and each gap candidate with its quotes |

When injection is suspected anywhere in the material, the gap check and the verifier don't run.

## 2. Tokens per review, measured

**Method.** `scripts/review-tokens.ts` (new, no model calls) replays the `opus-5-v1.5` record set through the same code
the Engine runs: three agent runs, then assembly, then the gap check, then the verifier. It measures every request and
reply. Run it with `pnpm tsx scripts/review-tokens.ts opus-5-v1.5`.

The recordings keep only the reply text. They have no usage fields: the eval's `tokensIn` and `tokensOut` are 0 because
`replayLlm` returns 0. So tokens are estimated as characters ÷ 4. The Engine uses the same estimate to reserve its
budget (`pipeline.ts`).

The injection check is not part of the eval. Its prompt is rebuilt exactly with `extractPrompt` over each case's facts.
Its reply size, 1,937 characters, is the median of the extraction replies in `evals/results/recorded-pipeline/`
(Sonnet 4.5, the earlier pipeline design).

**Data.** 65 cases: 40 clean, 15 poisoned, 10 fresh. There are 6 model calls per review, or 4 when injection is
suspected (the 15 poisoned cases). No case needed a repair call.

| Per review (tokens) | Median | p90 | Max |
| --- | --- | --- | --- |
| Injection check, input | 389 | 414 | 435 |
| Injection check, output (estimated) | 485 | 485 | 485 |
| 3 runs, input | 6,678 | 6,759 | 6,858 |
| 3 runs, output | 7,705 | 9,505 | 10,505 |
| Gap check, input | 2,600 | 3,008 | 3,375 |
| Gap check, output | 799 | 1,267 | 1,369 |
| Verifier, input | 1,744 | 2,152 | 2,404 |
| Verifier, output | 210 | 273 | 322 |
| **Deep tier (Opus 5), input** | 11,031 | 11,846 | 12,115 |
| **Deep tier (Opus 5), output** | 8,527 | 10,279 | 11,316 |
| **Total input** | 11,447 | 12,235 | 12,525 |
| **Total output** | 9,012 | 10,764 | 11,801 |

The median run writes 2,565 output tokens (p90 3,201, max 3,856, across 195 runs). The 50 cases without injection
cost $0.28 median and $0.32 p90. The 15 poisoned cases cost $0.24 median, because they skip two calls.

**Why these numbers are a floor.** The eval cases are short. The rendered review context is a median of 947
characters, about 240 tokens. Real reviews read more:

- **Context scaling, measured with the same code.** A linked 12,000-character design page becomes six facts of 2,000
  characters and adds about 10,900 characters (2,700 tokens) to each prompt that carries the context. That is the
  three runs and the gap check on the deep tier, plus about 2,600 tokens to the injection check. So each full design
  page adds about $0.06 of input per review.
- **Live logs (cross-check).** Forge logs on the demo site on 2026-11-20 showed about 6,000 to 7,000 output tokens and
  about 80 seconds per Opus 5 run. These are the owner's notes and are not committed to the repo. That is about 2.5
  times the recordings' 2,565 (characters ÷ 4). Possible causes are richer demo stories, a tokenizer that counts more
  tokens per character on JSON, or reasoning tokens billed as output. The recordings can't tell which.
- **Tokenizer.** Characters ÷ 4 is a rule of thumb. If the model counts 35% more tokens, the recordings' median
  becomes $0.37.

**Replace the estimate with real usage before setting the price.** The Forge adapter logs `tokensIn` and `tokensOut`
from the platform's `usage` field on every call (`llm.call` lines in `apps/core/src/adapters/forge-llm.ts`). The
admin page shows the month's tokens under **Budgets**. Taking 10 to 20 production reviews from those logs costs
nothing and settles the question.

## 3. Model prices

From the Forge LLMs pricing page (last updated 2026-11-17). Forge bills LLM use in credits: an input credit is $0.10
and an output credit is $0.50.

| Model | Used for | Input, $ per 1M tokens | Output, $ per 1M tokens |
| --- | --- | --- | --- |
| `claude-opus-5` | runs, gap check, verifier | $5 | $25 |
| `claude-opus-4-8`, `-4-7`, `-4-6` (fallbacks) | same | $5 | $25 |
| `claude-sonnet-5` | injection check | $2 | $10 |
| `claude-sonnet-4-6`, `-4-5` (fallbacks) | same | $3 | $15 |
| `claude-opus-5-5` (not used) | | $4 | $20 |
| `claude-sonnet-5-5` (not used) | | $2 | $10 |

- **Who pays.** There is no free LLM allowance. All Forge LLM usage counts toward the developer's monthly Forge bill.
- **Rates in the SDK.** The page says `list()` in `@forge/llm` returns current rates in a `pricing` field.
- **Proxy not needed.** Forge publishes its own rates, so the Anthropic API price is not used as a stand-in.
- **Other Forge costs are small.** A review is about 6 function invocations at the default 512 MB. Assuming about
  360 seconds in total, that is about 180 GB-seconds. Each app gets 200,000 GB-seconds a month free, which covers
  roughly 1,100 reviews. Past that, compute is $0.000025 per GB-second, about $0.005 per review. KVS and SQL use per
  review sits well inside their free allowances.

## 4. Cost per review and per site per month

Each scenario has deep-tier tokens at Opus 5 rates and injection-check tokens at Sonnet 5 rates.

| Scenario | Input tokens | Output tokens | $ per review |
| --- | --- | --- | --- |
| A. Eval recordings, median | 11,420 | 9,012 | 0.27 |
| A. Eval recordings, p90 | 12,260 | 10,764 | 0.32 |
| B. Live-calibrated: 6,500 output per run, one 12,000-character design page | 24,908 | 21,600 | **0.65** |
| C. Live-calibrated: 7,000 output per run, three full design pages | 51,884 | 23,450 | 0.81 |
| D. Context at its 200 KB cap (`MAX_CONTEXT_BYTES`), runs writing 8,000 each | 255,368 | 27,500 | 1.79 |
| E. Per-review caps reached (400,000 in, 60,000 out, all at deep rates) | 400,000 | 60,000 | **3.50** |

The output in B to D is an assumption, scaled from the live logs. Only A is measured from the repo.

**Cap mechanics** (`apps/core/src/adapters/kvs-config.ts`, `services/budget.ts`, `consumers/review-consumer.ts`):

- **Developer ceiling.** The Forge variables `THREATLINE_MAX_REVIEWS_PER_MONTH` (production: 10),
  `THREATLINE_MAX_TOKENS_IN_PER_REVIEW` and `THREATLINE_MAX_TOKENS_OUT_PER_REVIEW` set a ceiling. Each budget field is
  the smaller of the site admin's value and that ceiling, so a site admin can lower spend but never raise it. Without
  a variable, that field has no ceiling. The site starts at the default (500 reviews a month, 400,000 input and
  60,000 output tokens per review), and its admin can save any higher value: the schema sets only a minimum of 1.
  Only the review variable is set in production (`docs/MARKETPLACE.md`). **Until
  `THREATLINE_MAX_TOKENS_IN_PER_REVIEW=400000` and `THREATLINE_MAX_TOKENS_OUT_PER_REVIEW=60000` are set too, the $3.50
  per-review ceiling holds only while site admins keep the defaults.**
- **Counting reviews.** The count is per site, per calendar month (UTC). It is reserved atomically (increment, then
  check) when a review is created, so parallel gathers can't overshoot. Every new revision counts: the first review, a
  re-run (panel button or label), and an incident or create whose content changed. Edits only mark a review out of
  date. Rules-only reviews use no AI and don't count.
- **At the cap.** The review is created as failed with reason `budget`. The gate blocks until a champion confirms, and
  the admin sees the pause.
- **Per-review tokens.** Each model call atomically reserves its estimated input (characters ÷ 4) and its full
  `maxOutputTokens` against the review's caps before it runs, then settles to the actual usage. Output can't pass
  60,000. Input can pass 400,000 slightly when the real token count exceeds the characters ÷ 4 estimate of the last
  call. So $3.50 is "about", not exact.
- **Runs are not repeated.** Three runs (`agentSamples: 3`) are part of every review. A redelivered queue job never pays
  twice, because runs and stages are checkpointed.

**Monthly AI cost per site:**

| Reviews per month | A (recordings median) | A (p90) | B (planning) | C (heavy) | D (200 KB context) | E (ceiling) |
| --- | --- | --- | --- | --- | --- | --- |
| **10 (production cap)** | $2.74 | $3.22 | **$6.48** | $8.10 | $17.91 | $35.00 |
| 25 | $6.85 | $8.05 | $16.20 | $20.26 | $44.78 | $87.50 |
| 50 | $13.70 | $16.09 | $32.40 | $40.52 | $89.55 | $175.00 |
| 100 | $27.40 | $32.19 | $64.80 | $81.04 | $179.11 | $350.00 |
| 500 (the site default if the variable were unset) | $136.98 | $160.94 | $324.01 | $405.21 | $895.53 | $1,750.00 |

**Trials cost too.** A 30-day trial site can use the full cap. Atlassian checks evaluation licenses only on the
billing date, so a trial can stay active for up to 59 days. Each trial can cost up to two months of cap: about $13
on planning cost, or $70 at the ceiling. Free installs from the install links cost the same until the paid listing
replaces them.

## 5. Marketplace pricing mechanics (Forge, Paid via Atlassian)

- **Payment model.** Paid via Atlassian or Free. Atlassian bills the customer, collects and remits sales tax, and pays
  out. The payment model is hard to change after listing.
- **Price basis (standard billing).** Customers pay by the number of users on the parent product, not the number of
  users who use the app. For Jira apps, that is the highest Jira user count on the site. Atlassian's own Forge example:
  500 users at $2 per user per month is $1,000 a month.
  - User-based billing, where a customer pays only for users granted access, is an Early Access Program. It is not
    available for publishing yet.
- **Tiers.** The partner sets a price per user tier. Atlassian's pages name 1-10, 11-100 and 101-250, and Jira tiers now
  go up to 100,000 users (since 2025-07-09).
  - The 1-10 tier can be set to any price, including $0. Since 2021, $0 is an option, not a requirement.
  - Monthly invoices use maximum quantity billing: the highest seat count in the period.
  - Annual pricing is 10 times the monthly price, which is about a 17% discount.
- **Revenue share.** For Forge apps (no Connect modules, OAuth, Forge UI), the partner keeps 84% from 2026-04-01 and
  **83% from 2026-10-01**.
  - From 2026-01-01, the partner keeps **100% until $1M of lifetime Forge revenue**, counted per partner across all
    their Forge apps. After that, the standard rate applies.
  - So at launch Threatline keeps 100%. The tables below also show 83%, for after the $1M mark or if the incentive
    ends (Atlassian promises at least 6 months' notice).
- **Payouts.** Atlassian pays by EFT, within 30 days after the end of the month in which at least $500 is owed. Full
  refunds are allowed within 30 days of purchase.
- **Trials.** 30 days. A trial converts to a monthly paid license if the customer has a payment method on file.
- **Editions.** Atlassian supports app editions (for example Standard and Advanced). Its packaging guide recommends
  break-even analysis and keeping advanced features in the higher edition. Check whether a Forge app can read its
  edition at runtime before relying on it to set caps.
- **Price changes.** Price changes take effect within 24 hours. Existing cloud customers keep the lower price for 60
  days (price protection).
- **Manifest and code.** A paid Forge app sets `app.licensing.enabled: true` in the manifest, and the app should check
  the license in its context before running paid work. The production manifest (`apps/core/manifest.yml`) has no
  `licensing` block yet.

## 6. Recommended price

The AI cost is **per review, per site**, capped by one developer-wide number. It does not grow with users. Revenue
grows with users. So the small tiers carry the risk, and the 1-10 tier should not be $0: a $0 tier with a 10-review
cap costs about $6.50 a month per site on planning cost, and up to $35.

| Tier | Price per month | Notes |
| --- | --- | --- |
| 1-10 users | **$20 flat** | Covers the 10-review cap at planning cost (about 3 times over at 100%, 2.6 times at 83%) |
| 11-100 users | **$2.50 per user** | 25 users = $62.50, 100 users = $250 |
| 101-250 users | **$2.00 per user** | 250 users = $500 |
| 251-1,000 users | **$1.50 per user** | |
| 1,001+ users | **$1.00 per user**, tapering | |

**Margin at the production cap of 10 reviews per site per month:**

| Users | Price | Net at 100% | Net at 83% | AI cost, planning ($0.65) | Margin at 83% | AI cost, ceiling ($3.50) | Margin at 83%, ceiling |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | $20.00 | $20.00 | $16.60 | $6.50 | +$10.10 | $35.00 | **−$18.40** |
| 25 | $62.50 | $62.50 | $51.88 | $6.50 | +$45.38 | $35.00 | +$16.88 |
| 50 | $125.00 | $125.00 | $103.75 | $6.50 | +$97.25 | $35.00 | +$68.75 |
| 100 | $250.00 | $250.00 | $207.50 | $6.50 | +$201.00 | $35.00 | +$172.50 |
| 250 | $500.00 | $500.00 | $415.00 | $6.50 | +$408.50 | $35.00 | +$380.00 |

**If the review cap were raised**, net at 83% minus AI cost. "Heavy" is $1.00 per review.

| Users | 25 reviews (planning / heavy / ceiling) | 50 reviews | 100 reviews | Break-even reviews (planning / heavy / ceiling) |
| --- | --- | --- | --- | --- |
| 10 | +$0.35 / **−$8.40** / **−$70.90** | **−$15.90 / −$33.40 / −$158.40** | **−$48.40 / −$83.40 / −$333.40** | 25 / 17 / 5 |
| 25 | +$35.62 / +$26.88 / **−$35.62** | +$19.38 / +$1.88 / **−$123.12** | **−$13.12 / −$48.12 / −$298.12** | 80 / 52 / 15 |
| 50 | +$87.50 / +$78.75 / +$16.25 | +$71.25 / +$53.75 / **−$71.25** | +$38.75 / +$3.75 / **−$246.25** | 160 / 104 / 30 |
| 100 | +$191.25 / +$182.50 / +$120.00 | +$175.00 / +$157.50 / +$32.50 | +$142.50 / +$107.50 / **−$142.50** | 319 / 208 / 59 |
| 250 | +$398.75 / +$390.00 / +$327.50 | +$382.50 / +$365.00 / +$240.00 | +$350.00 / +$315.00 / +$65.00 | 638 / 415 / 119 |

Monthly prices are used throughout. On annual billing, a month of revenue is about 17% lower.

**Which tiers lose money under high usage:**

- **1-10 users.** This tier loses first. It is safe at the 10-review cap on realistic reviews, and loses only if every
  review hits the per-review ceiling. Above about 17 reviews (heavy) or 25 (planning) it loses money.
- **11-25 users.** These sites lose money at 100 reviews, and at 50 if reviews approach the ceiling.
- **50 users and up.** These sites only lose money when reviews approach the per-review ceiling at 50 to 100 reviews a
  month.

**What to do with the cap.** At launch, keep `THREATLINE_MAX_REVIEWS_PER_MONTH` at 10. Raise it only to about 20 while
the cap is one number for every site. A larger customer will want more than 10 reviews a month, so before raising it
much further, make the cap follow what the site pays. Two ways: an Advanced edition with a higher cap, or a per-site
override that only the developer can set. Either is a code change, not part of this document.

**Alternatives the owner might prefer:**

- **Lower entry price ($10 flat for 1-10, $2.00 per user up to 100).** Still covers planning cost at the cap, with
  thinner margins at the ceiling.
- **Higher price for an AI security product ($3 to $4 per user).** Fewer installs, more room to raise the cap.
- **Cutting cost instead of raising the price:**
  - Opus 5.5 is listed at $4/$20, which would make scenario B $0.52 instead of $0.65. It would need a new recorded
    eval before switching.
  - Sonnet 5 for the runs would cost about 60% less. But the eval shows a large drop in quality: judged recall 78.0%
    against 97.7%, high-severity 84.2% against 100%.

## 7. Risks and caveats

- **Token counts are estimates.** No recording in the repo has real usage. Recorded output gives about 2,600 tokens
  per run, and the live notes about 6,500. The planning figure follows the live notes. Measure from production `llm.call`
  logs before setting the price (section 2).
- **Reasoning tokens.** If Forge enables reasoning for Opus 5 and bills it as output, output per run can grow. The
  16,000-token output limit per run and the 60,000 per review cap still bound it.
- **Fallback models.** If `claude-opus-5` is unavailable, the deep tier falls back to Opus 4.8, 4.7 or 4.6 at the same
  $5/$25. If `claude-sonnet-5` is unavailable, the injection check uses Sonnet 4.6 or 4.5 at $3/$15. That changes the
  total very little.
- **The token ceiling isn't enforced yet.** The per-review token ceiling is not developer-enforced in production yet. A
  site admin can raise the per-review token caps on the admin page. Set both token variables (section 4) before
  listing as paid.
- **The cap is global.** One developer variable covers every site. Raising it for one customer raises it for all,
  including 1-10 user sites and trials.
- **Price changes.** Atlassian can change Forge LLM rates; the pricing page was updated 2026-11-17. Atlassian can also
  change the revenue share, though it promises at least 6 months' notice. The $1M incentive is described as temporary.
- **Unmetered installs.** Trials, free install links and sites that never convert all cost money with no revenue.
  Licensing (`app.licensing.enabled` plus a license check before Engine reviews) has to be in place when the paid
  listing goes live.
- **Pricing pages.** Several Atlassian pricing pages are older than their rules: the pricing and billing page shows
  "last updated 2025-06-17" yet lists the 2026 rates. The tier boundaries above the ones named here, and the exact
  monthly calculation per tier, come from the Marketplace pricing tool when you set the price.
- **Not financial or tax advice.** Payouts are in USD. Income tax on them is the owner's.

## Sources

All accessed 2026-11-23.

- Forge LLMs pricing (per-model credits and USD, no free quota; last updated 2026-11-17):
  <https://developer.atlassian.com/platform/forge/runtime-reference/forge-llms-api-pricing/>
- Forge platform pricing (free allowances, compute and storage rates, LLMs billed to the developer; last updated 2026-11-17):
  <https://developer.atlassian.com/platform/forge/forge-platform-pricing/>
- Forge invocation limits (default 512 MB memory): <https://developer.atlassian.com/platform/forge/limits-invocation/>
- Marketplace pricing, payment and billing (revenue share 84% from 2026-04-01, 83% from 2026-10-01; $1M Forge
  incentive; $500 payout threshold; annual = 10× monthly; price changes):
  <https://developer.atlassian.com/platform/marketplace/pricing-payment-and-billing/>
- Updates to Marketplace revenue share (the $1M lifetime Forge incentive, per partner, eligibility; 2025-05-05, dates later moved to April and October 2026):
  <https://www.atlassian.com/blog/developers/updates-to-marketplace-revenue-share-2026>
- Forge licensing overview (standard billing per user, `licensing.enabled`, user-based billing EAP; last updated 2026-07-14):
  <https://developer.atlassian.com/platform/forge/licensing-overview/>
- Decide pricing and licensing model (Paid via Atlassian or Free; EULA and DPA required; last updated 2026-05-19):
  <https://developer.atlassian.com/platform/marketplace/onboarding-hub/launch/decide-pricing-and-licensing-model/>
- App editions pricing and packaging guide: <https://developer.atlassian.com/platform/marketplace/app-editions-pricing-and-packaging-guide/>
- $0 price point for the 1-10 cloud tier (2021-12-07):
  <https://community.developer.atlassian.com/t/introducing-a-new-0-price-point-for-your-1-10-cloud-app-user-tier/54225>
- Licensing FAQ (30-day cloud trials; evaluation licenses checked on the billing date):
  <https://developer.atlassian.com/platform/marketplace/knowledge-base/licensing-faq/>
- Understand billing for Marketplace apps (priced by the parent product's user count):
  <https://support.atlassian.com/subscriptions-and-billing/docs/understand-billing-for-cloud-apps/>
- How maximum quantity billing works: <https://support.atlassian.com/subscriptions-and-billing/docs/how-maximum-quantity-billing-works/>
