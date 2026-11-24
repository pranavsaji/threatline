# Threatline

![tests](https://img.shields.io/badge/tests-1700%2B%20passing-brightgreen)
![coverage](https://img.shields.io/badge/line%20coverage-92.9%25-brightgreen)
![high-severity recall](https://img.shields.io/badge/high--severity%20recall%20%28graded%2C%20Opus%205%29-60%2F60-blue)
![injection resistance](https://img.shields.io/badge/injection%20resistance%20%2855%20cases%2C%20Opus%205%29-15%2F15-blue)
![runs on Atlassian](https://img.shields.io/badge/egress-none-informational)

**Security review that gates Done and merge.** Security review is advisory, so it loses to the deadline. Threatline
makes it part of "Done": every Jira work item gets a cited threat model, the threats that matter become requirements,
and neither the Done transition nor the merge goes through until each one is verified or its risk is accepted by
someone allowed to accept it.

*Build with context, ship with confidence:* the threat model is the context, the gate is the confidence.

![Threatline issue panel](docs/screenshots/jira-1-issue-panel.png)

## The story in five steps

1. **Create a story.** Within a few minutes Threatline Engine has reviewed it by itself on Atlassian-hosted Claude
   models: three independent analyses that must agree and quote their evidence word for word, then a verifier that
   checks each threat against its quotes. No setup, no Rovo agent, no Automation rule.
2. **Read the threats in plain language.** "Anyone with the link can download another customer's orders", with the
   sentence it rests on, its STRIDE category, ASVS 5 and CWE, and a Given/When/Then requirement.
3. **Try to move it to Done.** Blocked, with the open requirements listed and a link back. Missing, failed or
   out-of-date reviews block too, with a one-click re-run: the gate fails closed.
4. **Fix or accept.** Verify a requirement with a PR link, or accept the risk with a reason, controls, an expiry and an
   approver who is not you. Done passes.
5. **Merge.** Paste the signed attestation into the pull request: the Bitbucket merge check (or the
   [GitHub Action](docs/GITHUB.md)) passes for that exact commit. Change one character and it fails.

**And the AI cannot be talked into approving.** Text that tries to instruct the model is flagged in the panel, the
threats resting on it wait for a security champion, and the verdict is always computed by code, never by the model.
Measured on `claude-opus-5`, the model Threatline Engine runs, through the Engine's full path (three runs, the gap
check, then the verifier): all 15 of 15 poisoned cases held, and a separate model grader found all 60 high-severity
must-find threats (97.7% of all) on the full 55-case set, and every must-find threat on 10 fresh cases written before
the gap check existed ([eval](#eval), [how the engine works](docs/ENGINE.md)).

## Also in the box

- **CI closes the loop.** Tests named after a requirement pass in CI (GitHub Action or Bitbucket Pipelines), and
  Threatline marks it Verified with the run as evidence: no clicking ([CI verification](docs/CI_VERIFICATION.md)).
- **Incidents reopen reviews.** An incident on a component re-reviews the open work there, so the next story touching
  it cannot repeat the mistake; the panel names the incident ([incidents](docs/INCIDENTS.md)).
- **One queue for champions.** Threats that need a person, across projects, grouped when the verifier thinks they
  repeat each other, decided in bulk ([champion inbox](docs/CHAMPION_INBOX.md)).
- **See the architecture.** Each review's components, data stores, flows and trust boundaries drawn as a data-flow
  diagram with its threats pinned to them, in the panel, on Confluence and for coding agents ([diagram](docs/DIAGRAM.md)).
- **Less noise, by team.** A false positive dismissed on three work items becomes a suggested project rule; a champion
  approves it for up to 90 days, and it can never hide a threat that would block ([suppressions](docs/SUPPRESSIONS.md)).
- **Audit-ready.** Requirements and evidence mapped (indicatively) to SOC 2, ISO 27001:2022 and PCI DSS v4.0 controls,
  in the posture page and an exportable controls summary ([compliance](docs/COMPLIANCE.md)).
- **A ledger you can audit.** Every acceptance, override and refusal goes into an append-only hash chain with daily
  signed Merkle tree heads (posted to Confluence once a digest space is set under Notifications); download an inclusion proof and check it offline with
  `node scripts/verify-ledger-proof.mjs` (Node built-ins only).
- **For coding agents.** An MCP server and Rovo agent expose the same requirements, so Claude Code or Cursor fix what
  the gate will check, then mark a requirement verified with their pull request as evidence ([walkthrough](docs/MCP.md),
  [skill](mcp-skill/skill.md)). Each requirement also copies as a failing test skeleton
  (TypeScript, Python or Java).
- **Guardrails for the guardrail.** Review runs can be locked to one account, so developers cannot write their own
  review; break-glass overrides need a written reason and are ledgered; warn-only mode expires after 14 days (on GitHub the date lives in the workflow file, so it binds only as far as edits to that file are reviewed: see [GitHub](docs/GITHUB.md)); a
  budget pause needs a champion's confirmation; changes that touch no sensitive paths merge freely.
- **Where people already work.** Issue panel, admin wizard, posture page and dashboard gadget, Confluence threat-model
  pages, fix-by dates (7, 30, 90 days by severity), and a rule-based mode for sites without AI.

Built for Atlassian Codegeist 2026 on Forge: Forge LLMs, Jira, Confluence, Bitbucket, Rovo (agent, actions, MCP) and
Forge SQL. No egress: nothing leaves Atlassian.

## Eval

**On the production model (`claude-opus-5`, prompt v1.4.0, gap check `gaps-v2`, 2026-11-23).** All 55 cases (40
clean, 15 poisoned twins) through Threatline Engine's full path: three runs, the gap check, then the verifier, all on
Opus 5, recorded in `evals/results/opus-5-v1.5/` and replayed offline
(`evals/results/2026-11-23-recorded-all-engine-opus-5-v1.5.md`). CI replays this set on every change
(`evals/runner/gate.test.ts`). Recall is graded two ways: by the keyword matcher, and by a separate `claude-sonnet-4-5`
call per case that decides which shown threat, if any, finds each must-find threat (`pnpm threatline rematch`, verdicts
in `matched/`, report `evals/results/2026-11-23-match-opus-5-v1.5-all.md`). The keyword matcher misses threats worded
differently ("find out which email addresses have accounts" for user enumeration), so it under-reports recall by about
7 points.

| Metric (40 clean + 15 poisoned cases) | Now | Before the gap check | Before the clustering fix |
| --- | --- | --- | --- |
| Injection resistance | 15 of 15 | 15 of 15 | 15 of 15 |
| High-severity recall, graded | **100% (60 of 60)** | 98.3% (59 of 60) | 96.7% (58 of 60) |
| Recall, graded | **97.7% (85 of 87)** | 93.1% (81 of 87) | 92.0% (80 of 87) |
| Recall, keyword matcher | 90.8% | 87.4% | 83.9% |
| Severity of found threats vs the expert's | 39 same, 45 higher, 1 lower | 37 same, 43 higher, 1 lower | 38 same, 42 higher, 0 lower |
| Blocking requirements per story (average) | 4.97 | 4.42 | 4.0 |
| Precision, judged: threats the model proposed | 82.4% (128 of 172, all 40 cases) | 81.1% (101 of 142) | 79.9% (32 cases judged) |
| Citation grounding | 99.8% | 99.8% | 99.8% |

**Fresh held-out set.** Ten new cases (`evals/fixtures/fresh-cases.ts`, two per domain) were written and committed
before the gap check and the verifier changes were built, and nothing was tuned on them. Same runs, before and after:
graded recall 100% both times (26 of 26 with one case ungraded before; 29 of 29 after), high-severity 12 of 12, judged
precision of model-proposed threats 81.4% → 83.6% (`evals/results/2026-11-23-match-opus-5-v1.5-fresh.md`). They
were written by the same author as the fixes, after seeing the misses below, so they test generalisation, not blindness.

**The gap check** (stage 5 in [ENGINE.md](docs/ENGINE.md)). Six threats were missed before it, and five were Low:
threats the runs left out because the prompt asks them to skip generic hygiene, or that only one of three runs raised.
After the runs agree, one more Opus call reads the same context, the agreed threats and the ones only one run raised,
writes a one-line check of each threat reviews commonly leave out (automated abuse of what is reachable, staff screens
that show other people's content, no record of who deleted or paid, cached documents, attacker text reaching logs or
exports), and names at most three gaps. Each is stored hidden until the verifier keeps it, so the gap check alone can
never change what blocks. The verifier now also counts a repeat only when the attacker, the part of the feature and
the harm are all the same (a script in a moderator's session is not the same threat as the script hitting visitors),
and drops added threats that depend on how a feature might be built rather than on what the design says. It found the
moderator-session hijack (High), log forging, proxy caching and the audit trail for comment deletion. Costs: one more
model call per review, and 0.55 more blocking requirements per story.

Two Low threats are still missed. `web-05` expects flooding or brute force of an internet-facing SSO admin portal;
the gap check judged that covered by "the portal has no second factor or network restriction" and noted the design has
no password form. `mobile-08` expects automated sign-ups as a load problem; the gap check raised it, and the verifier
counted it as the credit-farming threat already shown. One found threat is rated below the expert's severity.

What changed around the same model:

- **The gap check and a sharper verifier** (2026-11-23), above.
- **Clustering keeps threats the runs agree on** (2026-11-22). A threat counts when most of the three runs report it.
  Runs often file one attack under different STRIDE categories ("any service can mint tokens" was Elevation of
  privilege in one run and Spoofing in the next), and the clustering required the same category, so both halves were
  voted out: that is how `api-06` lost both of its High threats. Threats now match across runs in any category when
  they quote the same passage and their wording overlaps clearly. The opposite fault went too: two different threats
  from one run that quoted the same sentence were chained into one ("read other customers' invoices by changing the
  id" and "the download has no stated authentication"); a cluster now takes one threat per run, unless the run simply
  restated it. 17 of the 55 cases changed; their verifier, judge and grader replies were recorded again.
- **Severity from stated facts.** Opus rated 52 of 80 found threats above the expert and one below. Each threat now
  states who can attack, how hard it is, how many it reaches and what is harmed (`rating`); a fixed table computes
  likelihood and impact (`ratedScores`), insiders scored like signed-in users (zero trust). The table may lower the
  model's own severity by one level at most (`boundedScores`), because a gate should err on the side of blocking. Across
  the three runs the median score counts, not the highest (the highest still counts under suspected injection).
- **A quieter, sharper rule-based floor.** Tool misuse only when the AI can act, payment manipulation only when money
  moves, leaked credentials only when they are stored, logged or shared (now including signing secrets: "a shared HS256
  secret in environment variables"), third-party disclosure only when personal or health data goes to another company.
  Triggers stay monotonic: more text never switches a rule off. A rule-based threat stays covered while its cover waits
  for a champion, and a specific threat whose severity comes from a rating can cover it one level lower (a model's bare
  numbers never lower the floor).
- **The eval parses runs exactly as the Engine does** (`agentSampleFromText`), retries a malformed judge or grader reply
  once, and refuses recorded verdicts that rate other threats than today's instead of applying them by position.
- **Prompt v1.4.0** adds the rating and a three-item check (automated abuse, values the client sends that the server
  trusts, unauthenticated writes to internal channels).

Tuning and held-out: the prompt checklist uses only misses from the 30-case subset. On the 25 held-out cases it added no
finds (graded recall 87.9% with either prompt). Two severity fixes (insiders scored like users, the one-level bound)
were made after seeing held-out threats rated below High, so the held-out half is not blind for them. The clustering fix
came from one case (`api-06`) and was checked on all 55.

**Which model.** With prompt v1.3.0 and the earlier code, graded recall and high-severity recall were 93.1% and 98.3% on
Opus 5, 79.3% and 85.0% with Sonnet 5 runs checked by an Opus 5 verifier, and 78.0% and 84.2% on Sonnet 5 alone (38 of
40 cases graded), which also let one poisoned case lower its blocking (14 of 15). The Engine stays on Opus 5
(`evals/results/2026-11-22-claude-code-all-engine-sonnet-5.md`, `…-recorded-all-engine-sonnet-5-opus-verify.md`).
Replay it with `pnpm threatline eval --subset all --llm recorded --path engine --gaps recorded --verify recorded --judge
recorded --record-set opus-5-v1.5` (`--subset fresh` for the fresh cases) and `pnpm threatline rematch --record-set
opus-5-v1.5 --match recorded`. The set before the gap check is kept in `evals/results/opus-5-v1.4/`.

**Older recordings: `claude-sonnet-4-5`, prompt v1.3.0, 30 cases** (24 clean, 6 poisoned; `evals/results/recorded/`,
the set CI has replayed since 2026-11-20, `evals/results/2026-11-22-recorded-30.md`). With today's code: recall 88.9%,
high-severity recall 94.6%, 6 of 6 poisoned cases held, citation grounding 99.8%, judged precision of model-proposed
threats 64.4% (strict 31.6%). The clustering fix trades precision for recall on this model (before: 85.2%, 91.9% and
76.3%): Sonnet 4.5 restates and splits threats more than Opus 5, so more generic or overlapping ones survive the vote.
That is one reason the product runs Opus 5.

Each case lists only 1 to 3 must-find threats (most list 2), while Threatline shows about 5 to 7 per case, so strict
precision counts every other threat as wrong. A separate `claude -p` call (tools off, a strict rubric: follows from the
design, specific, not a duplicate) grades each threat outside the list. A judge from the same model family may be
lenient to its own outputs; every verdict is recorded (`judged/`) so you can read it. Recorded verdicts are matched to
threats by STRIDE and title; `--no-coverage` turns off the rule-based floor's coverage.

The eval set is 40 clean cases across web, API, mobile, data and AI features, plus 15 poisoned twins that hide
instructions to the AI in the design text; a poisoned case holds when its risk and blocking count do not drop below
its clean twin's and the injection is flagged. Run it yourself:

```bash
pnpm threatline eval --llm recorded --subset 30 --judge recorded   # replay recorded outputs and judge verdicts (CI)
pnpm threatline eval --llm claude-code --subset 30          # live, through your own Claude Code subscription
pnpm threatline eval --llm recorded --subset 30 --judge claude-code   # re-grade the extras live (one call per case)
pnpm threatline eval --llm fake                             # deterministic baseline rules only, no model
```

## Try it

- **On a Jira site**: [install Threatline for Jira](https://developer.atlassian.com/console/install/13898a7c-6897-48d3-a512-079d9f9f5f00?signature=AYABeCcfIQJqGrR0SUgfCmoTNmEAAAADAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NzA5NTg3ODM1MjQzOmtleS83MDVlZDY3MC1mNTdjLTQxYjUtOWY5Yi1lM2YyZGNjMTQ2ZTcAuAECAQB4CxqLTo9l4lqXuFjNim1xJM%2Bp%2F3TVP9xHS2BrU5DRRucB1BD8mEv4t3Ljf3OukSd5eQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDEh%2BKItDcqUwro%2BHrQIBEIA7MA0KHRf%2BF3YuTEAMovFxVALBMAXOWvXwcePSrlXd8eWbO0Gu4PlzXePH9QGutTzgsBB7obWKVcKw55kAB2F3cy1rbXMAS2Fybjphd3M6a21zOmV1LXdlc3QtMTo3MDk1ODc4MzUyNDM6a2V5LzQ2MzBjZTZiLTAwYzMtNGRlMi04NzdiLTYyN2UyMDYwZTVjYwC4AQICAHi9bVMAkme4qVQX1fQHo6ePw3H40A7cGfz7yrmSfBWMXgHlW5ynSsuhZ7zbqiK2sh%2B2AAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMkPcTbpchY2MsayhfAgEQgDuWokoIpYBa88xi5ggk1L1JkcZBleXY2Fhu75VlWDzfTq%2FPjQu2HTJqqUvWAGr3gQmwdhbGrdneGDgHcgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtZWFzdC0xOjcwOTU4NzgzNTI0MzprZXkvNmMxMjBiYTAtNGNkNS00OTg1LWI4MmUtNDBhMDQ5NTJjYzU3ALgBAgIAeDYASx0XCjkny4iLV6vz%2BKtEGSGT6kdt0QRpkn6D%2FlVEAbLrick3%2FS2k9TO8wl7jjBMAAAB%2BMHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwPyU3UXZLk3LyqQEcCARCAO56x65zN0k8TKW9hcCjB8AjClKyO30ptqnOAj2gX5CQsUchhHNyCLeBw5CSlVzbE5lnPkVzoFWWWPI9DAgAAAAAMAAAQAAAAAAAAAAAAAAAAAE5uz5LjAh1FnegGXQysekL%2F%2F%2F%2F%2FAAAAAQAAAAAAAAAAAAAAAQAAADJlU7brRNHeEAgdUVuQgPgaQWe2H582mtCI1iAJ%2FP3ZS3ti2WQm0S86s3LQVssf56LpbJ8u0XxBB32s7u970Pyt6So%3D&product=jira&product=confluence) (and [Threatline for Bitbucket](https://developer.atlassian.com/console/install/53a2efe5-9150-4e9a-b869-8bd2605d64e0?signature=AYABeMU6Rt2jeek7C5UOdWnYVhcAAAADAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NzA5NTg3ODM1MjQzOmtleS83MDVlZDY3MC1mNTdjLTQxYjUtOWY5Yi1lM2YyZGNjMTQ2ZTcAuAECAQB4CxqLTo9l4lqXuFjNim1xJM%2Bp%2F3TVP9xHS2BrU5DRRucB9X7SgA05cnObTkvhYN1xbQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDNEhzAe7TPWDBVqk6wIBEIA7keQSd6CapbYmtUGdkeKKsGD9awYJ3ooCpMpwMF2EDUNbpBp%2F9PeiHpLYzLpKRCnH1ToDtNvaJyOei0kAB2F3cy1rbXMAS2Fybjphd3M6a21zOmV1LXdlc3QtMTo3MDk1ODc4MzUyNDM6a2V5LzQ2MzBjZTZiLTAwYzMtNGRlMi04NzdiLTYyN2UyMDYwZTVjYwC4AQICAHi9bVMAkme4qVQX1fQHo6ePw3H40A7cGfz7yrmSfBWMXgEaeJ%2BkdCobmSDv47DLtIySAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMGEExVBpjK5bbUYmTAgEQgDvy5cWJv19sweBbrSFr5C3xdwywv%2BBv20pRtihL1aMr7o8uQnVvR9vasue1xGfDidyWyh8RzUzmiGXFBQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtZWFzdC0xOjcwOTU4NzgzNTI0MzprZXkvNmMxMjBiYTAtNGNkNS00OTg1LWI4MmUtNDBhMDQ5NTJjYzU3ALgBAgIAeDYASx0XCjkny4iLV6vz%2BKtEGSGT6kdt0QRpkn6D%2FlVEAWqyfoA4bYp55SbOGUdCdOkAAAB%2BMHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwmXimEV%2FsYgm0GihwCARCAO2yT52i7N%2B%2BDNBN%2F2F87pJutoitrvTBVazhVeMuRbv%2BmP8xV9sDbTccsGcHKl%2BfdohjSFjjtL%2BQGx983AgAAAAAMAAAQAAAAAAAAAAAAAAAAANo1IMueG73KsfmrDTjuUgD%2F%2F%2F%2F%2FAAAAAQAAAAAAAAAAAAAAAQAAADJ0ZrDuRm0Q%2Biua58qqR3NYv5pw6Y4tZl2HqZtAX21FXdWDPb0BBfCK40FDFpZmG9vKBDYJl3oHZ3or2flppy5yAWs%3D&product=bitbucket)), then follow the
  [judge guide](docs/JUDGE_GUIDE.md): run the admin wizard, load the demo data,
  open the epic, try to move it to Done.
- **Locally, no site needed**:

  ```bash
  pnpm install
  pnpm test                                   # unit, contract, pipeline, UI and accessibility tests
  pnpm --filter @threatline/core-ui dev --port 5179   # http://localhost:5179/?state=ready · ?view=admin · ?view=posture
  pnpm threatline sign-demo                      # sign an attestation and watch a one-character change fail
  pnpm e2e                                    # Journeys A and B and the merge check in a real browser
  ```

  `pnpm e2e` drives the real UI against Threatline's real resolvers, agent actions, Done validator and signing, with
  only Jira, Confluence, Rovo and the clock simulated (`e2e/local/server.ts`). CI also runs semgrep (Threatline's own
  rules in `.semgrep.yml` plus the registry rulesets), `pnpm audit`, gitleaks and knip, and fails on any high finding.

  The line-coverage badge comes from `pnpm test:cov` (92.85% of lines on 2026-11-21, when the suite had 1,084 tests; 1,732 on 2026-11-22). It counts only the
  TypeScript under `packages/*/src` and `apps/*/src` (`vitest.config.ts`). The Custom UI (`apps/core/ui`,
  `apps/bitbucket/ui`), the eval runner, `scripts/` and `e2e/` are not part of that figure.

## Docs

- [Roadmap](docs/ROADMAP.md): what comes next.
- [Architecture](docs/ARCHITECTURE.md): the review flow, the risk formula, the verdict rules, packages and ports.
- [Security review](docs/SECURITY_REVIEW.md): Threatline threat-modelled, each control with the test that proves it.
- [Licensing](docs/LICENSING.md): what Threatline does when a site's Paid via Atlassian license is inactive, and the runbook for turning licensing on.
- [Judge guide](docs/JUDGE_GUIDE.md), [screenshots](docs/screenshots/README.md), [privacy](docs/PRIVACY.md),
  [terms](docs/TERMS.md).

## Repository

```
apps/core        Threatline for Jira: Forge functions, Rovo actions and agent, Custom UI (apps/core/ui)
apps/bitbucket   Threatline for Bitbucket: merge check and repository settings
apps/github-action  Threatline merge gate for GitHub (same decision code; see docs/GITHUB.md)
apps/local       pnpm threatline: offline reviews, evals, demo signing
packages/        core (domain), crypto, db, frameworks (ASVS 5, CWE, OWASP LLM/Agentic), prompts, shared, llm-dev
evals/           cases, runner, metrics, recorded model outputs, results
e2e/             Playwright journeys (local harness in CI; optional smoke test on a real site)
scripts/         ledger proof verifier, layout audit, listing screenshots
```

Deploy (development): `pnpm --filter @threatline/core-ui build && cd apps/core && node build.mjs && forge deploy -e development`.
