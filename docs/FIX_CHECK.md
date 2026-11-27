# Fix check: does the pull request actually fix it?

A requirement used to count as Verified when its tests passed in CI or someone linked a pull request. Neither of those
shows that the code changed. A test named for the requirement can assert nothing, and a pull request link can point at a
change that never touches the check.

With the fix check, CI also sends the pull request's change. Threatline Engine reads it against every requirement and
says, for each one: **fixed**, **partly fixed** or **not addressed**. Each "fixed" quotes the added lines that enforce
the requirement, and code checks every quote against the diff. A verified requirement the change does not show is fixed
goes to a security champion before Done or merge. For anything not fixed, the panel shows what is still missing and a
suggested change.

```
Critical  Verified  Re-authenticate before changing the account email
Evidence: tests passed in CI · acme/payments-service @ 4f1c2a9be03d (2 tests passed)
[Not fixed by the pull request] changeEmail() still updates the address straight away; the new test only checks
                                that the endpoint answers 200.        Why and how to fix   Confirm it is fixed

High  Verified  Magic links expire after 15 minutes
✓ The pull request fixes it · src/auth/magic-link.ts:41                Evidence
```

## The rules (code, not the model)

| What the check found | A requirement verified for this change | An open requirement |
| --- | --- | --- |
| Still running | Holds Done and merge (`fix_check_pending`) for up to 30 minutes | Shown only |
| **Fixed**, with at least one quote code finds in the change | Nothing changes: it stays Verified | "Looks fixed" is shown; its tests still have to pass |
| **Partly fixed**, **not addressed**, or **unclear** (no answer, or no quote code can find) | Waits for a security champion (`fix_unconfirmed`) | Shown only (it already blocks as open) |
| The check failed or timed out, or the site is out of budget | Waits for a security champion (fails closed) | Shown only |
| The change contains text that reads like instructions to an AI | Waits for a security champion, whatever the model said | Shown only |

- **The model can only hold, never release.** "Fixed" never removes a block that would apply without the fix check,
  never verifies an open requirement, and never closes anything. The worst a fooled model can do is say "fixed" about a
  requirement the tests already verified, which is where Threatline was before the fix check existed.
- **Which requirements a check speaks for.** A requirement Verified by CI in the same repository, or Verified with a
  link to the same pull request. Evidence from somewhere else (another pull request, a Confluence page, a note) is not
  about this change, so the check leaves it alone.
- **A quote counts** when it is code on an added line of that file within three lines of where the model said: at
  least 8 characters (or the whole line), never a comment. Whitespace is ignored. A "fixed" or "partly fixed" whose
  quotes all fail becomes **unclear**.
- **The latest change wins.** Each work item keeps one fix check: the newest commit CI sent. The same commit is checked
  only once. A new commit replaces the check, so a fix pushed after a "not addressed" clears the hold by itself.
- **A champion's confirmation** applies to that requirement on that commit. It is written to the risk ledger
  (`fix_check.confirmed`) before it is saved, and the next commit is checked again.

## What the model is told

One deep-tier call (`claude-opus-5`, as for reviews) per change, with every requirement of the work item that is Open,
In progress or Verified (the 20 most severe), each with its threat's own words. The prompt
(`packages/prompts/src/fix-check.ts`, version `fix-v1.0.0`) is strict on purpose:

- a test alone is not a fix; a test that asserts nothing (`expect(true)`), only checks a 200, or mocks out the check it
  claims to test is not addressed;
- a check placed after the side effect, behind a flag that defaults off, compared with `==` where timing matters, or
  caught and ignored is partial at best;
- comments, TODOs, logging and configuration nobody reads are not addressed;
- when the fix might be in code the diff does not show, the answer is partial or not addressed, never fixed.

The diff is the pull request author's text, so it is fenced with a random nonce as untrusted data, and the added lines
go through the same injection scanner as design pages. What the model sees: every changed file except lock files,
bundles, maps, snapshots and binaries, files the requirement's hints point to first, at most 80,000 characters.

## How accurate it is

On 22 hand-labelled changes in TypeScript, Python, Java and Go (`evals/fixtures/fix-cases.ts`), run through the
product's own code path on `claude-opus-5` (`pnpm threatline fix-eval --llm claude-code --model claude-opus-5`):

| Measure | Result |
| --- | --- |
| **False fixes**: a change that does not fix the requirement, called fixed | **0 of 14** |
| Verdicts a reviewer would accept | 21 of 22 (95.5%) |
| Exactly the reviewer's verdict | 20 of 22 (90.9%) |
| Real fixes held for a champion | 1 of 8 |
| The change that tells the AI it is fixed | flagged as injection, and not addressed |

The one real fix held (`go-ssrf-fixed`) adds a safe HTTP client but never shows the delivery worker using it, and the
model said exactly that: the label was written before the run and is left as it was. The other non-exact answer
(`ts-catch-ignore`, a signature check whose error is caught and ignored) came back partly fixed where the label says
not addressed; both hold the requirement. Full report: `evals/results/2026-11-26-fix-check-claude-opus-5.md`.

The cases are built around fake fixes: a green test that asserts nothing, a comment that tells the AI the requirement
is done, a signature check after the payout, a check behind a flag that is off, an SSRF filter on the URL string, a
rate limit per IP address when the threat is one account, an authorisation check in the React page instead of the API,
and JWT verification that still accepts `none`. CI replays the recorded replies on every pull request
(`evals/runner/fix-gate.test.ts`) and fails on a single false fix.

## Set it up

**GitHub Actions.** In the workflow that runs your tests, on `pull_request`, fetch the history and turn it on:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0          # the fix check diffs the pull request's base and head
- run: npm ci && npx vitest run --reporter=junit --outputFile=reports/junit.xml
- uses: pranavsaji/threatline/apps/github-action@main
  if: always()
  with:
    merge-gate: false
    threatline-url: https://…/x1/…
    threatline-token: ${{ secrets.THREATLINE_CI_TOKEN }}
    junit: reports/**/*.xml
    fix-check: true
```

**Bitbucket Pipelines.** In a `pull-requests` pipeline, clone the full history and add `--fix-check`:

```yaml
clone:
  depth: full
pipelines:
  pull-requests:
    '**':
      - step:
          name: Test
          image: node:22
          script:
            - npm ci
            - npx vitest run --reporter=junit --outputFile=test-results/junit.xml
          after-script:
            - node scripts/threatline-ci-report.mjs --junit "test-results/**/*.xml" --fix-check
```

`--fix-check` takes the base from `BITBUCKET_PR_DESTINATION_COMMIT` and builds the pull request link from
`BITBUCKET_PR_ID`; any other CI passes `--diff-base <commit>` and `--pr-url <https link>`. `junit` is optional when the
fix check is on.

**The request.** The CI report (`docs/CI_VERIFICATION.md`) takes two more fields: `diff`, the unified diff of
`base...head` (at most 200,000 characters), and `prUrl`, the pull request's https link. The client leaves generated
files out and cuts the change at whole files to keep the report under 256 KB; test results are never dropped. The web
trigger answers `recorded-checking` while the check runs.

## Where it shows

| Surface | What |
| --- | --- |
| Issue panel, Requirements | One quiet line per requirement. "Why and how to fix" or "Evidence" opens the checked quotes (path and line), what is still needed, a suggested change with **Copy suggested change**, and the deterministic signals (tests named for the requirement, whether the change touches the files the requirement points to). Champions get **Confirm it is fixed** on a held requirement. |
| Header and Done gate | `fix_check_pending` and `fix_unconfirmed` reasons, like any other block. Attestations are issued only on a passing verdict, so Bitbucket's merge check and the GitHub Action block the merge too. |
| Rovo agent and MCP | `get-security-requirements` returns `fixCheck` per requirement: verdict, commit, reason, evidence lines, what is missing, the suggested change, and `holdsDone`. |
| Risk ledger | `fix_check.completed` (actor `ci:<token id>`, per-requirement verdicts) and `fix_check.confirmed` (the champion). |

## Data and cost

- **Stored:** the change only until the check finishes (in Forge storage, in parts), then deleted. The result keeps
  short quotes of added lines (at most five per requirement, 300 characters each), the reason, and the suggestion.
- **Who sees it:** anyone who can see the work item sees the quotes and suggestions for the requirements they can see.
  The CI token's project list decides which work items a pipeline can send a change for.
- **Cost:** one deep-tier call per new commit, usually 5,000 to 25,000 input tokens and 1,000 to 4,000 output tokens
  (roughly $0.05 to $0.25 at Opus 5 prices). The developer's ceiling is `THREATLINE_MAX_FIX_CHECKS_PER_MONTH` (default
  200 a site), on top of the monthly AI budget; over either, the check does not run and the requirement waits for a
  champion.
