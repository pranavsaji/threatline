# Verification from CI

A security requirement is closed by evidence. Until now a developer gave that evidence by hand: a PR link in the issue
panel, or `verify-requirement` over MCP. With verification from CI, the test run is the evidence: CI tells Threatline
which requirement tests passed on a commit, and Threatline marks those requirements **Verified** with a link to the run.
Nobody clicks anything, and the Done gate opens by itself once the tests prove the acceptance criteria.

## How a test names its requirement

Every requirement has an id such as `req_1a2b3c4d5e6f7a8b` (`req_` and 16 lowercase hex digits). The test skeletons
Threatline copies (panel → **Copy test skeleton**, or `get-security-requirements` with `testLanguage`) already put it in
the test name:

| Language | Where the id is | The name JUnit reports |
| --- | --- | --- |
| TypeScript (vitest, jest) | the `describe` title: `describe('PAY-101 Verify webhook signatures [req_1a2b3c4d5e6f7a8b]', …)` | `PAY-101 Verify webhook signatures [req_…] > rejects a bad signature` |
| Python (pytest) | the function: `def test_req_1a2b3c4d5e6f7a8b_the_request_is_rejected()` | `tests.test_webhooks test_req_…_the_request_is_rejected` |
| Java (JUnit 5, Surefire, Gradle) | the method: `void req_1a2b3c4d5e6f7a8b_theRequestIsRejected()` | `com.acme.Pay101SecurityTest req_…_theRequestIsRejected` |

Any test you write yourself works the same way: put the id in its name (or a `describe` around it). The match is strict:
`req_` plus exactly 16 lowercase hex digits, not touching another letter or digit (`_`, spaces, brackets and dots
separate). A test whose name carries no id is ignored.

**The rule.** On one run, a requirement is verified when at least one of its tests passed and none failed. A failure or
an error in any of its tests (including a flaky or rerun failure, or an error on the whole suite) means it is not
verified. Skipped tests prove nothing. CI only ever moves a requirement that is **Open** or **In progress**:

- a requirement already **Verified** stays as it is; if its tests fail on a later run, it stays Verified and the report
  says so (`stillVerified`), so a reviewer can reopen it in the panel. CI never un-verifies silently, and never
  un-verifies at all;
- an **accepted risk** or a **Not applicable** is never changed by CI, even if the person's decision lands while the
  report runs (the save is a compare-and-set on the status it read);
- CI never approves or rejects an acceptance, dismisses a threat, marks anything Not applicable or overrides the gate.

## Set it up

### 1. Create a CI token (Jira admin)

**Threatline admin → CI verification** shows the web trigger URL for your site and lists the CI tokens. Choose
**Create token** (optionally limited to some projects, e.g. `PAY, SEC`). The token, `tlci_<id>_<secret>`, is shown once:
store it as a secret in your CI. Threatline keeps only its SHA-256 hash, in Forge secret storage. **Revoke** stops a
token at once; to rotate, create a new token, switch CI to it, then revoke the old one. Creating and revoking are
recorded in the risk ledger (the token id, never the token).

### 2a. GitHub Actions

Run the action **in the workflow that runs your tests**, after them, with `merge-gate: false` (the merge gate stays in
its own `pull_request_target` workflow, see [GITHUB.md](GITHUB.md)):

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npx vitest run --reporter=junit --outputFile=reports/junit.xml
      # Pin to a full commit SHA from https://github.com/pranavsaji/threatline/commits/main
      - uses: pranavsaji/threatline/apps/github-action@main
        if: always()   # report failures too: a failing requirement test is reported as failed
        with:
          merge-gate: false
          threatline-url: https://…/x1/…            # Threatline admin → CI verification → Copy URL
          threatline-token: ${{ secrets.THREATLINE_CI_TOKEN }}
          junit: |
            reports/**/*.xml
```

| Input | Meaning |
| --- | --- |
| `threatline-url` | The web trigger URL. |
| `threatline-token` | The CI token, from a secret. The action masks it in the log. |
| `junit` | JUnit XML globs, one per line, relative to the workspace (`*`, `**`, `?`, `{a,b}`). |
| `merge-gate` | `true` (default) also runs the merge gate in the same step; `false` only reports. |

The work item is found exactly as the merge gate finds it: the keys in the pull request title and branch name
(`PAY-7 …`, `feature/PAY-7-hmac`); on a push, the branch name. A requirement's own sub-task key (`PAY-101`) works too.
The commit is the pull request's head commit (on a push, `GITHUB_SHA`), and the evidence link is the workflow run. The
output `ci-report` is `reported`, `warning` or `failed`. Each key named gets its own report; a key Threatline answers
403 or 404 for (another project, or not a work item) is skipped with a line in the log, and the step fails only when
every key named does. An algorithm name or a full CVE id (`SHA-256`, `CVE-2025-1234`) is never taken for a key; keys set in
`THREATLINE_ISSUE_KEY` are always used as given.

Secrets are not given to workflows triggered from forks, so reports come from branches in your own repository.

### 2b. Bitbucket Pipelines

`scripts/threatline-ci-report.mjs` is one file, Node 18 or later, no dependencies. Copy it into your repository (or
fetch it at a pinned commit), add `THREATLINE_URL` and `THREATLINE_TOKEN` as **secured** repository variables, and run
it after the tests:

```yaml
pipelines:
  default:
    - step:
        name: Test
        image: node:22
        script:
          - npm ci
          - npx vitest run --reporter=junit --outputFile=test-results/junit.xml
        after-script:
          # Runs even when the tests fail, so failures are reported too. Its exit code is ignored (see below).
          - node scripts/threatline-ci-report.mjs --junit "test-results/**/*.xml"
```

It reads `BITBUCKET_COMMIT`, `BITBUCKET_REPO_FULL_NAME`, `BITBUCKET_BUILD_NUMBER` (the evidence link is the pipeline
result page), `BITBUCKET_CLONE_DIR` and `BITBUCKET_BRANCH` (for the work item key). Flags: `--junit <glob>`
(repeatable), `--issue-key PAY-7` (repeatable; otherwise from the branch), `--url`, `--commit`, `--repo`, `--run-url`.
The token is read only from `THREATLINE_TOKEN`, never from a flag. Exit code 0 when reported (or when Threatline was
busy), 1 on a configuration error or a refused report.

**Bitbucket ignores an `after-script`'s exit code.** In the example above, a refused report (a revoked token, a work item
the token's project list does not include, a report over 256 KB) still leaves the step green: the only sign is the
script's output in the step log, and the requirements stay unverified. To make a refused report fail the build, run the
script in `script` instead, after tests that are allowed to fail, and keep the tests' own result:

```yaml
pipelines:
  default:
    - step:
        name: Test
        image: node:22
        script:
          - npm ci
          - |
            status=0
            npx vitest run --reporter=junit --outputFile=test-results/junit.xml || status=$?
            # Failures are reported too; a refused report fails the step.
            node scripts/threatline-ci-report.mjs --junit "test-results/**/*.xml" || exit 1
            exit $status
```

Any other CI can run the same script with `THREATLINE_URL`, `THREATLINE_TOKEN`, `--commit`, `--repo`, `--run-url` and
`--issue-key`, or post the request below itself.

## The request

`POST <web trigger URL>` with `Authorization: Bearer <CI token>` and a JSON body of at most 256 KB:

```json
{
  "issueKey": "PAY-7",
  "repo": "acme/payments",
  "commitSha": "4f1c…(40 lowercase hex)",
  "runUrl": "https://github.com/acme/payments/actions/runs/42",
  "results": [
    { "name": "PAY-101 Verify webhook signatures [req_1a2b3c4d5e6f7a8b] > rejects a bad signature", "status": "passed" },
    { "name": "tests.test_webhooks test_req_0000ffff0000ffff_rejects_replay", "status": "failed" }
  ]
}
```

`status` is `passed`, `failed` or `skipped`; at most 5,000 results and 200 distinct requirement ids per report. Unknown
fields are refused. The script and the action send only the tests whose names carry a requirement id, and never drop a
result to make a report fit: a report over 256 KB fails instead.

**The answer is one of a fixed set** (Runs on Atlassian): the web trigger is `static`, so Threatline can only answer
with an output declared in `apps/core/manifest.yml` and never sends work-item or requirement data back out. What CI
verified, per requirement, is in the work item's Threatline panel (Requirements: "CI run" evidence with the run link,
repository and commit) and in the risk ledger (`requirement.verified` with `viaCi: true`). The action and the script
print their own per-requirement summary from the JUnit results they sent.

| Output | HTTP | When |
| --- | --- | --- |
| `recorded-pass` / `recorded-warn` / `recorded-block` | 200 | Processed. The body's `verdict` is what the Done gate now sees for the work item. |
| `bad-request` | 400 | Not JSON, or not the format above. |
| `unauthorized` | 401 | Missing, malformed, wrong or revoked token. |
| `forbidden` | 403 | The token is limited to other projects, or Threatline is not on for the work item's project. |
| `not-found` | 404 | The work item does not exist. |
| `method` / `too-large` | 405 / 413 | Not a POST / body over 256 KB. |
| `rate-limited` | 429 | More than 120 reports in a clock hour for this token. |
| `unavailable` | 503 | Threatline could not read or write its storage, or could not record a requirement; nothing unrecorded was verified. Retry. |

Per requirement, Threatline verifies one only when at least one of its tests passed and none failed on that run, it is
Open or In progress, its threat is in the latest review, and it belongs to the named work item (or is its sub-task).
A failure never un-verifies a requirement verified earlier; reopen it in the panel if it is a regression. An accepted
risk or Not applicable is never changed by CI.

## Security model

- **Who can verify.** Only a holder of a CI token an admin created. The token is 256 random bits; Threatline stores
  only its SHA-256 (Forge secret storage), compares in constant time, and a token works only while it is both listed
  and its hash is stored, so a half-finished create or revoke fails closed. Nothing about the token is logged, stored
  in the ledger, or returned. Tokens can be limited to project keys, and each is rate-limited (120 reports an hour,
  taken atomically from the same SQL counter as review re-runs).
- **What it can do.** Move an Open or In progress requirement of the named work item, in a Threatline-enabled project,
  to Verified. That is all: it cannot approve, reject or request acceptances, dismiss threats, mark anything Not
  applicable, override the gate or touch another work item's requirements. The status change goes through the same
  `setRequirementStatus` as the panel, which writes the ledger entry before it saves (`requirement.verified`, actor
  `ci:<token id>`, payload `viaCi: true`, the token id, commit and repository); if the ledger is unavailable nothing
  changes, and if the save then fails a `requirement.status_change_failed` entry says so. The panel and the MCP action
  cannot give `ci` evidence.
- **What it proves.** That tests named for the requirement passed on that commit in that run, and nothing more: the
  test author decides what the test checks. The evidence links to the run and names the commit, so a reviewer can read
  the test and reopen the requirement in the panel. CI runs that execute pull request code with the token (for example
  `pull_request` workflows in the same repository) let the pull request's author influence the report, as they could
  influence the tests themselves; keep the token to trusted branches and workflows if that matters to you.
- **No new permission.** The web trigger needs no OAuth scope; the app reads the work item and writes its own storage
  as before. The gate still fails closed: a report that does not get through verifies nothing, so Done stays blocked.
