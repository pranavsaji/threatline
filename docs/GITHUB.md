# Threatline merge gate for GitHub

The Threatline GitHub Action does on GitHub what Threatline for Bitbucket's merge check does on Bitbucket: a pull request
that touches security-sensitive files merges only with a valid Threatline attestation for its head commit. Changes that
touch no sensitive paths pass freely. The decision code is shared with Bitbucket (`packages/core/src/merge-gate.ts`),
so both platforms give the same answer for the same change.

## Set it up (5 minutes)

1. In Jira, open **Threatline admin → Signing keys** and copy the active public key. It is public: no secret is needed.
2. Add `.github/workflows/threatline.yml` to the repository:

   ```yaml
   name: Threatline
   on:
     # pull_request_target runs this file from the base branch, so a pull request cannot change its own gate.
     # Safe here: the action never checks out or runs pull request code; it only reads the pull request through the API.
     pull_request_target:
       types: [opened, edited, synchronize, reopened]
   permissions:
     contents: read
     pull-requests: read
   jobs:
     merge-gate:
       runs-on: ubuntu-latest
       steps:
         # Pin to a full commit SHA from https://github.com/pranavsaji/threatline/commits/main
         - uses: pranavsaji/threatline/apps/github-action@main
           with:
             public-keys: |
               PASTE-THE-PUBLIC-KEY-HERE
   ```

3. In **Settings → Branches** (or Rules), require the **Threatline / merge-gate** status check on your main branch.

`edited` is in the trigger list so that pasting an attestation into the description re-runs the check.

**Why `pull_request_target`.** On `pull_request`, GitHub runs the workflow file from the pull request itself, so its
author could swap in their own key, switch to warn mode, or replace the step. `pull_request_target` runs the base
branch's workflow. The action warns if it runs on `pull_request`. Do not add a checkout of the pull request's code to
this job. For organisation-wide enforcement, add the workflow as a required workflow in an organisation ruleset.

Changes to the gate's own configuration always count as sensitive, on GitHub and Bitbucket alike: `.github/workflows/**`,
`.github/actions/**`, `bitbucket-pipelines.yml`, `.threatline/**` and `.redline/**` (the policy file's name before the
rename). Editing, deleting or shadowing `policy.yml` therefore needs an attestation like any other security change; no
setting or policy file can remove these paths (`GATE_CONFIG_PATHS` in `packages/core/src/merge-gate.ts`).

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `public-keys` | none; required unless `merge-gate: false` | Threatline public keys, one per line: `<key>` or `<key> until=<ISO date>`. During a key rotation, list both (see below). With the merge gate on and no key, the step fails with `outcome=config_error`. |
| `sensitive-paths` | none | Extra path globs, one per line, on top of Threatline's defaults. |
| `diff-score-threshold` | `40` | A change scoring at or above this needs an attestation even outside sensitive paths. |
| `mode` | `block` | `warn` reports failures but passes, until `warn-until`. |
| `warn-until` | none | Required in warn mode: an ISO date at most 14 days away. After it, the check blocks again. |
| `github-token` | `${{ github.token }}` | Token the action reads the pull request, its files and the base branch's policy file with. The workflow's own token with `contents: read` and `pull-requests: read` is enough. |
| `merge-gate` | `true` | `false` skips the gate and only sends the CI verification report (`threatline-url`, `threatline-token`, `junit`; see [CI_VERIFICATION.md](CI_VERIFICATION.md)). |

**Warn mode's 14-day limit is checked against each run, not against when warn mode was switched on.** The action has no
memory between runs: it only sees today's `warn-until`, so someone who can edit the workflow on the base branch can keep
moving the date forward and stay in warn mode indefinitely. The limit stops a forgotten warn mode, not a determined
admin. Branch protection on the workflow file (and an organisation ruleset, below) is what controls who can do that.
Threatline for Bitbucket sets the date itself when an admin saves warn mode and keeps it while warn mode runs, so there
saving the settings again cannot extend it (warn mode can be switched on again only after it has ended).

The base branch's `.threatline/policy.yml` can add sensitive paths and lower the threshold. It can never weaken them, and
an unreadable policy file makes every changed file count as sensitive.

## Rotating the signing key

**Threatline admin → Signing keys → Rotate key** makes a new key active; Threatline keeps publishing the old one for
7 days so attestations signed just before the rotation still verify. A merge gate, though, trusts every key pasted into
it until it is removed. So:

1. Add the new public key to every repository (the `public-keys` input here, Repository settings → Threatline on
   Bitbucket), next to the old one.
2. After the 7-day overlap, remove the old key, or mark when it retires so you can do both edits at once:

   ```yaml
   public-keys: |
     NEW-PUBLIC-KEY
     OLD-PUBLIC-KEY until=2026-12-08
   ```

   From that time (a date alone means 00:00 UTC; a time without a zone is UTC) attestations signed by the old key fail
   with "signed with key …, which this repository retired at …". Bitbucket's settings page takes the same syntax.

Independently of keys, the gate refuses any attestation whose lifetime (`exp - iat`) is longer than Threatline ever issues
(168 hours, the largest `attestationTtlHours`, plus 5 minutes of clock skew).

## How a developer gets through the gate

1. Finish the work item's security requirements in Jira (or get a risk acceptance).
2. In the Threatline panel, use **Merge attestation** with the repository as `owner/repository` and the pull request's
   head commit. An IDE agent can call `get-merge-attestation` over MCP instead.
3. Paste the attestation into the pull request description. Put the work item key in the title or branch name.

Every work item the title or branch names needs its own valid attestation for the head commit (one passing item cannot
carry another). A key is a project key, `-` and a number, not touching another letter or digit: `PAY-7`, `MY_PROJ-12`,
and also `PAY-7_fix` or `fix_PAY-7` (an underscore separates). A lowercase key such as `pay-7-fix` counts only when the
title or branch also names an uppercase key of the same project (`PAY-6 …` with branch `pay-7-fix` names PAY-6 and
PAY-7); on its own, lowercase text like `utf-8` or `sha-256` is never treated as a work item. An algorithm or encoding
name and a full CVE id are never work items either: `PAY-7 switch to SHA-256` and `Fix CVE-2025-1234 in PAY-7` name
only PAY-7 (`SHA-256`, `AES-128`, `UTF-8`, `RSA-2048`, `X-509` and the like, `STANDARD_ID` in
`packages/shared/src/ci.ts`). Nothing else is excluded, because RFC, ISO and CWE are common real project keys:
`RFC-1234` always counts, and so do `SHA-12` and `CVE-2025` on its own. The attestation must be for exactly the head commit (all
40 characters).

The check fails, saying exactly why, when the attestation is missing, for another commit or repository, for a
different work item than the one the pull request names, expired, or not signed by a listed key. It also fails closed
when GitHub cannot be read, when a text diff is too large for GitHub to return, or when the pull request changes more
than 3,000 files.
