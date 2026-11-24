# Support

Threatline (Threatline for Jira and Threatline for Bitbucket) is built and supported by one developer. This page
explains how to get help, how quickly to expect an answer, and how to report a security problem.

## Getting help

Open an issue at **<https://github.com/pranavsaji/threatline/issues>**. Use it for questions, bugs, install problems and
feature requests.

Issues are public. **Do not paste work item text, page content, threat models, attestations, tokens or anything else
from your site that you would not publish.** Describe the problem in general terms, and say in the issue if you need to
share something private. A private channel will be arranged.

## What to include

- Which app and version: Threatline for Jira, or Threatline for Bitbucket. The version is on the site's
  **Manage apps** page.
- Your site's cloud URL. Leave it out if you would rather not make it public, and say so.
- The review mode: Threatline Engine, Rovo agent, or rules only. It is on the Threatline admin page under **Review mode**.
- What you did, what you expected and what happened, with the time (and time zone) it happened.
- For a review that failed or stalled:
  - The work item key.
  - The review's revision number.
  - The stage the panel or the admin trace shows (injection check, run 1 to 3, gap check, verify).
  - The failure reason shown, for example `budget`, `timeout` or `upstream`.
- For the Done gate or the merge check: the verdict reason shown, and for Bitbucket the repository and commit hash.
- A screenshot with sensitive text blurred, if it helps.

Threatline logs record ids, timings and counts only, never work item text, page text or prompts. So the details above
are what make a problem traceable.

## Response times

Targets, not a contractual service level: Threatline is maintained by one person.

| What | First response | Fix or workaround |
| --- | --- | --- |
| Security vulnerability (see below) | 2 business days | Critical or High: aim for 14 days |
| Gate blocks or passes wrongly, reviews fail on every work item | 2 business days | Best effort, prioritised |
| Other bugs | 5 business days | Scheduled with the next release |
| Questions and feature requests | 5 business days | Feature requests are considered for the [roadmap](ROADMAP.md) |

Business days are Monday to Friday, excluding US public holidays. Expect slower replies during holidays and announced
absences; these are noted in the repository's README when they happen.

## Reporting a security vulnerability

**Do not open a public issue for a vulnerability.** Report it privately through GitHub:
<https://github.com/pranavsaji/threatline/security/advisories/new> ("Report a vulnerability" on the repository's
Security tab).

Include:

- The affected app and version.
- The impact.
- Steps to reproduce, or a proof of concept against your own site or the local harness (`pnpm e2e`).

Please do not test against sites you do not own, and give a reasonable time to fix before you disclose publicly.

Of particular interest:

- Ways to make the Done gate or the merge check pass without a valid verdict or attestation.
- Ways to read another site's or another user's data.
- Prompt injection that changes a verdict rather than being flagged.

How Threatline defends itself is in the [security review](SECURITY_REVIEW.md).

## Known limitations

- **AI review is assistance, not assurance.** Threat models are written by AI and can miss risks or include wrong ones
  (see the [terms](TERMS.md)). The gate is computed by code, but what it gates on starts from the model's findings.
- **Monthly review cap.** Each site has a monthly review cap, currently 10 reviews per site per month on Threatline
  Engine, set by the publisher. A site admin can lower it but not raise it above that.
  - Every new revision counts: the first review, a re-run, and a change brought in by an incident or a create.
  - At the cap, new reviews pause, and the gate blocks the affected work items until a security champion confirms.
    The cap resets on the 1st of each month (UTC).
  - Rules-only reviews do not count.
- **Review time.** A review takes a few minutes. It runs three model calls in parallel, then a gap check and a verifier.
  The panel shows progress while it runs.
- **Long pages are read in part.** Each linked page or work item is read up to about 12,000 characters (six parts of
  2,000). The whole review context is capped at about 200 KB. Content past those limits is not reviewed.
- **Only what the person who triggered the review can see.** Restricted pages and incidents under issue security that
  this person cannot open are left out of the review.
- **Suspected prompt injection changes the flow.** When text that looks like instructions to an AI is found, the gap
  check and the verifier do not run. The threats resting on that text wait for a security champion.
- **Rovo agent mode** uses your site's Rovo credits. Reviews pause if the site appears to be out of credits.
  Threatline Engine mode does not use Rovo credits.
- **Bitbucket merge check.** Making the check *required* needs Bitbucket Premium. On other plans it warns rather than
  blocks.
- **Preview platform features.** Some features rely on Atlassian features marked Preview: Rovo MCP, and Teamwork Graph
  for the Delivery check. They may change or be unavailable on some sites.
- **Cloud only.** Threatline runs on Atlassian Cloud (Forge). There is no Data Center version.

## Related

[Privacy](PRIVACY.md) · [Terms](TERMS.md) · [Threatline Engine](ENGINE.md) · [Marketplace listing](MARKETPLACE.md) ·
[Pricing](PRICING.md)
