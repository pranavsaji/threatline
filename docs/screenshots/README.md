# Marketplace listing screenshots

Captured from the mock-bridge previews (fixture data, no live site) with `pnpm exec tsx scripts/listing-screenshots.ts`
while both preview servers run (see the script header). Re-run it after UI changes; it overwrites these files.

## Threatline for Jira (with Confluence)

1. `jira-1-issue-panel.png` — the issue panel: risk score, why Done and the merge are blocked, threats in plain language first.
2. `jira-2-threat-evidence.png` — a threat opened (dark theme): the cited quote and its source, and "Explain like I'm new to security".
3. `jira-3-accept-risk.png` — accepting a risk inline: reason, compensating controls, expiry, and who must approve.
4. `jira-4-posture-dashboard.png` — the security posture dashboard: open Critical/High, where they are, the 30-day trend.
5. `jira-5-admin-policy.png` — the admin page (dark theme): setup checklist, projects, severity policy, roles, budgets.

## Threatline for Bitbucket

1. `bitbucket-1-repo-settings.png` — repository settings: trusted keys, extra sensitive paths, block or warn, diff-score threshold.
2. `bitbucket-2-attestation-valid.png` — a pasted attestation verified in the browser against the repository's keys.
3. `bitbucket-3-attestation-tampered.png` — the same attestation with one character changed: rejected as an invalid signature.
4. `bitbucket-4-jira-attestation.png` — where the attestation comes from: the Jira panel issues it for one repository and commit.
5. `bitbucket-5-repo-settings-dark.png` — repository settings in the dark theme.

Not here yet: the merge check on a real pull request (Bitbucket's own UI), which needs a capture on the live workspace.

## Marketplace

- `marketplace-bitbucket-submitted.jpg` — Threatline for Bitbucket 2.10.0 submitted as a free informational listing,
  pending approval (2026-11-24). See `docs/MARKETPLACE.md`.
