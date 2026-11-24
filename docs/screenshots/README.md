# Marketplace listing screenshots

Captured from the mock-bridge previews (fixture data, no live site) with `pnpm exec tsx scripts/listing-screenshots.ts`
while both preview servers run (see the script header). Re-run it after UI changes; it overwrites these files. Pass
names to re-capture only some, for example `pnpm exec tsx scripts/listing-screenshots.ts jira-7 jira-8`.

## Threatline for Jira (with Confluence)

1. `jira-1-issue-panel.png` — the issue panel: risk score, the headline saying what stands between the work item and Done, threats in plain language first.
2. `jira-2-threat-evidence.png` — a threat opened (dark theme): the cited quote and its source, and "Explain like I'm new to security".
3. `jira-3-accept-risk.png` — accepting a risk inline: reason, compensating controls, expiry, and who must approve.
4. `jira-4-posture-dashboard.png` — the security posture dashboard: open Critical/High, where they are, the 30-day trend.
5. `jira-5-admin-policy.png` — the admin page (dark theme): setup checklist, projects, severity policy, roles, budgets.
6. `jira-6-live-injection-flagged.jpg` — live site, not from the script: threats from content that looked like instructions to the AI wait for a security champion.
7. `jira-7-status-label.png` — the context column (jira:issueContext) at about its width: "✕ Blocks Done · 2 open" and the top reason.
8. `jira-8-check-attestation.png` — "Check an attestation" under Requirements: a pasted merge attestation checks as Valid, with its commit and requirements.
9. `jira-9-check-attestation-tampered.png` — the same check (dark theme) after one character of the signature changed: "Signature invalid".
10. `jira-10-setup-use-group.png` — the admin setup checklist on a site without the champion group: one click uses a group the admin is already in.
11. `jira-11-live-status-label.jpg` — live site (threatline-demo, production), not from the script: the Security gate label in the
    right-hand column and the panel's headline on a story that blocks Done.

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
