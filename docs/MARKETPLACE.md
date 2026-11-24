# Marketplace listing kit

Everything needed to list **Threatline** (the Jira + Confluence app) on the Marketplace. A Free listing of this app is
not possible (see [Paid listing (February 2027)](#paid-listing-february-2027)); it is planned as Paid via Atlassian,
priced as in [PRICING.md](PRICING.md). The Codegeist
bonus "Best Marketplace published app" counts an app that is *submitted for listing*: keep the review ticket link (or a
screenshot of the "Submitted" status) for the Devpost form.

## Before you submit: decisions and blockers

| Item | Why it matters | Status |
|---|---|---|
| **Developer-side AI spend ceiling** | Forge LLM usage is billed to the developer for every public install. Site admins set their own budget on the admin page; the Forge variables `THREATLINE_MAX_REVIEWS_PER_MONTH`, `THREATLINE_MAX_TOKENS_IN_PER_REVIEW` and `THREATLINE_MAX_TOKENS_OUT_PER_REVIEW` cap it per site, and only the developer can set them (`forge variables set -e production THREATLINE_MAX_REVIEWS_PER_MONTH 5`). | Done (`kvs-config.ts`); production is set to 5 reviews per site per month and 400,000 input / 60,000 output tokens per review (2026-11-24) |
| Paid via Atlassian licensing | The inactive-license behaviour is in the code. `app.licensing.enabled` stays off until February, so production can still be installed by link. The patch, the runbook and what existing installs see are in `docs/LICENSING.md`. | Ready; flip in February |
| Install links stop for new installs once the listing is approved | Judges would install from Marketplace instead of `docs/JUDGE_GUIDE.md`. While the review is pending, the links keep working. Update the judge guide on approval. | Plan for it |
| Developer Space publish is irreversible | It creates the Marketplace partner profile. | Your call |
| Partner Verification (one-time) | Business or individual details, ID for the primary contact, Stripe Identity selfie, Partner Security Questionnaire, within **14 days** or the ticket is auto-rejected. | You only |
| Review time | Atlassian quotes 1 week to 15 business days; 2026 reports say 2–3+ weeks. Submit well before Dec 22. | — |

## Steps (yours to click)

1. `forge deploy -e production` (already done for the current version) and confirm the production version is the one to list.
2. developer.atlassian.com → Developer Space "Threatline" → **Make public on Marketplace** → accept the partner agreement.
3. marketplace.atlassian.com/manage/apps/create → choose the Forge app `13898a7c-6897-48d3-a512-079d9f9f5f00` →
   paste the listing below → **Paid via Atlassian** (Free is refused for this manifest) → set the price → submit.
4. Complete Partner Verification from the ticket within 14 days.
5. Save the ECOHELP ticket link (or screenshot "Submitted") for Devpost.

The Bitbucket app (`53a2efe5-…`) was submitted on 2026-11-24 as a free informational listing (see below).

## Paid listing (February 2027)

The plan is to list Threatline for Jira as **Paid via Atlassian** after Codegeist judging, in February 2027. Until then,
the install links in `docs/JUDGE_GUIDE.md` stay free. The cost per review, the cap mechanics and the recommended price
are in [PRICING.md](PRICING.md).

**Why not Free: the multi-product finding.** The manifest declares `compatibility.jira.required: true` and
`compatibility.confluence.required: false`, so this is a multi-product app. Marketplace refused a Free listing of it
with:

> Required products can only be specified for PAID_VIA_ATLASSIAN apps

To list it Free, the app would have to drop the Confluence compatibility entry. That would also drop the Confluence
features: design-page reading and published threat-model pages. Paid via Atlassian keeps the manifest as it is. The
payment model is hard to change after listing, so choose it once.

**Threatline for Bitbucket: submitted.** It went in on 2026-11-24 as a **free informational listing**:

- Bitbucket Forge apps are not installed from the Marketplace. The listing says the app isn't directly installable and
  links to the install link.
- Version 2.10.0, build 201000000, Cloud, "First Marketplace release of the Threatline security merge check".
- Status: **pending approval** (screenshot `docs/screenshots/marketplace-bitbucket-submitted.jpg`).
- Terms: the **Bonterms Standard End User Agreement**, with `docs/TERMS.md` as additional terms.
- License type: "Commercial - no charge". Personal data: no.
- Keep the ECOHELP ticket link, or this screenshot, for the Devpost form.

**Before the paid listing goes live (repo work):**

- **Licensing.** Add `app.licensing.enabled: true` to `apps/core/manifest.yml`. Engine reviews should run only for
  licensed or evaluation installs. See the Forge licensing overview.
- **Token ceilings.** Done (2026-11-24, 5.12.0). Production sets `THREATLINE_MAX_REVIEWS_PER_MONTH=5`,
  `THREATLINE_MAX_TOKENS_IN_PER_REVIEW=400000` and `THREATLINE_MAX_TOKENS_OUT_PER_REVIEW=60000`, so a site admin
  cannot raise the per-review token caps and the $3.50 per-review ceiling in `PRICING.md` holds.
- **Real token use.** Measure it from production `llm.call` logs (10 to 20 reviews) and update the numbers in
  `PRICING.md`. The repo's recordings have no usage fields, so its cost per review is an estimate.

**Owner-only steps (nobody else can do these):**

1. **Payment method.** Add a payment method on the Developer Space. Forge usage, including every Forge LLM call made
   by any install, is billed to it monthly.
2. **Partner Verification.** Complete it from the ticket within **14 days**, or the submission is auto-rejected. You
   need business or individual details, government ID for the primary contact, a Stripe Identity selfie, a tax ID or
   registration number, and the Partner Security Questionnaire.
   - Before starting, ask Atlassian (ECOHELP) to confirm that an individual without a company can be verified.
   - Set up tax and payout details too. Payouts go by EFT in USD to an account in your name, once at least $500 is
     owed.
3. **Price.** Choose it in the Marketplace pricing tool when you create the paid version. `PRICING.md` recommends $20 a
   month flat for 1-10 users, then $2.50, $2.00, $1.50 and $1.00 per user for the tiers above. That is a
   recommendation, not a decision.
4. **Legal documents.** Attach an end-user agreement (EULA) and, because Threatline stores personal data (Atlassian
   account IDs), a Data Processing Agreement. Missing legal documents block a paid listing in review.
5. **Vulnerability reporting.** Turn on GitHub private vulnerability reporting for the repository (Settings → Code
   security). It was off on 2026-11-23, and `docs/SUPPORT.md` points security reports there.

## Listing content

**Name:** Threatline: Security Review Gate

**Tagline (≤ 80 chars):** AI threat models that gate Jira Done and merge, with cited evidence.

**Summary (≤ 250 chars):** Threatline reviews every story for security threats, cites the exact sentence each threat rests
on, turns them into testable requirements, and blocks Done and merge until each is verified or its risk is accepted.

**Highlights**
1. *Threat models with receipts.* Every threat quotes the design text it rests on, with STRIDE, OWASP ASVS 5 and CWE
   references and a Given/When/Then requirement. Instructions hidden in pages are treated as data and flagged.
2. *A gate the AI cannot talk past.* The Done gate and the Bitbucket merge check are plain code reading signed
   verdicts. Requirements close only with evidence; exceptions need an expiring, approved risk acceptance.
3. *Sees what actually shipped.* From Teamwork Graph, Threatline lists linked pull requests and deployments and warns
   when a work item reached production with security requirements still open.

**Description:** use the "What it does" section of `README.md`, ending with the data handling paragraph below.

**Categories:** Security; Workflow; Project management. **Hosting:** Cloud (Forge, Runs on Atlassian eligible).

**Links:** privacy `docs/PRIVACY.md`, terms `docs/TERMS.md` (GitHub), support `docs/SUPPORT.md` (GitHub issues at
<https://github.com/pranavsaji/threatline/issues>), source <https://github.com/pranavsaji/threatline>.

**Screenshots:** `docs/screenshots/jira-1-issue-panel.png`, `jira-2-threat-evidence.png`, `jira-3-accept-risk.png`,
`jira-4-posture-dashboard.png`, `bitbucket-6-live-merge-check-fails.jpg`. Still to take: a Delivery check capture,
once the demo site shows a linked pull request and deployment (not in `docs/screenshots/` yet).

**Logo:** `docs/brand/icon-144.png` (144×144).

## Data handling (for the listing and the Privacy & Security tab)

- No egress: no `permissions.external` entry; everything runs on Atlassian (Forge functions, SQL, KVS, queues, LLMs).
- Stores: review records, threats, requirements, a signed append-only ledger, and Atlassian account IDs of the people
  who verify, accept or approve (personal data: **yes**, account IDs only).
- AI: Forge LLMs (Claude models hosted by Atlassian). Page and issue text is sent to the model only inside Atlassian.
- Teamwork Graph data (linked PRs and deployments) is read as the viewing user, shown to that user only, never stored
  and never sent to a model.

## Scope justifications

| Scope | Why |
|---|---|
| `read:jira-work` (impersonation) | Read the work item and linked items to review them; permission checks as the viewer. |
| `write:jira-work` | Create requirement sub-tasks, labels for re-runs, comments that summarise a review. |
| `read:jira-user` (impersonation) | Resolve the viewer's permissions (`mypermissions`) and Jira expressions. |
| `storage:app` | KVS for verdicts and keys. |
| `read:confluence-content.summary`, `read:page:confluence`, `read:space:confluence`, `read:confluence-content.permission` | Read the design pages a story links to, and check the viewer may see them. |
| `write:page:confluence` | Publish the threat-model page and ledger heads when a user asks. |
| `manage:jira-project` | Project-level setup from the admin page. |
| `manage:jira-configuration` (impersonation) | "Add the gate for me": adds the Done validator to a workflow, as the admin who clicks. |
| `read:graph:issue:jira`, `read:graph:pull-request:external`, `read:graph:deployment:external` | Delivery check: PRs and deployments linked to the work item, as the viewer. |
