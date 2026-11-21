# Threatline judge guide

Threatline makes security review part of "Done": every Jira work item gets a cited STRIDE threat model, the threats that
matter become requirements, and the work item cannot move to Done (nor its pull request merge) until each requirement
is verified or its risk is accepted by someone allowed to accept it.

## Install

| App | Install link | Needs |
| --- | --- | --- |
| Threatline for Jira (with Confluence) | [Install Threatline for Jira](https://developer.atlassian.com/console/install/13898a7c-6897-48d3-a512-079d9f9f5f00?signature=AYABeCcfIQJqGrR0SUgfCmoTNmEAAAADAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NzA5NTg3ODM1MjQzOmtleS83MDVlZDY3MC1mNTdjLTQxYjUtOWY5Yi1lM2YyZGNjMTQ2ZTcAuAECAQB4CxqLTo9l4lqXuFjNim1xJM%2Bp%2F3TVP9xHS2BrU5DRRucB1BD8mEv4t3Ljf3OukSd5eQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDEh%2BKItDcqUwro%2BHrQIBEIA7MA0KHRf%2BF3YuTEAMovFxVALBMAXOWvXwcePSrlXd8eWbO0Gu4PlzXePH9QGutTzgsBB7obWKVcKw55kAB2F3cy1rbXMAS2Fybjphd3M6a21zOmV1LXdlc3QtMTo3MDk1ODc4MzUyNDM6a2V5LzQ2MzBjZTZiLTAwYzMtNGRlMi04NzdiLTYyN2UyMDYwZTVjYwC4AQICAHi9bVMAkme4qVQX1fQHo6ePw3H40A7cGfz7yrmSfBWMXgHlW5ynSsuhZ7zbqiK2sh%2B2AAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMkPcTbpchY2MsayhfAgEQgDuWokoIpYBa88xi5ggk1L1JkcZBleXY2Fhu75VlWDzfTq%2FPjQu2HTJqqUvWAGr3gQmwdhbGrdneGDgHcgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtZWFzdC0xOjcwOTU4NzgzNTI0MzprZXkvNmMxMjBiYTAtNGNkNS00OTg1LWI4MmUtNDBhMDQ5NTJjYzU3ALgBAgIAeDYASx0XCjkny4iLV6vz%2BKtEGSGT6kdt0QRpkn6D%2FlVEAbLrick3%2FS2k9TO8wl7jjBMAAAB%2BMHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwPyU3UXZLk3LyqQEcCARCAO56x65zN0k8TKW9hcCjB8AjClKyO30ptqnOAj2gX5CQsUchhHNyCLeBw5CSlVzbE5lnPkVzoFWWWPI9DAgAAAAAMAAAQAAAAAAAAAAAAAAAAAE5uz5LjAh1FnegGXQysekL%2F%2F%2F%2F%2FAAAAAQAAAAAAAAAAAAAAAQAAADJlU7brRNHeEAgdUVuQgPgaQWe2H582mtCI1iAJ%2FP3ZS3ti2WQm0S86s3LQVssf56LpbJ8u0XxBB32s7u970Pyt6So%3D&product=jira&product=confluence) | Any Jira Cloud site (Threatline Engine needs no Rovo); Confluence on the same site for published pages |
| Threatline for Bitbucket | [Install Threatline for Bitbucket](https://developer.atlassian.com/console/install/53a2efe5-9150-4e9a-b869-8bd2605d64e0?signature=AYABeMU6Rt2jeek7C5UOdWnYVhcAAAADAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NzA5NTg3ODM1MjQzOmtleS83MDVlZDY3MC1mNTdjLTQxYjUtOWY5Yi1lM2YyZGNjMTQ2ZTcAuAECAQB4CxqLTo9l4lqXuFjNim1xJM%2Bp%2F3TVP9xHS2BrU5DRRucB9X7SgA05cnObTkvhYN1xbQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDNEhzAe7TPWDBVqk6wIBEIA7keQSd6CapbYmtUGdkeKKsGD9awYJ3ooCpMpwMF2EDUNbpBp%2F9PeiHpLYzLpKRCnH1ToDtNvaJyOei0kAB2F3cy1rbXMAS2Fybjphd3M6a21zOmV1LXdlc3QtMTo3MDk1ODc4MzUyNDM6a2V5LzQ2MzBjZTZiLTAwYzMtNGRlMi04NzdiLTYyN2UyMDYwZTVjYwC4AQICAHi9bVMAkme4qVQX1fQHo6ePw3H40A7cGfz7yrmSfBWMXgEaeJ%2BkdCobmSDv47DLtIySAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMGEExVBpjK5bbUYmTAgEQgDvy5cWJv19sweBbrSFr5C3xdwywv%2BBv20pRtihL1aMr7o8uQnVvR9vasue1xGfDidyWyh8RzUzmiGXFBQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtZWFzdC0xOjcwOTU4NzgzNTI0MzprZXkvNmMxMjBiYTAtNGNkNS00OTg1LWI4MmUtNDBhMDQ5NTJjYzU3ALgBAgIAeDYASx0XCjkny4iLV6vz%2BKtEGSGT6kdt0QRpkn6D%2FlVEAWqyfoA4bYp55SbOGUdCdOkAAAB%2BMHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwmXimEV%2FsYgm0GihwCARCAO2yT52i7N%2B%2BDNBN%2F2F87pJutoitrvTBVazhVeMuRbv%2BmP8xV9sDbTccsGcHKl%2BfdohjSFjjtL%2BQGx983AgAAAAAMAAAQAAAAAAAAAAAAAAAAANo1IMueG73KsfmrDTjuUgD%2F%2F%2F%2F%2FAAAAAQAAAAAAAAAAAAAAAQAAADJ0ZrDuRm0Q%2Biua58qqR3NYv5pw6Y4tZl2HqZtAX21FXdWDPb0BBfCK40FDFpZmG9vKBDYJl3oHZ3or2flppy5yAWs%3D&product=bitbucket) | A Bitbucket Cloud workspace; Premium to make the check *required* (otherwise it warns) |

Install the Jira app into Jira and Confluence. To use Threatline's MCP tools from a coding agent (optional), a site or
org admin turns them on in **Atlassian Administration → Apps → Sites → your site → Connected apps → Threatline → View
app details → Tools** (off by default; see [MCP.md](MCP.md)).

**Tested from scratch on 2026-11-20:** a brand-new free Jira + Confluence site, the install link above, the wizard,
one-click gate, demo data, and a story reviewed by Threatline Engine in about two minutes (once each work item's
model calls stopped queuing behind other reviews, PR #20), with Done blocked until
its requirements were handled. No Rovo, Automation rule or other setup was needed.

## The 2-minute path

1. **Open the admin page**: Jira settings → Apps → **Threatline**. The first-run wizard asks for a project, the transition
   to guard (for example Done) and the security champion group. Save.
2. **Add the gate**: click **Add the gate for me** (right after saving the wizard, or on the setup checklist).
   Threatline adds **Threatline security gate** to the transition you chose, in team-managed and company-managed
   projects alike. (Jira's team-managed workflow editor does not list app rules, so this is the way there; in a
   company-managed project you can also add it yourself under the transition's rules, Marketplace rules.)
3. **Load the demo data**: admin page → **Demo data** → enter the project and a Confluence space → **Load demo data**.
   It creates an epic "Add AI support agent" with stories (order lookup, refunds), two incidents, and a design page
   with one poisoned paragraph that tells the AI to approve the change.
4. **Nothing to set up for reviews.** Threatline Engine (the default; Threatline admin → **Review mode**) reviews every new
   story or epic itself on Atlassian-hosted Claude models. It takes about two to four minutes: a quarantined injection check, three
   independent analyses on the strongest model, then a verifier. To start one by hand: the work item → Threatline panel →
   **Run review**. (Prefer your site's Rovo agent? Choose **Rovo agent review** and follow "Rovo agent mode" below.)
5. **Open the epic "Add AI support agent"**. If the Threatline panel is not on it, add it once from the apps button
   under the title (**Threatline security review**), then in the panel's **⋯** menu choose **Show for all work items**. Loading the demo queues its review; within about two to four minutes the Threatline panel shows:
   - the risk score and why Done is blocked;
   - threats in plain language first, each with the quote it rests on and a link to its source;
   - a banner naming the design page as containing instructions aimed at the AI: they were treated as data, and the
     threats resting on that page wait for a security champion instead of being trusted;
   - "What if…" to see the score if the feature were public or handled payment data.
6. **Try to move it to Done.** The gate blocks with the open requirements listed and a link back to the panel.
7. **Fix or accept**: on **Requirements**, create the sub-tasks, mark one *Verified* with a PR link as evidence, and
   **Accept risk** on another (a reason, controls and an expiry; a security champion approves it on **Acceptances**).
   Move the work item to Done: it passes.
8. **Merge**: on **Requirements → Merge attestation**, enter the repository and head commit, copy the attestation into
   the pull request description. The Bitbucket check passes; change one character and it fails.
9. **Audit**: admin page → **Risk ledger** → **Verify the ledger**, and download an inclusion proof; check it offline
   with `node scripts/verify-ledger-proof.mjs proof.json`.

Also worth a look: **Apps → Threatline security posture** (and the dashboard gadget), the threat model published to
Confluence (**History → Publish to Confluence**), and asking the **Threatline** agent in Rovo chat "What do I need to fix
before this can merge?".

## Rovo agent mode (optional)

Create an Automation rule in the project: *Work item created* (condition: type is Story or Epic) → **Use agent:
Threatline** with **Let this agent take actions** on, three times. Connect Automation to Rovo when asked. Then, under
**Review mode → Who can submit AI review runs**, choose **Only these accounts** and click **Use** next to the account
that ran the rule.

## If a review never arrives

- **Rovo is not on the site** (for example a free developer site): Threatline Engine, the default, does not need
  Rovo. Rovo is only needed for **Rovo agent review** mode and for the Threatline agent in Rovo chat. If the site was
  switched to Rovo agent review, set Threatline admin → **Review mode** back to **Threatline Engine** → Save, then click
  **Run review on this work item** in the panel.
- **Reviews must not use AI at all**: Threatline admin → **Review mode** → **Rule-based checks only** → Save. Every
  review then completes at once from Threatline's built-in checks, the panel says "Rule-based review", and the Done
  gate, requirements, acceptances and merge attestations work the same.
- **Automation audit log says "The agent selected for this rule has been deactivated"**: an app update replaced the
  Threatline agent. Open the rule, and in each **Use agent** step choose **⋯ → Switch agent → Threatline**, then save.
- **Reviews time out and the risk ledger shows `review.sample_rejected`**: the Automation rule runs as an account that
  is not a review author. Add it under Threatline admin → **Review mode → Who can submit AI review runs**.
- **The Threatline panel is not on a work item**: add it once from the apps button under the work item title
  (**Threatline security review**), then **⋯ → Show for all work items** so it is on every work item.
- **"Threatline could not reach Jira, or is still finishing its install"** right after installing: a new install sets
  up its database in the first minute. Try again a minute later.
- **Load demo data says the Confluence space was not found**: create a space (any name) and enter its key.
- **Run review on this work item does nothing for a long time** (Rovo agent mode only): the re-run needs a second Automation rule with the
  trigger *Field value changed → Labels → Value added*, condition `{{issue.labels}}` contains `threatline-review`, and the
  same three **Use agent: Threatline** steps.

## Without a Jira site

Everything above runs against fixture data in a local preview, no Atlassian site needed:

```bash
pnpm install
pnpm --filter @threatline/core-ui dev --port 5179   # then open http://localhost:5179/?state=ready (or ?view=admin, ?view=posture)
pnpm test                                        # 1,250+ tests, including accessibility checks
pnpm threatline sign-demo                           # sign an attestation, then show that one changed character fails
pnpm threatline eval --llm recorded --subset 30     # replay the recorded eval offline
```

Screenshots of every surface are in [screenshots/](screenshots/README.md); the design in [ARCHITECTURE.md](ARCHITECTURE.md);
Threatline's own threat model in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).
