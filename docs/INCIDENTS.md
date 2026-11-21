# Incidents reopen reviews

A review reads recent incidents on its work item's components as context. A review that finished before an incident
happened would never hear of it. So when an incident appears, Threatline re-reviews the open work it touches.

## What happens

1. **An incident appears.** In an enabled project, someone creates a work item that is an incident, adds the incident
   label to one, or changes its work type to the incident type. By default a work item is an incident when it has the
   label `incident` or its work type is `Incident`. The issue trigger (`apps/core/src/triggers/on-issue-change.ts`)
   queues one `incident` job.
2. **The fan-out** (`apps/core/src/services/incident-reopen.ts`) reads the incident from Jira again and checks the
   rule. It needs components or links, a creation date in the last 90 days (reviews read only incidents that recent),
   and a person to scope the re-reviews to (whoever raised it). It then searches the incident's project for open work
   (`statusCategory != Done`) on the same components or linked to it, newest first, at most 100 results. It keeps the
   reviewed work types (Epic and Story by default) that already have a review, are not incidents themselves and have
   not been reopened for this incident before, up to the cap (25 by default).
3. **Ledger first, then the queue.** A `review.reopened_by_incident` entry records the incident key, its components,
   the work items queued and anything held back (`heldForBudget`, `rateLimited`, `capped`). Then each work item gets a
   `gather` job with reason `incident`. In Rovo agent mode the `threatline-review` label is also added, so the
   Automation rule runs the agent.
4. **The re-review** is an ordinary review. The gatherer reads the incident as untrusted text, fenced and scanned for
   injection like every other fact. A new revision is created only when the context really changed, which means the
   incident is new to that work item. The revision records its cause (review stage `reopened_by_incident`).
5. **The panel says why.** The Threats tab and the History tab show, for example: "Re-reviewed because PAY-9
   (incident) hit component Payments API on 2026-11-21." A viewer who cannot open the incident sees "an incident you
   cannot open" instead of its key.
6. **A comment on the incident** (optional, on by default) lists the work items being re-reviewed in plain text. It
   uses keys and component names only. The incident's own text is never copied into a comment.

## Bounds

- **Cap:** at most `maxItems` (1 to 50, default 25) work items per incident, newest first, from one bounded search.
- **Dedupe:** each work item is claimed once per incident (atomic KVS swap). A redelivered or concurrent event (a
  create and a label edit together) does not queue it again. Fan-outs for one incident run one at a time (Forge
  concurrency key). A failed queue push releases its claims, so the retry queues them.
- **Budget:** re-reviews count towards the monthly review budget. When reviews are paused (the budget is spent, or
  the site is out of Rovo credits), nothing is queued and the admin is told through the ops alert. When only part of
  the batch fits, the rest is held back and the alert says so. If the budget runs out between the fan-out and the
  re-review, the re-review does not start, and the existing review is not replaced by a paused one. It shows as out
  of date, so the gate still blocks.
- **Storms:** a work item can be re-run by incidents at most 10 times an hour (the per-item re-run limit).
- **No loops:** only people's edits reach the trigger (`ignoreSelf`). The app's comment, its labels and the demo
  seeder never start a fan-out, and a re-review never queues one.

## Settings

Go to **Threatline admin → Incidents** to turn this on or off, set the incident labels and work types, set the cap and
turn the comment on or off. These settings are saved in the site policy as `incidents`. Sites saved before this
setting existed have no `incidents` field. They still parse, and they read the defaults (`DEFAULT_INCIDENT_POLICY`).
The same rule decides which incidents every review reads as context. A changed rule can therefore change a work
item's context, and its review shows as out of date until it is re-run.

## Demo

1. Load the demo data (Threatline admin → Demo data) and wait for the stories to be reviewed. The seeder's two
   incidents are created by the app, so they do not start a fan-out.
2. Create a work item in the demo project with the label `incident` on the `support-agent` component (or of work type
   Incident), for example "Agent read back another customer's refund status".
3. Within a few minutes, both stories get a new revision. Their panels say "Re-reviewed because PAY-… (incident) hit
   component support-agent on …". The incident has a comment listing them, and the ledger has a
   `review.reopened_by_incident` entry.

Locally, run `pnpm --filter @threatline/core-ui dev` and open `?state=reopened`.
