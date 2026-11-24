# Licensing (Paid via Atlassian)

Threatline (the Jira + Confluence app, `apps/core`) is ready to be sold as a **Paid via Atlassian** Marketplace app.
The code that handles an inactive license is merged and does nothing until a license is reported. **Licensing itself is
not on yet.** `manifest.yml` has no `app.licensing` key, so the production environment can still be installed from the
developer console install link. The owner turns it on in February with the runbook below.

Source: [Listing Forge apps](https://developer.atlassian.com/platform/marketplace/listing-forge-apps/).

## How Threatline reads the license

`apps/core/src/services/license.ts` returns one of three states:

| State | When | Effect |
|---|---|---|
| `licensed` | Forge reports `context.license.active === true` | Everything works |
| `unlicensed` | Forge reports `context.license.active === false` | Reduced functionality (below) |
| `not_applicable` | No `context.license` (free or unlisted app, development or staging environment, licensing off) | Treated as licensed |

The state is worked out in this order:

1. **The license in the Forge context.** When Forge reports one, it always wins, and Threatline records it in KVS
   (`license:seen`) whenever it changes.
2. **The recorded license.** Atlassian documents `context.license` only for resolvers. The workflow validator, the
   queue consumer and the Rovo actions may get no license, so they use the last license a context reported. Resolvers
   always get the license when one exists, so a resolver that gets none clears the record. A development site tested
   with `--license inactive` and then reinstalled without it does not stay unlicensed.
3. **The Forge variable `THREATLINE_LICENSE_OVERRIDE`** (`active` or `inactive`). It is for testing in development, and
   it only counts when Forge reports no license, so it can never buy a license in production.
4. Otherwise `not_applicable`.

**Security:** an inactive license opens the Done gate, so nobody but Forge and the developer can set it. The state comes
only from the Forge invocation context (never a payload), from app storage that only Threatline writes, or from a Forge
variable that only the developer can set.

`composeCore(ctx)` builds `deps.license` from the context of each invocation. Resolvers pass `context.license` with
`licenseAuthoritative: true`, and Rovo actions, triggers, the consumer, the validator and scheduled jobs pass their
whole context through. Handlers call `await deps.license.state()` and `isLicensed(state)`. The result is computed once
for each invocation, and a KVS failure never fails the caller (an unreadable record is ignored).

## The policy when unlicensed

The refusal message is `LICENSE_INACTIVE_MESSAGE`, which starts "Threatline's license for this site is inactive". Each
refusal logs `license.refused` with a `where` field.

**No new AI work:**

| Path | Where | Behaviour |
|---|---|---|
| Rovo `start-review`, panel **Re-run review** | `panelRerun` (resolvers/panel.ts) | Refused with the message after the access check. Nothing is queued, labelled or counted |
| Admin **Load demo data** (queues reviews) | `adminSeed` (resolvers/admin.ts) | Refused with the message |
| Issue created/updated trigger | `onIssueChange` | No `gather` or `incident` job is queued. Verdict refreshes still are |
| Confluence page trigger | `onPageChange` | Nothing is queued |
| Queue consumer, a `gather` that would create a revision | `gather` (consumers/review-consumer.ts) | No review is created and no review is counted. The verdict is refreshed |
| Queue consumer, a Threatline Engine stage | `engineJob` (services/engine.ts) | No model call. The stage is traced as `engine_<stage>` failed, `license_inactive`. The sweeper later times out a review left waiting |
| Rovo `submit-threat-model` | actions/submit-threat-model.ts | `{ saved: false, error: 'license_inactive', message }` |

**Nothing is trapped:**

- **The Done gate** (`validators/validate-transition.ts`) lets every transition through and logs `license.gate_open`
  with the project key.
- **Merge attestations** for finished reviews are still issued, so the Bitbucket merge check and the GitHub Action still
  pass a verified commit. Nothing in that path checks the license.
- **Existing data stays readable:** the panel, posture, ledger, inbox, requirements, acceptances, suppressions, exports
  and CI verification all work as before.
- **Housekeeping keeps running:** migrations, review timeouts, acceptance and suppression expiry, retention purges and
  the ledger tree head.

**Banner:** `panel.get` and `admin.getPolicy` return `licenseInactive: true`, and the issue panel and the admin page
then show a warning banner (`ui/src/components/LicenseBanner.tsx`).

## Manifest patch (not applied)

Apply this in February, not before. Once it is deployed to production, production can no longer be installed by link.

```diff
 app:
   id: ari:cloud:ecosystem::app/13898a7c-6897-48d3-a512-079d9f9f5f00
+  licensing:
+    enabled: true
   runtime:
     name: nodejs22.x
@@ modules:
   trigger:
     - key: lifecycle
       function: lifecycleFn
       events: [ avi:forge:installed:app, avi:forge:upgraded:app ]
     - key: issue-events
       function: issueEventsFn
       events: [ avi:jira:created:issue, avi:jira:updated:issue ]
       filter:
         ignoreSelf: true
+        appIsLicensed: true
     - key: page-events
       function: pageEventsFn
       events: [ avi:confluence:updated:page ]
+      filter:
+        appIsLicensed: true
```

Why these triggers and not the others:

- `issue-events` and `page-events` start reviews. `appIsLicensed: true` has Forge skip them on an unlicensed site, so no
  invocation is spent. The code check in `onIssueChange` and `onPageChange` stays as a second line. The cost is that,
  while the site is unlicensed, edits no longer mark reviews out of date. After the site renews, the next edit or a
  re-run brings the review up to date.
- `lifecycle` stays unfiltered. It runs the SQL migrations on install and upgrade, which readable data depends on.
- The scheduled triggers (`sweeper`, `hourly`, `daily`) stay unfiltered:
  - `sweeper` runs migrations and times out waiting reviews.
  - `hourly` expires acceptances and suppression rules. Without it, an expired risk acceptance would stay in force.
  - `daily` purges data past retention and signs the ledger tree head.

  None of them calls a model.
- The queue consumer, the workflow validator, the web trigger and the Rovo actions are not triggers, so `appIsLicensed`
  does not apply to them. They use the code checks above.

## February runbook

The owner runs these steps. Agents must not deploy or change Forge state.

1. **Test on development first:**
   - `forge install --upgrade -e development --license inactive` on the development site (`--license` works only in
     non-production environments).
   - Open a work item's Threatline panel. The banner appears, and the resolver records `license:seen = unlicensed`.
   - **Re-run review** and Rovo `start-review` are refused with the message. A guarded transition goes through, and
     `forge logs -e development` shows `license.gate_open`. Editing a work item queues no review.
   - The panel, posture and ledger still load, and `get-merge-attestation` still issues for a finished review.
   - Repeat with `--license active`: the banner goes away and Re-run works. Also try `--license trial`, which should
     act like `active`.
   - Quicker toggling without reinstalling: `forge variables set -e development THREATLINE_LICENSE_OVERRIDE inactive`,
     then `forge deploy -e development`. It only applies while Forge reports no license. Unset it afterwards.
2. **Flip the manifest:**
   - Apply the patch above.
   - In `apps/core/test/actions/manifest.test.ts`, change "licensing is not enabled yet" to expect `enabled` to be
     `true`.
   - Run `pnpm -w typecheck && pnpm -w lint && pnpm -w test` and commit.
3. **Deploy to development** (`forge deploy -e development`) and repeat the step 1 checks. The `appIsLicensed` filters
   now apply too: with `--license inactive`, the issue trigger no longer shows up in `forge logs` at all.
4. **Paid listing:** set the Marketplace listing to Paid via Atlassian with the pricing, and have it approved.
5. **Deploy to production:** `pnpm --filter @threatline/core-app build`, then `forge deploy -e production`. Then run
   `forge install --upgrade -e production` on any site that the CLI says needs a scope or permission upgrade.
6. **Update `docs/JUDGE_GUIDE.md` and `docs/MARKETPLACE.md`:** new installs now come from the Marketplace listing only.

## What existing installs experience

- Forge treats every existing production installation as **unlicensed until a site admin subscribes** in Atlassian
  Administration. That includes demo sites and judges' sites.
- Right after the February deploy, those sites show the banner and start no new reviews, and their Done gate stops
  blocking. Everything already there stays readable, and attestations for finished reviews still issue.
- When the admin subscribes (or starts a trial), the next panel or admin page view records `licensed`. From then on
  reviews start again and the gate enforces verdicts again.
- The validator and the queue rely on that recorded state. So a site that lapses or renews gets the new behaviour at the
  gate only after someone opens a Threatline panel or the admin page. A person blocked at the gate usually opens the
  panel to see why, and that view records the new state.

## The install-link consequence

- Once `licensing.enabled: true` is deployed to production, **production can no longer be installed from the developer
  console link**. New installs go through the Marketplace listing.
- After the listing is approved, the developer console can no longer distribute the app at all. To share a test build
  (with judges or reviewers), copy the code into a separate Forge app with licensing off and share that app's install
  link.
- The development and staging environments stay installable by link, and `--license` lets them simulate any state.
