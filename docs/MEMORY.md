# Seen before: organisational memory for each threat

A threat model tells a team what could go wrong. "Seen before" tells them whether it already has, here: the incident
where it happened, and the other work items where the same threat was fixed (and with which pull request), accepted
as a risk (and until when), or dismissed as a false positive. It is built from Threatline's own history and a Jira
search, with deterministic matching that explains itself, and it never shows a person anything they cannot open.

## What the panel shows

Under each active threat (accepted, proposed or waiting for a champion), at most three lines:

```
Seen before
INC-7 · Incident · Duplicate refunds after webhook retries (Sev-2, payments)
        Why: same component payments; shared words: duplicate, refund, webhook
PAY-3 · same threat · Verified with PR #41
        Why: same STRIDE category (Tampering); same asset (webhook endpoint); shared words: duplicate, refund, replay, webhook…
PAY-9 · same threat · risk accepted until 2027-01-31
```

The key opens the work item (`target="_top"`, through the Forge router inside Jira, like every other work item link in
the panel); "PR #41" opens the pull request that verified the requirement. Incidents come first, then verified,
accepted and dismissed, best match first, one line per work item.

When a threat at or above the blocking level (High by default) matches a past incident, the header says so under the
headline: **This happened before: INC-7 — Duplicate refunds after webhook retries.**

The Rovo agent and the MCP tool `explain-threat` return the same lines in `seenBefore` (key, kind, line, reason, link,
and the evidence link when there is one), filtered for the person calling.

## What is matched

**1. Past incidents.** Work items the site's incident rule recognises (Threatline admin → Incidents; by default the
label `incident` or the work type `Incident`; the same rule as [incidents reopen reviews](INCIDENTS.md)), created in
the last 365 days. Two searches, run as the app and filtered per viewer afterwards:

- linked to this work item, or on one of its components in its project (at most 25);
- the most recent anywhere on the site (at most 50).

Jira refuses a JQL that names a work type the site does not have, so a refused search is retried on the labels alone.

**2. The same threat on other work items' reviews.** From Forge SQL: the latest ready review of each other work item
updated in the last 365 days (at most 150 reviews, newest first, at most 1,000 threat rows). A match is shown only with
an outcome to learn from:

| Outcome | When |
| --- | --- |
| **Verified** | Its requirement is Verified. A PR link shows as "PR #41" (Bitbucket, GitHub and GitLab links); CI evidence as "tests passed in CI"; a test, Confluence page or note by kind only (a page may be restricted, a note is free text). |
| **Risk accepted until** | Its requirement is covered by an active risk acceptance (from the ledger); the date is the acceptance's expiry. |
| **Dismissed as a false positive** | A champion dismissed it with that reason. Other dismissals (duplicate, not applicable…) are not shown. |

A threat still open elsewhere is not shown: it says nothing yet. Rule-based threats on the other side are left out,
because the same rule fires on every work item of a kind and would be "seen before" everywhere.

## How it matches (deterministic, explainable)

All matching is pure code in `packages/core/src/memory.ts`; no model is called. Text is normalised, lightly stemmed
(plurals, -ed, -ing, applied the same way to both sides) and stripped of generic words ("attacker", "user", "data",
"another", "could"…), leaving the *distinctive words*. A threat's words come from its title and plain-language line.

**Incident ↔ threat** (words of the incident's summary and the first 2,000 characters of its description):

| Rule | Needs |
| --- | --- |
| Names the CWE | The incident text names one of the threat's CWEs (`CWE-639`). |
| Nearby | The incident is on one of the work item's components, or linked to it, **and** shares at least 3 distinctive words that make up at least 25% of the threat's words. |
| Anywhere | Elsewhere on the site: at least 4 shared words, at least 40% of the threat's words. |

**Threat ↔ threat on another work item** (Jaccard overlap of the two threats' distinctive words):

| Rule | Needs |
| --- | --- |
| Same specific CWE | A CWE in common other than the STRIDE category's default one (every threat gets that, so it says nothing more than the category), at least 2 shared words and overlap ≥ 0.2. |
| Same STRIDE and asset | The same STRIDE category, a similar component ("webhook endpoint"), at least 2 shared words and overlap ≥ 0.25. |
| Same STRIDE | The same STRIDE category, at least 3 shared words and overlap ≥ 0.4. |

Each line carries its reason, built only from what the two sides share: "same CWE-639; shared words: customer,
number, order", "same component payments; shared words: duplicate, refund, webhook". The thresholds live in
`MEMORY_RULES`; `packages/core/test/memory.test.ts` holds the clear positives and the near misses that must not match
(two shared words on one component, generic wording only, the STRIDE-default CWE alone, the same words under another
STRIDE category).

## Where it is computed

Lazily, when the panel opens: `panel.get` returns as before, then the panel calls `panel.memory` once the review is
ready (and again for a new revision or a changed verdict). Until it answers, or if it fails, threats just show no
history. `panel.status` (the Security gate label in the right-hand column) is untouched and never reads history.

Matches are computed for every active threat of the latest review (at most 50, most severe first) and cached in KVS per
work item (`memory:v1:<issueId>`, the review id and the time) for 15 minutes; a new revision recomputes at once. A
result with a failed search or query is shown (marked partial) but not cached, so the next load tries again. The
cache holds candidates before any permission filter; the filter runs on every call, for whoever is asking.

## Permissions

Only what the viewer may open, checked on every call:

- **Work items** (incidents and other work items) go through one search as the viewer, `id in (…)` with Jira's own
  project permissions and issue security (`JiraClient.browsable`, impersonating the viewer with `read:jira-work`). A
  work item they cannot browse is dropped silently: no key, no summary, no count.
- **A same-threat line** also needs that threat to be visible to the viewer on its own work item, as that work item's
  panel would show it: at least one of its cited sources readable by them (`scopeForViewer`, which checks Confluence
  pages and linked issues). At most 10 other reviews are checked per call; anything not checked is not shown.
- **This work item's own threats** are scoped as on the panel: only threats the viewer can see get history.
- Any failed check hides the item (fail closed). If the permission search itself fails, nothing is shown.

The incident's summary is shown only to people who can open the incident, exactly as Jira would show it; the other
work item's threat text is never shown, only its key and outcome. Nothing is sent to a model, written to a comment or
copied into another work item.

## Limits

| What | Bound |
| --- | --- |
| Incident searches | 2 JQL searches per computation: 25 nearby, 50 most recent; last 365 days. |
| Other reviews | 150 most recently updated ready reviews; 1,000 threat rows; last 365 days. |
| Outcomes | Requirements and acceptances of at most 25 other work items (one SQL query, one ledger read). |
| Threats matched | 50 per review (most severe first). |
| Per threat | 6 candidates cached, 3 shown. |
| Viewer checks | 1 permission search (100 ids per request), facts of at most 10 other reviews. |
| Cache | 15 minutes per work item, or until a new revision. |

On a very busy site the most relevant incident can be older than the 50 most recent; the nearby search (linked or same
component) still finds it within its 25.

## Demo

**Load demo data** creates two incidents on the `support-agent` component. Their descriptions read like postmortem
summaries ("the getOrder lookup tool did not check that the order belonged to the customer chatting"; "bots flooded the
public chat endpoint … no per-IP rate limit"), so once the epic and stories are reviewed, their order-disclosure and
chat-flooding threats show the incidents under "Seen before", and when such a threat blocks (High or above) the
headline says "This happened before". What the review raises depends on the model run; the matcher is tested against
the wording recorded Engine runs use for this design. After you
verify a requirement on one story with a PR link, the same threat on the epic shows "PAY-… · same threat · Verified with
PR #…" within 15 minutes (or at once after a re-run). `apps/core/test/services/memory-demo.test.ts` keeps the demo text
and the matcher in step.

Locally: `pnpm --filter @threatline/core-ui dev`, open `?state=ready`.

## Not yet

- **Teamwork Graph enrichment.** Incidents and post-incident reviews from connected tools (Opsgenie, Jira Service
  Management, Confluence postmortems) and code ownership, read as the viewer through Teamwork Graph. Today the history is
  Jira's incidents and Threatline's own reviews.
- **The same CWE on recently shipped work** (Done work items whose code reached production), from the delivery check.
- **History as review context.** Seen before is shown to people; it is not fed to the model that writes the review.

## In the review

Seen before shows history next to a threat after the review. The review itself also learns from it: the gatherer puts
past incidents linked to the work item or on its components into the review context (only those the person who caused
the review may open), and when there are any, Threatline Engine's gap check gets one more step: for each incident, does
this design have the same weakness, and does a listed threat already cover it? A threat it finds this way is held to
the same rules as any gap-check threat: it must quote the design word for word, stays hidden until the verifier keeps
it, and can only ever add to what blocks. A review with no past incidents in its context gets exactly the prompt the
eval measured.

