# Champion inbox

Some threats need a person: the verifier doubted a threat at or above the blocking level, the threat rests on text that
reads as instructions to an AI, or its quotes were not all found word for word. Such a threat has the state
`needs_human`, and it blocks Done until a security champion decides it. The issue panel shows these threats one work
item at a time. The champion inbox puts all of them, across projects, in one queue.

## Where

The **Threatline security posture** global page (`jira:globalPage`, `threatline-posture`) has a **Champion inbox** tab next to the dashboard, with
the number of threats waiting. Only members of the champion group and Jira admins see the tab. The server checks the
role on every call (`isChampionOrAdmin` in `apps/core/src/services/roles.ts`), and a failed lookup grants nothing.
Everyone else sees the dashboard on its own.

## What it lists

Each row is an open `needs_human` threat on the **latest, settled** review of a work item in an **enabled project**
that the viewer can **browse**. A review that a champion already confirmed as a whole in the panel (*Confirm
threats*) is left out, because its threats no longer wait for anyone. Rows are sorted by severity, then by age (the
oldest first). A row shows:

- the work item key (a link), its summary, the threat title, STRIDE, severity and how long it has waited;
- why it needs a person: the verifier's doubt, the verifier's `duplicateOf`, text flagged as instructions to an AI,
  or weak evidence.

Redaction follows the panel's rule (`scopeForViewer`). Citations to sources the viewer cannot open are dropped, and
a threat left with no citation is not shown. It is only counted ("1 more threat rests only on sources you cannot
open"). A failed permission check hides the threat.

Rows are **grouped** so that a cluster can be decided at once:

- a threat and the threat the verifier marked as its `duplicateOf`, in the same review;
- similar threats on different work items (`similar()` from `packages/core`: same STRIDE category and a similar
  title, the same rule that matches earlier dismissals).

## Deciding

- **Confirm** accepts the threat, so it becomes a requirement, exactly as the panel's *Accept* does.
- **Dismiss** needs a reason code (false positive, not applicable, duplicate, already mitigated). The note is optional.

Both work on one row, on a selection, or on a whole cluster. A bulk decision is N separate decisions made one after
the other. The server authorises and validates each one, then decides it through the triage service, which ledgers
it, keeps its requirement in step and refreshes the verdict. Before deciding, the server checks four things: the
viewer can browse the work item, the project is enabled, the latest review is settled, and the threat is still
visible and still waiting. If one item fails, the failure is reported for that item and the rest go ahead. The server
takes at most 25 items per call, so the UI sends a larger selection in batches.

The issue panel and the inbox decide through `applyTriage`, so every decision, from either place, appends a
`threat.triaged` ledger entry **before** it is saved. If the ledger cannot record the decision, nothing changes. If the
save fails afterwards, a `threat.triage_failed` entry records that the decision did not take effect.

## Keyboard

| Key | Does |
| --- | --- |
| `j` / `k` | Next / previous threat |
| `x` | Select or clear the current threat |
| `c` | Confirm the selection (or the current threat) |
| `d` | Dismiss the selection (or the current threat): opens the reason form |
| `?` | Show or hide the shortcut list |

Shortcuts do nothing while you type in a text field, list box or editor, while a modifier key is held, or while the
dismissal form is open. They also stay off while the inbox tab is not shown.

## Bounds

The inbox reads `ReviewRepo.needsHuman(limit)`, one query on the `threats (state, severity)` index (migration v8,
`threats_state_index`) that is joined to each work item's latest revision and capped at 500 rows. If the cap is hit,
the inbox says that only the most urgent threats are listed. Facts are read only for the reviews it finds. Pages hold
about 50 rows and never split a cluster.

## Code

| Where | What |
| --- | --- |
| `apps/core/src/services/inbox-service.ts` | Build, cluster, page and decide one item |
| `apps/core/src/resolvers/inbox.ts` | `inbox.list`, `inbox.decide` (registered in `resolvers/table.ts`) |
| `packages/core/src/verify.ts` | Keeps the verifier's `duplicateOf` on a threat sent to a champion |
| `apps/core/ui/src/inbox/` | `GlobalPage` (tabs and count badge), `ChampionInbox`, fixtures |
| `apps/core/ui/test/inbox.test.tsx`, `apps/core/test/resolvers/inbox.test.ts`, `e2e/tests/champion-inbox.spec.ts` | Tests |

To preview it locally, run `pnpm --filter @threatline/core-ui dev`, open `?view=posture` and choose the Champion
inbox tab. `&inbox=empty` shows the empty state, and `&inbox=forbidden` shows the page as a viewer without the role.
