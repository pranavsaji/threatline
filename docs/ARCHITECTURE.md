# Threatline architecture

Threatline turns a Jira work item into a cited STRIDE threat model, turns the threats that matter into security requirements,
and then enforces them: the work item cannot move to Done, and its pull request cannot merge, until each requirement is
verified with evidence or accepted as a risk by someone allowed to accept it. Every decision lands in a hash-chained,
Merkle-logged risk ledger.

Two Forge apps, because one app cannot carry both site and workspace scopes:

- **Threatline for Jira** (`apps/core`), with Confluence as a compatible product: the review, the issue panel, the
  workflow gate, the Rovo agent and MCP tools, the admin and posture pages, and the ledger.
- **Threatline for Bitbucket** (`apps/bitbucket`): a merge check that accepts a pull request touching security-sensitive
  files only with a valid, signed attestation for its head commit.

Neither manifest declares egress, so nothing leaves Atlassian's platform.

## How a review runs

Threatline Engine is the default review mode (Threatline admin → **Review mode**). Rovo agent mode is the alternative;
the diagram shows both, and they share everything after the proposals.

```mermaid
flowchart LR
  subgraph Jira
    WI["Work item created, or a re-run<br/>(Run review, threatline-review label)"]
    P[Issue panel] -->|panel.* resolvers| R[Threatline functions]
    V[Workflow validator<br/>threatline-gate] -->|reads KVS verdict| K[(KVS)]
  end
  WI -->|issue event → queue job| G["Gather: REST as the app,<br/>permission-checked per actor"]
  subgraph Engine["Threatline Engine (default), one queue job per stage"]
    X["Injection check, quarantined<br/>(balanced tier)"] --> N["3 independent runs in parallel<br/>Threatline agent prompt (deep tier)"]
  end
  G --> X
  N --> A["Assemble: deterministic<br/>validate · ground · vote · map · score"]
  A --> VF["Verifier (deep tier)<br/>skipped when injection is suspected"]
  subgraph AgentMode["Rovo agent mode (alternative)"]
    AR["Automation rule:<br/>3 × Use agent: Threatline"] --> AG[Rovo agent]
  end
  AG -->|GET get-review-context| R
  R -->|bundle + single-use<br/>submission token| AG
  AG -->|CREATE submit-threat-model| A
  A --> S[(Forge SQL)]
  VF --> S
  A --> VD[Verdict, computed by code] --> K
  VF --> VD
  VD --> EP[Issue property<br/>for JQL]
  S --> L[(Ledger: hash chain<br/>+ Merkle tree heads)]
  R -->|attestation, Ed25519| BB[Bitbucket merge check]
  L -->|daily signed tree head| C[Confluence page]
```

1. **Trigger.** Creating a story or epic in an enabled project fires `avi:jira:created:issue`, and Threatline queues a
   `gather` job. A re-run does the same: the panel's **Run review**, the `start-review` action, or adding the
   `threatline-review` label. An edit to a reviewed work item does not start a new review; it marks the review out of
   date, so Done blocks with a one-click re-run. Each stage after this is its own queue job
   (`apps/core/src/consumers/review-consumer.ts`, `apps/core/src/services/engine.ts`), so every model call fits a
   function timeout and a redelivered job is not paid twice.
2. **Context (gather).** Threatline gathers the work item, its parent, children, links, comments, linked Confluence
   pages and related incidents over REST. Only the work item's key, type, status, project, components and fix versions
   are *trusted*; every piece of free text is *untrusted* and wrapped as data. Pages and incidents the actor cannot
   read are left out (they still count towards the context hash). Secrets are redacted and text that looks like
   instructions to an AI is flagged (`injectionSuspected`). The review is created in `awaiting_agent` and its verdict
   already blocks. Before any model call, the gather's assembly stores the revision's rule-based threats as its
   **first look**, which the panel and the context column show while the review runs (display only; see
   [ENGINE.md](ENGINE.md)). Threatline's own comments are never gathered and never hashed.
3. **Proposals.**
   - *Threatline Engine:* a quarantined injection check reads the raw untrusted text, fenced with a random nonce, on
     the balanced tier; its model-based flag joins the scanner's. Then three independent runs (`agentSamples`, 3 by
     default) of the Threatline agent prompt run in parallel on the deep tier. Each writes a
     `threatline.threatmodel.v1` JSON document: STRIDE threats, each with verbatim quotes from the sources as
     evidence. A model error becomes a failed run. Its calls are billed to the app's developer. See [ENGINE.md](ENGINE.md).
   - *Rovo agent mode:* an Automation rule runs "Use agent: Threatline" three times with *Let this agent take actions*
     on. Each run calls `get-review-context`, which returns the same bundle with a single-use submission token bound
     to this review and context hash, and then `submit-threat-model`, which checks and spends the token. In engine
     mode `submit-threat-model` refuses every submission, so nothing outside Threatline can write a review.
4. **Assembly.** Each run that arrives queues an `assemble` job. Nothing the model wrote decides anything by itself;
   `assembleReview` does, deterministically:
   - schema validation (invalid samples are discarded with a reason, never repaired silently);
   - **quote grounding**: every quote must appear in a source; unsupported threats are discarded;
   - **self-consistency**: threats are clustered across the samples and only those a majority of runs raised are kept
     (the rest are discarded as `low_votes`); a kept threat is `accepted` when its quotes are found verbatim, and
     `needs_human` (a security champion must confirm it) when its evidence is weak or it touches a source suspected of
     injection;
   - deterministic **baseline rules** add threats the domain always implies (auth, PII, payments, credentials);
   - **mapping** to OWASP ASVS 5, CWE, OWASP LLM Top 10 and the Agentic Top 10;
   - **scoring** and the **verdict** (below);
   - **carry-over (R7)**: on a re-review, threats that cite only unchanged sources keep their triage.
5. **Verification (Threatline Engine only).** Once the review is ready, one `verify` job sends each accepted AI threat
   and its quotes to an adversarial verifier on the deep tier. Code applies the result: a kept threat is marked
   Verified; a doubted threat at or above the blocking level (High by default) goes to a security champion; one below
   it is dismissed with the reason, or stands back under a kept threat it duplicates. The verifier never runs when injection is suspected anywhere in the material or the injection
   check did not complete. If it fails, the review stands as assembled.
6. **Enforcement.** The verdict is written to KVS (read by the workflow validator, under 500 ms) and to an issue
   property (for JQL). The Bitbucket merge check verifies an attestation offline with the published public keys.
7. **Verdict comment.** When the revision is final (after verification, or failed), Threatline comments the verdict on
   the work item once: counts, the top risk only when everyone who can see the work item may read its sources, and
   the requirements. A re-run comments only when the verdict or blocking count changed. See [ENGINE.md](ENGINE.md).

The earlier dual-LLM design (proposals that saw only an extracted sketch) is kept in `packages/core/src/pipeline.ts`
for the eval; it measured worse and does not run in the product. A third mode, **Rule-based checks only**, settles
every review at once from the baseline rules, with no model.

## Risk score

```
score = min(100, round((min(70, Σ severity weights) + min(20, Σ data-class weights)) × exposure multiplier))
```

| Severity | Weight | | Data class | Weight | | Exposure | Multiplier |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Low | 2 | | PII | 6 | | internal | 1.0 |
| Medium | 5 | | credentials | 8 | | partner | 1.15 |
| High | 12 | | payment | 10 | | public | 1.3 |
| Critical | 25 | | health / secrets | 8 | | | |

Only threats that are accepted, proposed or waiting for a champion count. `whatIfScore` (R12) re-scores with another
exposure or data-class set and stores nothing.

## Verdict (fails closed)

`computeVerdict` (`packages/core/src/verdict.ts`) returns `pass`, `warn` or `block` with reasons a person can act on:

| Reason | Blocks until |
| --- | --- |
| No review, or the review failed | A review completes. The AI timing out counts as missing. |
| Review out of date (context changed, or it could not be checked) | Re-run (one click from the message). |
| Paused at the budget (token budget or the site out of Rovo credits) | A security champion confirms the work item; ledgered, admin alerted. |
| Threats at or above the policy level waiting for a champion | A champion confirms them (called out separately when injection was suspected). |
| Open requirements at or above the policy level | Each is verified with evidence, marked not applicable by a champion, or covered by an active risk acceptance. |

Work that touches no sensitive path merges freely. **Warn-only** mode (per project, at most 14 days) and
**break-glass** (an admin, with a written reason) let work through, and every use is ledgered. Verdicts are recomputed
when the policy changes or a lenient verdict's window ends.

## Packages and ports

| Package | Role |
| --- | --- |
| `packages/shared` | Zod schemas and types shared by everything (threats, requirements, attestations, the agent JSON contract). |
| `packages/core` | The domain: context normalisation and redaction, assembly, grounding, consensus, scoring, verdicts, acceptance rules, ledger, transparency log, posture. Pure, behind ports. |
| `packages/crypto` | Ed25519 attestations, SHA-256 hash chain, RFC 9162 Merkle trees, on `@noble/ed25519` and `@noble/hashes`; open-source candidate. |
| `packages/db` | Forge SQL migrations and SQL implementations of the repos. |
| `packages/frameworks` | ASVS 5, CWE, OWASP LLM and Agentic Top 10 catalogues and STRIDE defaults. |
| `packages/prompts` | The agent prompt and `PROMPT_VERSION`, shared by the deployed agent and the evals. |
| `packages/llm-dev` | Dev-only `claude -p` adapter for evals; never bundled into an app. |
| `apps/core` | Forge functions, resolvers, Rovo actions, jobs, adapters (Jira, Confluence, KVS, SQL, queue) and the Custom UI (`apps/core/ui`). |
| `apps/bitbucket` | Merge check, repository settings page, settings store. |
| `apps/local` | `pnpm threatline` CLI: offline review, evals, demo signing. |
| `evals` | 40 clean and 15 poisoned cases, the runner, metrics and recorded model outputs. |

Core logic depends only on ports (`packages/core/src/ports.ts`): `ClockPort`, `LlmPort`, `ContextGatherer`,
`ReviewRepo`, `RequirementRepo`, `LedgerRepo`, `FeedbackRepo`, `IssueRepo`, `AttestationRepo`, `TreeHeadRepo`,
`UsageRepo`, `VerdictSink`, `SigningKeyStore`. Every port has an in-memory fake that runs the same contract tests as the
SQL implementation (`packages/core/test/contracts`).

## Storage

| Store | What |
| --- | --- |
| Forge SQL | `reviews`, `review_stages` (doubles as the run trace, and holds the first look and the once-only verdict-comment claim), `agent_samples`, `context_facts`, `threats`, `review_discarded`, `requirements`, `feedback`, `issues`, `issue_pages`, `attestations`, `ledger`, `merkle_heads`, `posture_snapshots`, `usage_monthly`, `rate_limits`, `suppression_rules`, `suppression_matches`. Reviews are purged after 400 days; the ledger never is. |
| KVS | Verdicts (what the gate reads), site and project policy and its version, rate-limit counters, single-use submission tokens, Threatline's own account id (`app:account-id`, learnt from its first comment) and the last verdict comment per work item (`comment:last:<id>`). |
| Forge secret storage | The Ed25519 signing key (generated on install, never sent to the UI; rotation keeps old keys verifying for a grace period). |
| Issue property `threatline.verdict` | Searchable copy of the verdict for JQL and dashboards. It is never read by the gate, because users can edit issue properties. |

## The ledger

Every acceptance, approval, revocation, confirmation, break-glass, warn-only switch and policy change is appended to
`ledger` with `entryHash = SHA-256(prevHash ‖ canonical entry)`; there is no update or delete path. Once a day Threatline
builds an RFC 9162 Merkle tree over the entry hashes, signs the tree head with the attestation key, stores it and, once a digest space is set under
Notifications, posts it to a Confluence page. An admin can download a proof for any entry (inclusion in the signed tree, plus consistency
with the last published head) and anyone can check it offline with `node scripts/verify-ledger-proof.mjs proof.json`,
which uses only Node built-ins. A proof carries its own public key, so pin Threatline's published key with
`--public-key <key>` (from the Confluence tree-head page or **Threatline admin → Signing keys**); the verifier also
refuses a tree head whose key id is not the embedded key's.

**Try it.** `docs/examples/ledger-proof.json` is a real proof built with Threatline's own code
(`pnpm tsx scripts/make-example-ledger-proof.ts`), signed with a throwaway demo key that is not a Threatline key;
`ledger-proof-tampered.json` is the same proof with one payload field changed. From the repository root:

```console
$ node scripts/verify-ledger-proof.mjs docs/examples/ledger-proof.json --public-key ihXDX_OHPt0TIxhax2CBCqgc4lgjU8TzrlQThOzz6g8
OK: ledger entry 6 (attestation.issued) is in the signed tree of 8 entries.
Root c2326c75743bb5f5153ba85be52d7ce417d287c73cf1fb797952e43eceecdb6a, signed 2026-11-02T17:00:00.000Z.
Consistent with the earlier head of 4 entries (nothing before it was rewritten).
Public key ihXDX_OHPt0TIxhax2CBCqgc4lgjU8TzrlQThOzz6g8 (key id f4dc95a1eb1902e4).
It matches the pinned --public-key.

$ node scripts/verify-ledger-proof.mjs docs/examples/ledger-proof-tampered.json; echo "exit $?"
FAILED: entry_hash
exit 1
```

`packages/core/test/offline-verifier.test.ts` runs both commands.

## Surfaces

- **Issue panel**: verdict and the reasons behind it, risk score, the first look while a review runs, threats (plain
  language first, evidence quotes with links), requirements and evidence, risk acceptances, history and the diff since the last review, what-if, merge
  attestation, champion triage.
- **Work item comment**: the verdict once per settled review (site policy `postReviewComments`).
- **Admin page**: first-run wizard, projects and guarded transitions, severity policy, roles, budgets, warn-only,
  notifications, recent runs with stage timings, signing keys, ledger verification and Merkle proofs, demo data.
- **Security posture** global page and dashboard gadget: open Critical/High, where they are, trend, release report.
- **MCP server** (`rovo:mcp`, eight tools): `get-review`, `get-security-requirements`, `check-change-risk`,
  `get-merge-attestation`, `request-risk-acceptance`, `verify-requirement`, `explain-threat`, `posture-summary`.
- **Rovo agent** "Threatline": the same tools plus `release-readiness`, `start-review`, and (agent mode only) the two
  review actions `get-review-context` and `submit-threat-model`.
- **Confluence**: the threat model published as a page; the weekly digest; the ledger tree heads.
