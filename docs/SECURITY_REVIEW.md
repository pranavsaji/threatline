# Threatline security review

A security product is judged by its own security, so this is Threatline's own threat model: what could go wrong with
Threatline, how it is prevented, and the test that proves each control. Threats are written as STRIDE categories in
plain language first, the way Threatline writes them for its users.

Scope: Threatline for Jira (`apps/core`, with Confluence) and Threatline for Bitbucket (`apps/bitbucket`) as built in this
repository's `main` branch. Method: the spec's threat and control table (§ Security, privacy and trust), checked control by control
against the code, with the defects found during the build and the reviews of each task recorded under "Found and fixed".

## Threats and controls

| # | Threat (plain language) | STRIDE | Control | Proved by |
| --- | --- | --- | --- | --- |
| S-1 | Text in a page, comment or pull request tells the AI to pass the change, and the verdict flips. | Tampering, Elevation of privilege | The model never sets a verdict: code does (`computeVerdict`). Untrusted text is wrapped as data, instruction-like text sets `injectionSuspected`, and threats touching such a source go to a security champion (`needs_human`) and block until confirmed. Grounding drops any threat whose quote is not in a source. 15 poisoned eval cases must not lower risk or blocking versus their clean twins; on the production model (`claude-opus-5`, Engine path with the verifier) all 15 of 15 held (`evals/results/2026-11-21-recorded-all-engine-opus-5.md`); on `claude-sonnet-4-5` 14 of 15 held (`poisoned-ai-02` flagged the injection but scored risk 84 against its twin's 90, `evals/results/2026-11-20-recorded-all.md`). | `packages/core/test/ingest.test.ts`, `packages/core/test/review-context.test.ts`, `evals/` injection resistance |
| S-2 | Someone sees the review of a work item, or a linked page, they are not allowed to see. | Information disclosure | Every resolver and action resolves the caller's scope (`viewer-scope.ts`, `asUser` permission checks) before reading SQL rows; facts from sources the viewer cannot open are dropped and only counted ("2 threats cite sources you cannot open"). The gather includes pages and incidents only if the actor can read them. | `apps/core/test/viewer-scope.test.ts`, `apps/core/test/resolvers/panel.test.ts`, `apps/core/test/adapters/rest-gatherer.test.ts`, `apps/core/test/adapters/jira.test.ts` |
| S-3 | A developer approves their own risk acceptance. | Elevation of privilege, Repudiation | The approver must differ from the requester; High and Critical need the champion role; tech leads are capped by policy. Every request, approval, rejection and revocation is ledgered. | `packages/core/test/acceptance.test.ts`, `apps/core/test/services/acceptance-service.test.ts` |
| S-4 | A forged, edited or replayed attestation lets a pull request merge. | Spoofing, Tampering | Ed25519 signature over issue, repository, commit SHA, verdict, requirements, expiry and a nonce; 24 h default lifetime; the merge check requires the commit to equal the pull request head and the key id to be trusted by the repository. One changed character fails verification. | `packages/crypto/test/attestation.test.ts`, `apps/bitbucket/test/merge-check.test.ts`, `apps/core/ui/test/attestations.test.tsx` |
| S-5 | Someone edits or deletes ledger rows to hide an acceptance. | Tampering, Repudiation | Append-only hash chain (no update or delete code path), admin verification, and a daily RFC 9162 Merkle tree head signed with the attestation key and published to Confluence; downloadable inclusion and consistency proofs checked offline by `scripts/verify-ledger-proof.mjs`. A stored head that no longer matches the ledger raises an ops alert and is never re-signed. | `packages/crypto/test/hashchain.test.ts`, `packages/crypto/test/merkle.test.ts`, `packages/core/test/transparency.test.ts`, `packages/core/test/offline-verifier.test.ts` |
| S-6 | The signing key leaks. | Information disclosure, Spoofing | The key is generated on install into Forge secret storage, never sent to the UI or logged; rotation creates a new key id and old keys keep verifying for a grace period. | `apps/core/test/services/attestation-service.test.ts`, `apps/core/test/adapters/kvs.test.ts`, `apps/core/ui/test/attestations.test.tsx` |
| S-7 | Repeated re-runs burn AI usage (Threatline Engine's Forge LLM calls, billed to the app's developer, or the site's Rovo credits). | Denial of service | 10 re-runs per person per hour; a monthly review cap and token budgets; triggers debounced by context hash. When paused at the budget or out of Rovo credits, the gate blocks and a champion can confirm (ledgered, admin alerted). | `apps/core/test/triggers.test.ts`, `apps/core/test/consumer.test.ts`, `packages/core/test/verdict.test.ts` |
| S-8 | Secrets in a design page end up in an AI prompt or a log. | Information disclosure | Secret patterns are redacted and excerpts capped when facts are normalised; logs carry ids, timings and counts, never content or prompts. | `packages/core/test/context/context.test.ts`, `apps/core/test/services/confluence-page.test.ts` |
| S-9 | A forged agent submission writes a threat model for a review it did not run. | Spoofing | `get-review-context` issues a single-use submission token bound to the review and context hash; `submit-threat-model` spends it and rejects reuse or a mismatch. | `packages/core/test/review-context.test.ts`, `apps/core/test/actions.test.ts` |
| S-10 | A user edits the issue property to make the gate pass. | Tampering | The workflow gate reads the verdict from app storage (KVS), never from the user-editable issue property, which is only a searchable copy. | `apps/core/test/validators.test.ts` |
| S-11 | A failed, missing or stale review is treated as a pass. | Elevation of privilege | The verdict fails closed: no review, a failed review, an AI timeout, an unreadable context or an out-of-date review all block, each with a message saying why and how to fix it. A lenient verdict past its window, or computed under an older policy, is recomputed or blocks. | `packages/core/test/verdict.test.ts`, `apps/core/test/validators.test.ts`, `apps/core/test/resolvers/admin.test.ts` |
| S-12 | Break-glass or warn-only becomes a quiet bypass. | Repudiation, Elevation of privilege | Break-glass needs an admin and a written reason; warn-only lasts at most 14 days; both are ledgered with an ops alert, and the panel and gate messages say the gate is overridden and until when. | `packages/core/test/policy.test.ts`, `apps/core/test/resolvers/admin.test.ts`, `apps/core/ui/test/panel.test.tsx` |

## Found and fixed during the build

Defects the per-task reviews found in Threatline's own code, each fixed with a test that failed first:

- **A re-review hid fresh evidence under an old dismissal** (Task 31). Carry-over could fold a threat raised again from
  new, possibly attacker-planted, evidence into an earlier dismissed threat. Now a threat citing changed sources is
  always new, a fresh `needs_human` beats an older acceptance, and an old dismissal never suppresses a threat from a
  source suspected of injection.
- **An unknown context passed the gate** (Task 11). When the current context could not be gathered, the verdict
  compared a missing hash and passed; it now blocks as out of date.
- **Permission checks for other users are refused for apps** (Tasks 19 and 28, found live). Jira returns 403 when an
  app asks what another user may see, so checks now impersonate that user (`asUser` + `mypermissions`, and searches
  run as the user); a missing, forbidden or malformed work item reads as "no access", never as an error that leaks
  whether it exists.

## Residual risks

- **The Automation agent runs with the rule actor's permissions.** "Let this agent take actions" lets the agent call
  Threatline's CREATE actions; the submission token limits it to submitting the review it was given.
- **Merge blocking needs Bitbucket Premium.** Without a required check, a failed Threatline check is a warning on the pull
  request; the settings page says so.
- **Severity colour.** Critical and High share a colour; the severity word is always shown.
- **Carry-over keeps old threats on unchanged sources.** A bad earlier threat stays until someone dismisses it.
- **What-if understates a real exposure change**: it re-scores but does not add the threats a new exposure would trigger.
- **Threatline Engine's runs read the fenced untrusted text.** Only the injection check is quarantined (no tools, typed
  output). The runs see the design text inside nonce-fenced data blocks, like the Rovo agent; the defences are the
  scanner and the injection check (flagged material sends every AI threat to a champion and skips the verifier),
  majority consensus, verbatim-quote grounding, the rule-based floor, and code (never the model) setting the verdict.

## Privacy

- No egress in either manifest; data stays in Forge-hosted storage and follows its data residency.
- Reviews and facts are kept 400 days, the ledger for the app's life.
- See [PRIVACY.md](PRIVACY.md) and [TERMS.md](TERMS.md).
