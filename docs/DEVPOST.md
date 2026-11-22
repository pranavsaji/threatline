# Threatline: Devpost submission and demo script

Copy the sections below into the Devpost form. The demo script is for a video of about three minutes.

## Tagline

Security review that gates Done and merge: AI threat models with cited evidence, enforced by code the AI cannot talk
past.

## Inspiration

Teams already "do" security review: a checklist in the ticket template, a threat-model page nobody updates, a
reviewer asked at the last minute. The review is advisory, so it loses to the deadline. AI made it worse in a new way:
a chatbot will happily write a threat model, but it invents risks, misses real ones, and anyone can ask it to say the
change is fine. We wanted review that is specific to the work, cites its evidence, and is enforced where work actually
finishes: the Done transition and the merge.

## What it does

Threatline makes security review part of "Done". One story shows all of it:

1. **Create a story.** Threatline Engine reviews it by itself on Atlassian-hosted Claude models (Forge LLMs): three
   independent analyses that must agree and quote their evidence word for word, then an adversarial verifier. No
   setup, no Rovo agent, no Automation rule, and no developer can write their own review.
2. **Read the threats in plain language**, each with the sentence it rests on, its STRIDE category, ASVS 5 and CWE, and
   a Given/When/Then requirement with a fix-by date and a copyable test skeleton.
3. **Try to move it to Done: blocked.** The workflow validator lists the open requirements. Missing, failed or
   out-of-date reviews block too, with a one-click re-run. The gate fails closed.
4. **Fix or accept.** Verify a requirement with a PR link, or accept the risk with a reason, controls, an expiry and an
   approver who is not you. Done passes.
5. **Merge.** A signed Ed25519 attestation lets the Bitbucket merge check (or the Threatline GitHub Action) pass the
   sensitive pull request for its exact head commit. Change one character and it fails.

**The AI cannot be talked into approving.** Text that tries to instruct the model is flagged, the threats resting on it
wait for a security champion, the verifier never runs on flagged material, and code, not the model, computes the
verdict. Measured on our 55-case eval set on `claude-opus-5`, the model the product runs, through
Threatline Engine's full path: all 15 of 15 poisoned cases held, and a separate model grader found all 60
high-severity must-find threats (94.3% of all). Severity comes from facts each threat states, by a fixed table, so
Opus's tendency to call everything Critical no longer decides what blocks. Every run is recorded in the repository and
replays offline.

**Also:** CI verification (tests named after a requirement pass in CI and close it, with the run as evidence);
incidents that reopen the reviews of open work on the same component; a champion inbox across projects; a data-flow
diagram of each review with its threats pinned to it; team suppression rules that can never hide a blocking threat;
indicative SOC 2, ISO 27001 and PCI DSS control mapping; a hash-chained, Merkle-logged risk ledger with offline
inclusion proofs; MCP tools and a Rovo agent so coding agents (Claude Code, Cursor) see the same requirements; a
posture dashboard and gadget; Confluence threat-model pages; break-glass overrides with written reasons; warn-only mode
that expires after 14 days. It stays eligible for Runs on Atlassian: no egress, and the CI endpoint is a static web
trigger that can only answer with fixed messages.

## How we built it

Two Forge apps (Jira + Confluence, and Bitbucket) and a GitHub Action, in TypeScript. Forge LLMs run Threatline Engine as
a chain of queue jobs with checkpoints; Forge SQL stores reviews, requirements and the ledger; Forge KVS and secret
storage hold policy and signing keys; Custom UI with Atlaskit for every surface. The design rule: the model proposes,
code decides. Consensus, quote grounding, scoring, the verdict and the gates are deterministic and unit-tested
(over 1,600 tests, browser journeys, and a 55-case eval set with poisoned twins).

## Challenges

- Keeping the AI out of the decision while still using it for what it is good at: proposals and verification are
  requests; code decides what they do, and fails closed when the model errs.
- Prompt injection in design docs: a quarantined injection check runs first, the analyses read the text only inside
  nonce-fenced data blocks, and attacker text can never decide which threats are dropped or what the verdict is.
- Forge limits: every model call in its own job to fit a function timeout, and atomic usage accounting across
  parallel jobs.

## Accomplishments

- A review a developer cannot talk their way out of, that still explains itself in plain language.
- Signed attestations: change one character in the pull request and the merge check fails.
- An eval harness with recorded runs, a judge and a grader, and a CI gate that replays the production model's recordings
  and fails if recall, high-severity recall, judged precision or injection resistance drops.

## What we learned

Precision is the product. Security teams ignore tools that cry wolf; every feature that removed noise (consensus,
verbatim quotes, coverage, the verifier) mattered more than adding threat types.

## What's next

Marketplace listing, a check that a pull request really touches the code a requirement points to, Teamwork Graph
memory of past incidents across the organisation, and fix suggestions proposed as pull requests.

## Demo video (3:08)

A rough cut with synthetic narration is built from real screenshots of a fresh site (outside the repo, in
`threatline-video/`: `python3 build.py` renders the frames, narration and captions into `threatline-demo.mp4` and
`threatline-demo.srt`). Record your own voice over the same script for the final upload; put "Threatline" in the YouTube
title, and upload it as public or unlisted.

| # | On screen | Narration |
| --- | --- | --- |
| 1 | Title card | Threatline. Security review that gates Done, and merge. |
| 2 | The problem | Every team says it does security review. A checklist in the ticket. A threat model page nobody updates. A reviewer pinged the night before release. It's advisory, so it loses to the deadline. And A.I. made it worse: a chatbot will write you a threat model, but it invents risks, misses real ones, and can be talked into saying the change is fine. |
| 3 | A new story on a brand-new Jira site | Here is a story on a brand-new Jira site. Customers want to export their order history as a CSV, through a shareable link to a public bucket, chosen by a customer I.D. parameter. And the link never expires. |
| 4 | Reviewed by itself on Atlassian-hosted Claude models | Nobody set anything up. Within minutes, Threatline Engine reviewed it on Atlassian-hosted Claude models: three independent analyses that must agree, and quote their evidence word for word, then a verifier that checks each threat against those quotes. Risk, one hundred. It blocks Done, and merge. |
| 5 | Plain language, quoted, verified, mapped to ASVS and CWE | The threats read like a colleague wrote them. Anyone who can guess the address can download other people's order history. Critical, quoted, verified, and mapped to A.S.V.S. and C.W.E. When the verifier doubts a high-severity threat, here a duplicate, it can't quietly drop it. A security champion decides. |
| 6 | Move it to Done: blocked, with the reason | Now try to ship it. Done is blocked, and Jira says exactly why: open security requirements at High or above, with a link back to the review. Missing, failed, or out of date reviews block too. The gate fails closed. |
| 7 | Prompt injection is flagged, never obeyed | Here's the attack that breaks most A.I. reviewers. This epic's design page hides an instruction telling the A.I. to approve the change. Threatline flags the page, treats the text as data, and the threats resting on it wait for a security champion. The model never decides the verdict. Code does. |
| 8 | Fix it, or accept the risk with teeth | To get to Done, you fix, or you accept. Accepting a risk takes a reason, compensating controls, an expiry, and an approver with the right role, who isn't you. |
| 9 | Each requirement is verified with the pull request as evidence | Here a developer fixed the webhook story. Each requirement is marked verified, with the pull request as its evidence. |
| 10 | Every blocking requirement handled: Done goes through | Every blocking requirement is handled, so the story is ready for Done, and this time Done goes through. |
| 11 | A signed attestation for one repository and one exact commit | Threatline then signs an attestation, for one repository, and one exact commit. |
| 12 | Live in Bitbucket: the required merge check passes | Paste it into the pull request, and the required Bitbucket merge check verifies the signature, and passes: attested by PAY ten, five requirements verified. |
| 13 | Change one character: the signature fails | Change one character, and the signature no longer verifies. |
| 14 | Without a valid attestation the required check blocks the merge | Without a valid attestation, the required check stays red, and the merge is blocked. It checks again at merge time, and the same gate runs as a GitHub Action. |
| 15 | An audit trail anyone can verify | Every acceptance, override and refusal lands in a hash-chained ledger, with signed Merkle tree heads. An auditor can download an inclusion proof, and check it offline. |
| 16 | Coding agent over MCP | And coding agents see the same requirements. Through Threatline's M.C.P. server, Claude Code or Cursor fetch exactly what the gate will check, write the fix, and mark the requirement verified with their pull request. |
| 17 | Results and tagline | Threatline. On fifty-five eval cases, on the model it runs: every high-severity threat found, and all fifteen poisoned design docs held. Build with context. Ship with confidence. |

## Additional info (judges only): ready-to-paste answers

Fields not listed here (submitter type, country, age, eligibility, employment, survey questions) are yours to answer.

- **Is your project new?** New (started 2026-11-14).
- **Installation link:** the "Install Threatline for Jira" link in `docs/JUDGE_GUIDE.md` (Jira + Confluence). Also give the
  Bitbucket link from the same file in the testing instructions.
- **Testing instructions:** "Follow https://github.com/pranavsaji/threatline/blob/main/docs/JUDGE_GUIDE.md: open
  Jira settings → Apps → Threatline, save the first-run wizard, click Add the gate for me, load demo data (project
  key + any Confluence space key), then open the epic 'Add AI support agent' a few minutes later. No Rovo or Automation
  setup is needed; Threatline Engine runs the reviews on Forge LLMs."
- **App ID:** `13898a7c-6897-48d3-a512-079d9f9f5f00` (Threatline for Jira). Threatline for Bitbucket:
  `53a2efe5-9150-4e9a-b869-8bd2605d64e0`.
- **How it meets the technology requirement:** Built entirely on Forge. Jira: issue panel, workflow validator (the
  Done gate), admin and global pages, dashboard gadget, entity properties for JQL, issue events. Confluence: design
  pages read as review context, threat-model pages and signed ledger heads published. Bitbucket: a merge check that
  verifies signed attestations. Forge LLMs: Threatline Engine (Claude models hosted by Atlassian). Rovo: an agent with
  actions and an MCP server for coding agents. Forge SQL, KVS, secret storage and queues hold state; nothing egresses.
- **Category:** Apps for Software Teams. **Why:** it changes how software teams ship: security requirements become part
  of Done and of the merge, in Jira and Bitbucket, where developers already work.
- **Bonus prize:** Best app with Atlassian MCP. Threatline's MCP tools close the loop for coding agents: Claude Code or
  Cursor read the requirements the gate checks, write the fix and its tests, mark each requirement verified with the
  pull request as evidence (ledgered), and fetch the signed merge attestation. Walkthrough: `docs/MCP.md`. The Rovo agent
  also qualifies it for Best Agents.
- **AI tools used:** Claude Code (Claude) for pair programming and the eval harness; Forge LLMs (Claude) inside the app.
