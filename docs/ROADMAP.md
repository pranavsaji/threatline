# Roadmap

Ranked by how much each widens the gap between "a security checklist" and "security that ships with the code".

## Shipped

- **Verification from CI** ([docs](CI_VERIFICATION.md)): tests named after a requirement pass in CI and close it, with
  the run as evidence.
- **Champion inbox** ([docs](CHAMPION_INBOX.md)): one queue across projects, grouped, bulk decisions.
- **Incidents reopen reviews** ([docs](INCIDENTS.md)): an incident on a component re-reviews the open work there.
- **Data-flow diagrams** ([docs](DIAGRAM.md)): each review's architecture with its threats pinned to it.
- **Team-level learning** ([docs](SUPPRESSIONS.md)): repeated dismissals become champion-approved, expiring rules that
  never hide a blocking threat.
- **Compliance evidence** ([docs](COMPLIANCE.md)): indicative SOC 2, ISO 27001 and PCI DSS control mapping, posture view
  and export.
- **Seen before** ([docs](MEMORY.md)), the first step of organisational memory: under each threat, past incidents that
  match it and the same threat on other work items, verified (with the pull request), risk-accepted (until when) or
  dismissed as a false positive; "This happened before: INC-7" in the headline when a blocking threat was an incident.
  Built from Jira incident searches and Threatline's own reviews in Forge SQL, with deterministic matching that states
  its reason, and filtered to what each viewer may open. Also in the Rovo agent's and MCP `explain-threat`.
- **Turn requirements into tasks**: one primary action under the panel's headline creates the Jira work items for every
  open requirement and links the new keys.

- **Does the pull request actually fix it?** ([docs](FIX_CHECK.md)) CI sends the pull request's change; Threatline
  Engine says, per requirement, fixed, partly fixed or not addressed, quoting the added lines that enforce it (each
  quote checked against the diff by code). A verified requirement the change does not show is fixed waits for a
  champion before Done or merge. Anything not fixed comes with what is still missing and a suggested change.
- **Past incidents in the review itself** ([docs](MEMORY.md#in-the-review)): the gap check walks each past incident in
  the review context and asks whether this design repeats it.

## Next

1. **Teamwork Graph memory.** Seen before and the gap check read Jira and Threatline's own history today. Next:
   incidents and postmortems from connected tools (Jira Service Management, Opsgenie, Confluence) and code ownership
   through Teamwork Graph, and the same CWE on recently shipped work.
2. **Fix pull requests.** The fix check already writes a suggested change for each requirement still open; next, open
   it as a pull request on request (never merged by Threatline).
3. **Marketplace listing**, with per-site model and budget controls.
