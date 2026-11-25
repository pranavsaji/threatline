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

## Next

1. **Does the pull request actually fix it?** The merge check reads the diff: did it touch the files the requirement
   points to, and add the tests its criteria imply? A "verified" requirement whose PR never touched the hinted code is
   flagged to a champion.
2. **Teamwork Graph memory.** Seen before reads Jira and Threatline's own history today. Next: incidents and
   postmortems from connected tools (Jira Service Management, Opsgenie, Confluence) and code ownership through Teamwork
   Graph, the same CWE on recently shipped work, and the history as context for the review itself.
3. **Fix suggestions.** For each requirement, a suggested patch and test from the repository's own code, proposed as a
   pull request, never merged by Threatline.
4. **Marketplace listing**, with per-site model and budget controls.
