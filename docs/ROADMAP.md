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

## Next

1. **Does the pull request actually fix it?** The merge check reads the diff: did it touch the files the requirement
   points to, and add the tests its criteria imply? A "verified" requirement whose PR never touched the hinted code is
   flagged to a champion.
2. **Teamwork Graph memory.** "This pattern was exploited in INC-42 in another project": similar past threats,
   incidents and accepted risks across the organisation, as context for every review.
3. **Fix suggestions.** For each requirement, a suggested patch and test from the repository's own code, proposed as a
   pull request, never merged by Threatline.
4. **Marketplace listing**, with per-site model and budget controls.
