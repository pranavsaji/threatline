# Team suppression rules

A dismissal with a reason applies to one work item (and to its re-runs). When a team keeps dismissing the same false
positive on every new story, a security champion can turn that into a **project rule**: in new reviews of the project,
a matching threat below the blocking level is hidden, with the rule and its reason shown in the panel.

## Suggestions

**Threatline admin → Suppressions** suggests a rule when the same kind of threat (same STRIDE category, similar title,
the similarity Threatline uses for consensus) was dismissed with a reason on **3 or more different work items of a
project in the last 90 days**. A dismissal as a duplicate does not count. The dismissals are listed as evidence;
**Create rule** creates it as suggested, **Edit first** fills the form. Dismissals recorded before migration v7 carry no
work item and feed no suggestion.

## Rules

A rule names a project, a STRIDE category, a title (threats with a similar title match), optionally a component, a
reason (required) and an expiry (1 to 90 days, 90 by default). Security champions and Jira administrators create and
revoke rules. At most 50 active rules per project. Every create, revoke, expiry and unhide is in the risk ledger
(`suppression.created`, `.revoked`, `.expired`, `.unhidden`); a rule whose creation could not be ledgered never
applies. The hourly job expires rules (an expired rule never applies, even before that), and once a month the daily
job lists the active rules on the ops work item for re-approval.

## What a rule does at assembly

- A matching threat **below** the blocking level becomes `suppressed`: it is not scored and has no requirement, so it
  cannot affect the verdict. An untouched requirement an earlier revision gave it is removed. Rule-based threats are
  hidden the same way.
- A matching threat **at or above** the blocking level is never hidden. It stays as it was, and the panel notes that the
  rule matched but cannot hide a blocking threat.
- When injection is suspected anywhere in the material (scanner or quarantined check), no rule applies.
- A hidden AI threat covers nothing, so the rule-based threat it would have covered stays active.
- A suppressed threat is not carried to the next revision as a decision: rules are applied afresh each time.
- If the rules cannot be read, the review applies none (every threat stays shown).
- The gate re-checks every stored suppression: a `suppressed` threat counts as the state it had once its severity is
  at or above the current blocking level (for example after the policy is lowered), once its rule's expiry has passed,
  or once its rule is no longer active (revoked; or the active rules could not be read). A hidden threat cannot be
  triaged until a champion unhides it.
- Suggestions and their evidence only use dismissals on work items the viewer can browse, of threats whose every cited
  source the viewer can open (the panel's rule).

In the panel a hidden threat reads "Hidden by team rule: *reason* (expires *date*; rule *id*)". A champion can
**Unhide here**: the work item's threats hidden by that rule come back with their requirements, the verdict is
recomputed, and later reviews of that work item leave them shown. Other work items keep the rule.

The offline eval passes no rules, so its replay is unchanged.
