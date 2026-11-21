import type { IncidentPolicy, SitePolicy } from '@threatline/shared';

/** Incidents reopen reviews by default: `incident` label or Incident work type, 25 work items per incident, comment on. */
export const DEFAULT_INCIDENT_POLICY: IncidentPolicy = { enabled: true, labels: ['incident'], issueTypes: ['Incident'], maxItems: 25, comment: true };

/** The incident setting in force (sites saved before it existed have none stored, and get the defaults). */
export const incidentPolicyOf = (p: SitePolicy): IncidentPolicy => p.incidents ?? DEFAULT_INCIDENT_POLICY;

/** Is this work item an incident under the rule? Labels match exactly (as Jira stores them); work types in any case. */
export function isIncident(i: { labels: readonly string[]; issueType: string }, rule: Pick<IncidentPolicy, 'labels' | 'issueTypes'>): boolean {
  const type = i.issueType.toLowerCase();
  return i.labels.some((l) => rule.labels.includes(l)) || rule.issueTypes.some((t) => t.toLowerCase() === type);
}
