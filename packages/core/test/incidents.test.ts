import { describe, expect, it } from 'vitest';
import { SitePolicySchema } from '@threatline/shared';
import { DEFAULT_INCIDENT_POLICY, DEFAULT_SITE_POLICY, incidentPolicyOf, isIncident, parseSitePolicy } from '../src/index.js';

describe('incident policy', () => {
  it('a stored policy without the incidents setting still parses, and reads as the defaults', () => {
    const { incidents: _none, ...legacy } = { ...DEFAULT_SITE_POLICY, incidents: undefined };
    expect(parseSitePolicy(legacy).ok).toBe(true);
    expect(incidentPolicyOf(legacy)).toEqual(DEFAULT_INCIDENT_POLICY);
    expect(DEFAULT_INCIDENT_POLICY).toEqual({ enabled: true, labels: ['incident'], issueTypes: ['Incident'], maxItems: 25, comment: true });
  });

  it('a saved setting is used as stored', () => {
    const incidents = { enabled: false, labels: ['sev1'], issueTypes: [], maxItems: 5, comment: false };
    const p = SitePolicySchema.parse({ ...DEFAULT_SITE_POLICY, incidents });
    expect(incidentPolicyOf(p)).toEqual(incidents);
  });

  it('refuses a cap outside 1..50, labels with spaces, and an enabled rule that matches nothing', () => {
    const bad = (incidents: unknown) => SitePolicySchema.safeParse({ ...DEFAULT_SITE_POLICY, incidents }).success;
    expect(bad({ ...DEFAULT_INCIDENT_POLICY, maxItems: 0 })).toBe(false);
    expect(bad({ ...DEFAULT_INCIDENT_POLICY, maxItems: 51 })).toBe(false);
    expect(bad({ ...DEFAULT_INCIDENT_POLICY, labels: ['two words'] })).toBe(false);
    expect(bad({ ...DEFAULT_INCIDENT_POLICY, labels: [], issueTypes: [] })).toBe(false);
    expect(bad({ ...DEFAULT_INCIDENT_POLICY, enabled: false, labels: [], issueTypes: [] })).toBe(true);
    expect(bad({ ...DEFAULT_INCIDENT_POLICY, extra: 1 })).toBe(false);
  });

  it('isIncident: the label (exact) or the work type (any case) makes a work item an incident', () => {
    const rule = DEFAULT_INCIDENT_POLICY;
    expect(isIncident({ labels: ['incident'], issueType: 'Task' }, rule)).toBe(true);
    expect(isIncident({ labels: [], issueType: 'Incident' }, rule)).toBe(true);
    expect(isIncident({ labels: [], issueType: 'incident' }, rule)).toBe(true);
    expect(isIncident({ labels: ['Incident-review'], issueType: 'Bug' }, rule)).toBe(false);
    expect(isIncident({ labels: ['INCIDENT'], issueType: 'Bug' }, rule)).toBe(false);
    expect(isIncident({ labels: [], issueType: 'Bug' }, { ...rule, issueTypes: [] })).toBe(false);
  });
});
