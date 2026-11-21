import { useId, useState } from 'react';
import type { SitePolicy } from '../types.js';
import { field } from '../panel/form-styles.js';
import { grid2, hint, h2, intIn, Labeled, PolicyForm, sectionStyle, splitList, usePolicySave, type PolicySectionProps } from './policy-editor.js';

type IncidentPolicy = NonNullable<SitePolicy['incidents']>;
/** The server's defaults for a site that has not saved this setting (DEFAULT_INCIDENT_POLICY in @threatline/core). */
export const INCIDENT_DEFAULTS: IncidentPolicy = { enabled: true, labels: ['incident'], issueTypes: ['Incident'], maxItems: 25, comment: true };

const check = { display: 'flex', gap: 6, alignItems: 'center' } as const;

/** Incidents reopen reviews: whether they do, what counts as an incident, how many work items one may reopen. */
export function Incidents(props: PolicySectionProps) {
  const id = useId();
  const current = props.policy.incidents ?? INCIDENT_DEFAULTS;
  const [enabled, setEnabled] = useState(current.enabled);
  const [labels, setLabels] = useState(current.labels.join(', '));
  const [types, setTypes] = useState(current.issueTypes.join(', '));
  const [max, setMax] = useState(String(current.maxItems));
  const [comment, setComment] = useState(current.comment);
  const s = usePolicySave(props);

  const submit = () => {
    const maxItems = intIn(max, 1, 50);
    if (maxItems === null) return s.fail('An incident re-reviews 1 to 50 work items.');
    const l = splitList(labels);
    if (l.some((x) => /\s/.test(x))) return s.fail('A Jira label has no spaces.');
    const issueTypes = splitList(types);
    if (enabled && l.length + issueTypes.length === 0) return s.fail('Name at least one incident label or work type.');
    void s.save({ incidents: { enabled, labels: l, issueTypes, maxItems, comment } });
  };

  return (
    <section aria-labelledby={`${id}-h`} style={sectionStyle}>
      <h2 id={`${id}-h`} style={h2}>
        Incidents
      </h2>
      <p style={hint}>
        When an incident is raised on a component, or linked to a work item, the open work items there that already have a review are re-reviewed with the incident as context.
        Re-reviews count towards the monthly review budget.
      </p>
      <PolicyForm label="Incidents" submitLabel="Save incident settings" onSubmit={submit} {...s}>
        <label style={check}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Incidents reopen reviews
        </label>
        <div style={grid2}>
          <Labeled text="Incident labels (comma-separated)">{(fid) => <input id={fid} value={labels} onChange={(e) => setLabels(e.target.value)} spellCheck={false} style={field} />}</Labeled>
          <Labeled text="Incident work types (comma-separated)">{(fid) => <input id={fid} value={types} onChange={(e) => setTypes(e.target.value)} style={field} />}</Labeled>
          <Labeled text="Most work items re-reviewed per incident">{(fid) => <input id={fid} type="number" min={1} max={50} value={max} onChange={(e) => setMax(e.target.value)} style={field} />}</Labeled>
        </div>
        <label style={check}>
          <input type="checkbox" checked={comment} onChange={(e) => setComment(e.target.checked)} />
          Comment on the incident with the work items re-reviewed
        </label>
        <span style={hint}>A work item is an incident when it has one of these labels or is one of these work types. Newest work items are re-reviewed first.</span>
      </PolicyForm>
    </section>
  );
}
