import { useRef, useState, type MouseEvent } from 'react';
import type { ApiError } from '../types.js';
import Button from '@atlaskit/button/new';
import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { errorText as errorTextOf, isError, type PanelApi } from '../bridge.js';
import { SeverityLozenge } from '../components/SeverityLozenge.js';
import type { PanelDto, Requirement, RequirementStatus } from '../types.js';
import { AcceptRiskModal } from './AcceptRiskModal.js';
import { CopyAttestation } from './CopyAttestation.js';
import { EvidenceForm } from './EvidenceForm.js';
import { ControlLozenges } from './ControlLozenges.js';
import { FixBy, TestSkeletonCopy } from './RequirementTools.js';
import { count } from '../text.js';
import { useFocusReturn } from '../components/inline-form.js';
import { field } from './form-styles.js';
import { useInFlight } from '../components/in-flight.js';

const STATUS_LABEL: Record<RequirementStatus, string> = {
  Open: 'Open',
  InProgress: 'In progress',
  Verified: 'Verified',
  AcceptedRisk: 'Accepted risk',
  NotApplicable: 'Not applicable',
};
const EVIDENCE_LABEL = { pr: 'PR', test: 'Test', confluence: 'Confluence', manual: 'Note', ci: 'CI' } as const;
const DONE: ReadonlySet<RequirementStatus> = new Set(['Verified', 'NotApplicable', 'AcceptedRisk']);
const linkStyle = { color: token('color.link') };

/** Verified from CI: a link to the run, and the repository and commit its tests passed on. */
function CiEvidence({ e }: { e: NonNullable<Requirement['evidence']> }) {
  const where = [e.repo, e.commitSha ? e.commitSha.slice(0, 12) : null].filter(Boolean).join(' @ ');
  return (
    <span style={{ font: token('font.body.small'), color: token('color.text.subtle') }}>
      Evidence: tests passed in CI —{' '}
      {e.ref.startsWith('https://') ? (
        <a href={e.ref} target="_blank" rel="noreferrer" style={linkStyle}>
          CI run
        </a>
      ) : (
        e.ref
      )}
      {where ? ` · ${where}` : null}
      {e.note ? ` (${e.note})` : null}
    </span>
  );
}

function EvidenceLine({ r }: { r: Requirement }) {
  if (!r.evidence) return null;
  if (r.evidence.kind === 'ci') return <CiEvidence e={r.evidence} />;
  const link = r.evidence.kind === 'pr' || r.evidence.kind === 'confluence';
  return (
    <span style={{ font: token('font.body.small'), color: token('color.text.subtle') }}>
      Evidence: {EVIDENCE_LABEL[r.evidence.kind]} —{' '}
      {link ? (
        <a href={r.evidence.ref} target="_blank" rel="noreferrer" style={{ color: token('color.link') }}>
          {r.evidence.ref}
        </a>
      ) : (
        r.evidence.ref
      )}
      {r.evidence.note ? ` (${r.evidence.note})` : null}
    </span>
  );
}

/** Requirements: create sub-tasks (RQ-2), move status, and verify with evidence (RQ-3, RQ-4). */
export function RequirementsTab({ dto, api, onChanged }: { dto: PanelDto; api: PanelApi; onChanged: () => void }) {
  const [notice, setNotice] = useState<string | null>(null);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [accepting, setAccepting] = useState<string | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const returnTo = useFocusReturn(accepting !== null || verifying !== null, root);
  const creating = useInFlight();
  const busy = creating.busy;
  /** Status changes, one at a time; the selects are disabled while one saves. */
  const saving = useInFlight();
  const canEdit = dto.roles.includes('developer');
  const champion = dto.roles.includes('champion');
  const missing = dto.requirements.filter((r) => !r.subtaskKey);
  const openAcceptance = new Set(dto.acceptances.filter((a) => a.state === 'pending' || a.state === 'active').map((a) => a.requirementId));

  const create = () =>
    creating.run(async () => {
      const r = await api.createRequirements(missing.map((x) => x.threatId)).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setNotice(errorTextOf(r));
      const keys = r.created.map((c) => c.subtaskKey);
      const failed = r.skipped.filter((s) => s.reason === 'failed').length;
      setNotice(`${keys.length > 0 ? `Created ${keys.join(', ')}.` : 'No new sub-tasks were needed.'}${failed > 0 ? ` ${failed} could not be created; try again.` : ''}`);
      onChanged();
    });

  const change = async (r: Requirement, status: RequirementStatus) => {
    if (saving.busy) return;
    if (status === 'Verified') return (returnTo(`[data-status="${r.id}"]`), setVerifying(r.id));
    setVerifying(null);
    await saving.run(async () => {
      const out = await api.setStatus(r.id, status).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(out)) setNotice(errorTextOf(out));
      else onChanged();
    });
  };

  /** Custom UI runs on Atlassian's CDN origin, so a relative /browse link must go through the Forge router to reach Jira. */
  const openIssue = (e: MouseEvent<HTMLAnchorElement>, key: string) => {
    if (!api.navigate) return;
    e.preventDefault();
    void api.navigate(`/browse/${key}`, { newTab: e.metaKey || e.ctrlKey || e.shiftKey }).catch(() => setNotice(`Could not open ${key}. Find it in Jira search.`));
  };

  return (
    <div ref={root} style={{ display: 'grid', gap: 8, paddingTop: 8, width: '100%' }}>
      <p role="status" style={{ margin: 0, minHeight: 0 }}>
        {notice}
      </p>
      {canEdit && missing.length > 0 && (
        <div>
          <Button appearance="primary" onClick={create} isDisabled={busy}>
            {`Create sub-tasks (${missing.length})`}
          </Button>
        </div>
      )}
      <ul aria-label="Security requirements" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
        {dto.requirements.length === 0 && <li style={{ color: token('color.text.subtle') }}>No requirements yet.</li>}
        {dto.hiddenRequirements > 0 && (
          <li style={{ color: token('color.text.subtlest'), font: token('font.body.small') }}>{count(dto.hiddenRequirements, 'requirement')} {dto.hiddenRequirements === 1 ? 'comes from a source' : 'come from sources'} you cannot open and {dto.hiddenRequirements === 1 ? 'is' : 'are'} not shown.</li>
        )}
        {dto.requirements.map((r) => (
          <li key={r.id} style={{ border: `1px solid ${token('color.border')}`, borderRadius: 6, padding: 10, display: 'grid', gap: 6 }}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
              <SeverityLozenge severity={r.severity} />
              <Lozenge appearance={DONE.has(r.status) ? 'success' : r.status === 'InProgress' ? 'inprogress' : 'default'}>{STATUS_LABEL[r.status]}</Lozenge>
              <strong>{r.title}</strong>
              <FixBy requirement={r} />
              {r.subtaskKey && (
                <a href={`/browse/${r.subtaskKey}`} target="_top" onClick={(e) => openIssue(e, r.subtaskKey!)} style={{ color: token('color.link') }}>
                  {r.subtaskKey}
                </a>
              )}
            </div>
            {r.criteria.slice(0, 1).map((c, i) => (
              <span key={i} style={{ color: token('color.text.subtle'), font: token('font.body.small') }}>
                Given {c.given}, when {c.when}, then {c.then}.
              </span>
            ))}
            <ControlLozenges controls={dto.requirementControls?.[r.id]} />
            <EvidenceLine r={r} />
            {(r.status === 'Open' || r.status === 'InProgress') && <TestSkeletonCopy requirement={r} />}
            {canEdit && r.status !== 'AcceptedRisk' && (
              <label style={{ display: 'flex', gap: 6, alignItems: 'center', font: token('font.body.small') }}>
                Status
                <select aria-label="Status" data-status={r.id} value={verifying === r.id ? 'Verified' : r.status} onChange={(e) => void change(r, e.target.value as RequirementStatus)} disabled={saving.busy} style={field}>
                  <option value="Open">Open</option>
                  <option value="InProgress">In progress</option>
                  <option value="Verified">Verified</option>
                  {(champion || r.status === 'NotApplicable') && <option value="NotApplicable">Not applicable</option>}
                </select>
              </label>
            )}
            {canEdit && (r.status === 'Open' || r.status === 'InProgress') && !openAcceptance.has(r.id) && accepting !== r.id && (
              <div>
                <Button spacing="compact" testId={`accept-${r.id}`} onClick={() => (returnTo(`[data-testid="accept-${r.id}"]`), setVerifying(null), setAccepting(r.id))}>
                  Accept risk
                </Button>
              </div>
            )}
            {accepting === r.id && <AcceptRiskModal requirement={r} dto={dto} api={api} onDone={onChanged} onCancel={() => setAccepting(null)} />}
            {verifying === r.id && (
              <EvidenceForm
                onCancel={() => setVerifying(null)}
                onSubmit={async (evidence) => {
                  const out = await api.setStatus(r.id, 'Verified', evidence).catch((): ApiError => ({ error: 'unavailable' }));
                  if (isError(out)) return errorTextOf(out);
                  setVerifying(null);
                  setNotice(`${r.subtaskKey ?? 'Requirement'} marked Verified.`);
                  onChanged();
                  return null;
                }}
              />
            )}
          </li>
        ))}
      </ul>
      {canEdit && <CopyAttestation api={api} />}
    </div>
  );
}
