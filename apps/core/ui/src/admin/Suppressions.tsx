import { useCallback, useEffect, useId, useState } from 'react';
import Button from '@atlaskit/button/new';
import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type AdminApi, type SuppressionInput } from '../bridge.js';
import type { ApiError, Stride, SuppressionRuleDto, SuppressionsDto } from '../types.js';
import { STRIDE_LABEL } from '../components/StrideIcon.js';
import { useInFlight } from '../components/in-flight.js';
import { box, errorText as errorStyle, field } from '../panel/form-styles.js';
import { count } from '../text.js';
import { h2, hint, intIn, Labeled, PolicyForm, sectionStyle, utc } from './policy-editor.js';

type Suggestion = SuppressionsDto['suggestions'][number];
const STRIDES = Object.keys(STRIDE_LABEL) as Stride[];
const REASON_WORDS: Record<string, string> = { false_positive: 'false positive', not_applicable: 'not applicable', already_mitigated: 'already mitigated', duplicate: 'duplicate' };
const small = { font: token('font.body.small'), color: token('color.text.subtle') } as const;

interface Draft {
  projectKey: string;
  stride: Stride;
  title: string;
  component: string;
  reason: string;
  days: string;
  evidence: string[];
}
const EMPTY: Draft = { projectKey: '', stride: 'InformationDisclosure', title: '', component: '', reason: '', days: '90', evidence: [] };
const fromSuggestion = (s: Suggestion, maxDays: number): Draft => ({
  projectKey: s.projectKey, stride: s.stride, title: s.title, component: s.component ?? '', reason: s.suggestedReason, days: String(maxDays), evidence: s.evidence.map((e) => e.issueKey),
});
const toInput = (d: Draft, days: number): SuppressionInput => ({
  projectKey: d.projectKey.trim().toUpperCase(), stride: d.stride, title: d.title.trim(), reason: d.reason.trim(), expiryDays: days,
  ...(d.component.trim() ? { component: d.component.trim() } : {}), ...(d.evidence.length > 0 ? { evidence: d.evidence } : {}),
});

/**
 * Team learning: a project's champion hides one kind of below-threshold threat in new reviews (at most 90 days, with a
 * reason). Suggestions come from dismissals on three or more work items. Every create and revoke is ledgered.
 */
export function Suppressions({ api }: { api: AdminApi }) {
  const id = useId();
  const [dto, setDto] = useState<SuppressionsDto | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [formError, setFormError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const saving = useInFlight();

  const load = useCallback(async () => {
    const r = await api.suppressions().catch((): ApiError => ({ error: 'unavailable' }));
    if (isError(r)) return setLoadError(errorText(r));
    setLoadError(null);
    setDto(r);
  }, [api]);
  useEffect(() => void load(), [load]);

  const maxDays = dto?.maxDays ?? 90;
  const create = async (d: Draft): Promise<string | null> => {
    const days = intIn(d.days, 1, maxDays);
    if (days === null) return `A rule lasts 1 to ${maxDays} days.`;
    if (!d.reason.trim()) return 'Write why this kind of threat does not apply to the project.';
    const r = await api.createSuppression(toInput(d, days)).catch((): ApiError => ({ error: 'unavailable' }));
    if (isError(r)) return errorText(r);
    setDone(`Rule created for ${r.projectKey}: it applies to new reviews until ${utc(r.expiresAt)}.`);
    await load();
    return null;
  };

  return (
    <section aria-labelledby={`${id}-h`} style={sectionStyle}>
      <h2 id={`${id}-h`} style={h2}>
        Suppressions
      </h2>
      <p style={hint}>
        A team rule hides one kind of threat in new reviews of a project, for at most {maxDays} days, with a reason. It never hides a threat at or above the
        blocking level, never applies when a review suspects prompt injection, and a security champion can unhide it on any work item. Every rule, revocation,
        expiry and unhide is recorded in the risk ledger, and the ops work item gets a monthly list of active rules to re-approve.
      </p>
      {loadError && (
        <p role="alert" style={errorStyle}>
          {loadError}
        </p>
      )}
      {dto && (
        <>
          <h3 style={{ margin: 0, font: token('font.heading.xsmall') }}>Suggested rules</h3>
          {dto.suggestions.length === 0 ? (
            <p style={hint}>No suggestions. Threatline suggests a rule when the same kind of threat is dismissed with a reason on 3 or more work items of a project within 90 days.</p>
          ) : (
            <ul aria-label="Suggested suppression rules" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
              {dto.suggestions.map((s) => (
                <SuggestionRow key={`${s.projectKey}|${s.stride}|${s.title}`} s={s} maxDays={maxDays} create={create} onEdit={() => (setDraft(fromSuggestion(s, maxDays)), setDone(null))} />
              ))}
            </ul>
          )}
          <h3 style={{ margin: 0, font: token('font.heading.xsmall') }}>Active rules</h3>
          {dto.rules.length === 0 ? (
            <p style={hint}>No active rules.</p>
          ) : (
            <ul aria-label="Active suppression rules" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
              {dto.rules.map((r) => (
                <RuleRow key={r.id} api={api} rule={r} onRevoked={() => void load()} />
              ))}
            </ul>
          )}
          <PolicyForm
            label="New suppression rule"
            error={formError}
            done={done}
            busy={saving.busy}
            submitLabel="Create rule"
            onSubmit={() =>
              void saving.run(async () => {
                setDone(null);
                const e = await create(draft);
                setFormError(e);
                if (!e) setDraft(EMPTY);
              })
            }
          >
            <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit, minmax(min(200px, 100%), 1fr))' }}>
              <Labeled text="Jira project key">{(fid) => <input id={fid} value={draft.projectKey} onChange={(e) => setDraft({ ...draft, projectKey: e.target.value })} style={field} />}</Labeled>
              <Labeled text="STRIDE category">
                {(fid) => (
                  <select id={fid} value={draft.stride} onChange={(e) => setDraft({ ...draft, stride: e.target.value as Stride })} style={field}>
                    {STRIDES.map((s) => (
                      <option key={s} value={s}>
                        {STRIDE_LABEL[s]}
                      </option>
                    ))}
                  </select>
                )}
              </Labeled>
              <Labeled text={`Days (1 to ${maxDays})`}>{(fid) => <input id={fid} type="number" min={1} max={maxDays} value={draft.days} onChange={(e) => setDraft({ ...draft, days: e.target.value })} style={field} />}</Labeled>
            </div>
            <Labeled text="Threat title (similar titles match)">{(fid) => <input id={fid} value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} style={field} />}</Labeled>
            <Labeled text="Component (optional: only threats on this component)">{(fid) => <input id={fid} value={draft.component} onChange={(e) => setDraft({ ...draft, component: e.target.value })} style={field} />}</Labeled>
            <Labeled text="Reason">{(fid) => <textarea id={fid} rows={2} value={draft.reason} onChange={(e) => setDraft({ ...draft, reason: e.target.value })} style={field} />}</Labeled>
            {draft.evidence.length > 0 && <p style={small}>Evidence: dismissals on {draft.evidence.join(', ')}.</p>}
          </PolicyForm>
        </>
      )}
    </section>
  );
}

function SuggestionRow({ s, maxDays, create, onEdit }: { s: Suggestion; maxDays: number; create: (d: Draft) => Promise<string | null>; onEdit: () => void }) {
  const { busy, run } = useInFlight();
  const [error, setError] = useState<string | null>(null);
  const name = `${s.projectKey}: ${s.title}`;
  return (
    <li style={{ ...box, margin: 0 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Lozenge appearance="new">{s.projectKey}</Lozenge>
        <strong>{s.title}</strong>
        <span style={small}>
          {STRIDE_LABEL[s.stride]}
          {s.component ? `, ${s.component}` : ''} · dismissed on {count(s.workItems, 'work item')}
        </span>
      </div>
      <ul aria-label={`Evidence for ${name}`} style={{ margin: 0, paddingLeft: 18, ...small }}>
        {s.evidence.map((e, i) => (
          <li key={`${e.issueKey}-${i}`}>
            {e.issueKey}: “{e.title}”, {REASON_WORDS[e.reason] ?? e.reason}, {e.at.slice(0, 10)}
          </li>
        ))}
      </ul>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <Button appearance="primary" isDisabled={busy} aria-label={`Create rule: ${name}`} onClick={() => void run(async () => setError(await create(fromSuggestion(s, maxDays))))}>
          {`Create rule (${maxDays} days)`}
        </Button>
        <Button appearance="subtle" aria-label={`Edit first: ${name}`} onClick={onEdit}>
          Edit first
        </Button>
        <span style={small}>Reason: {s.suggestedReason}</span>
      </div>
      {error && (
        <p role="alert" style={errorStyle}>
          {error}
        </p>
      )}
    </li>
  );
}

function RuleRow({ api, rule, onRevoked }: { api: AdminApi; rule: SuppressionRuleDto; onRevoked: () => void }) {
  const { busy, run } = useInFlight();
  const [revoking, setRevoking] = useState(false);
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const name = `${rule.projectKey}: ${rule.title}`;
  const revoke = () =>
    run(async () => {
      const r = await api.revokeSuppression(rule.id, reason.trim()).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setError(errorText(r));
      setError(null);
      onRevoked();
    });
  return (
    <li style={{ ...box, margin: 0 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Lozenge appearance="moved">{rule.projectKey}</Lozenge>
        <strong>{rule.title}</strong>
        <span style={small}>
          {STRIDE_LABEL[rule.stride]}
          {rule.component ? `, ${rule.component}` : ''} · hid threats on {count(rule.matches, 'work item')} · expires {utc(rule.expiresAt)}
        </span>
      </div>
      <span style={small}>
        Reason: {rule.reason} (by {rule.createdBy}, {rule.createdAt.slice(0, 10)}
        {rule.evidence.length > 0 ? `; evidence ${rule.evidence.join(', ')}` : ''})
      </span>
      {!revoking ? (
        <div>
          <Button aria-label={`Revoke ${name}`} onClick={() => setRevoking(true)}>
            Revoke
          </Button>
        </div>
      ) : (
        <form
          aria-label={`Revoke ${name}`}
          noValidate
          style={{ display: 'flex', gap: 8, alignItems: 'end', flexWrap: 'wrap' }}
          onSubmit={(e) => {
            e.preventDefault();
            void revoke();
          }}
        >
          <Labeled text="Why revoke it">{(fid) => <input id={fid} value={reason} onChange={(e) => setReason(e.target.value)} style={{ ...field, minWidth: 240 }} />}</Labeled>
          <Button type="submit" appearance="warning" isDisabled={busy}>
            Confirm revoke
          </Button>
          <Button appearance="subtle" onClick={() => setRevoking(false)}>
            Cancel
          </Button>
        </form>
      )}
      {error && (
        <p role="alert" style={errorStyle}>
          {error}
        </p>
      )}
    </li>
  );
}
