import { useId, useRef, useState, type FormEvent } from 'react';
import type { ApiError } from '../types.js';
import Button from '@atlaskit/button/new';
import { errorText as errorTextOf, isError, type PanelApi, type TriageInput } from '../bridge.js';
import type { Threat } from '../types.js';
import { box, errorText, field, label } from './form-styles.js';
import { useFocusReturn, useInlineForm } from '../components/inline-form.js';
import { useInFlight } from '../components/in-flight.js';

type Action = 'accept' | 'dismiss' | 'edit' | 'merge' | 'split';
/** Dismissal reason codes, as the panel and the champion inbox offer them. */
export const DISMISS_REASONS = [
  ['false_positive', 'False positive'],
  ['not_applicable', 'Not applicable'],
  ['duplicate', 'Duplicate'],
  ['already_mitigated', 'Already mitigated'],
] as const;
const SCORES = [1, 2, 3, 4, 5];

/** TM-7: a security champion accepts, dismisses (with a reason code), edits, merges or splits a threat. */
export function ThreatEditor({ threat, others, api, onDone, onCancel }: { threat: Threat; others: Threat[]; api: PanelApi; onDone: () => void; onCancel: () => void }) {
  const id = useId();
  const [action, setAction] = useState<Action>(threat.state === 'accepted' ? 'dismiss' : 'accept');
  const [reason, setReason] = useState('');
  const [note, setNote] = useState('');
  const [title, setTitle] = useState(threat.title);
  const [likelihood, setLikelihood] = useState(threat.likelihood);
  const [impact, setImpact] = useState(threat.impact);
  const [into, setInto] = useState('');
  const [parts, setParts] = useState(['', '']);
  const [error, setError] = useState<string | null>(null);
  const { busy: saving, run } = useInFlight();
  const form = useInlineForm(onCancel);

  const build = (): TriageInput | string => {
    const threatId = threat.id;
    switch (action) {
      case 'accept':
        return { threatId, op: 'accept' };
      case 'dismiss':
        if (!reason) return 'Choose a reason.';
        return { threatId, op: 'dismiss', reason, ...(note.trim() ? { note: note.trim() } : {}) };
      case 'edit': {
        const patch: Extract<TriageInput, { op: 'edit' }>['patch'] = {};
        if (title.trim() && title.trim() !== threat.title) patch.title = title.trim();
        if (likelihood !== threat.likelihood) patch.likelihood = likelihood;
        if (impact !== threat.impact) patch.impact = impact;
        return Object.keys(patch).length > 0 ? { threatId, op: 'edit', patch } : 'Change something first.';
      }
      case 'merge':
        return into ? { threatId, op: 'merge', intoThreatId: into } : 'Choose the threat to merge into.';
      case 'split': {
        const titles = parts.map((p) => p.trim()).filter(Boolean);
        return titles.length >= 2 ? { threatId, op: 'split', parts: titles.map((t) => ({ title: t })) } : 'Give at least two parts a title.';
      }
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const input = build();
    if (typeof input === 'string') return setError(input);
    await run(async () => {
      const r = await api.triage(input).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setError(errorTextOf(r));
      setError(null);
      onDone();
    });
  };

  const select = (name: string, value: string | number, onChange: (v: string) => void, options: Array<readonly [string | number, string]>) => (
    <label style={label}>
      {name}
      <select aria-label={name} value={value} onChange={(e) => onChange(e.target.value)} style={field}>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <form ref={form.ref} onKeyDown={form.onKeyDown} aria-label="Triage threat" onSubmit={submit} style={box}>
      {select('Action', action, (v) => setAction(v as Action), [
        ...(threat.state !== 'accepted' ? ([['accept', 'Accept']] as const) : []),
        ['dismiss', 'Dismiss'],
        ['edit', 'Edit'],
        ...(others.length > 0 ? ([['merge', 'Merge into another threat']] as const) : []),
        ['split', 'Split into parts'],
      ])}
      {action === 'dismiss' && (
        <>
          {select('Reason', reason, setReason, [['', 'Choose a reason…'], ...DISMISS_REASONS])}
          <label style={label} htmlFor={`${id}-note`}>
            Note (optional)
          </label>
          <textarea id={`${id}-note`} value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={500} style={field} />
        </>
      )}
      {action === 'edit' && (
        <>
          <label style={label} htmlFor={`${id}-title`}>
            Title
          </label>
          <input id={`${id}-title`} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} style={field} />
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {select('Likelihood', likelihood, (v) => setLikelihood(Number(v)), SCORES.map((s) => [s, String(s)] as const))}
            {select('Impact', impact, (v) => setImpact(Number(v)), SCORES.map((s) => [s, String(s)] as const))}
          </div>
        </>
      )}
      {action === 'merge' && select('Merge into', into, setInto, [['', 'Choose a threat…'], ...others.map((o) => [o.id, o.title] as const)])}
      {action === 'split' &&
        parts.map((p, i) => (
          <label key={i} style={label}>
            {`Part ${i + 1} title`}
            <input value={p} onChange={(e) => setParts(parts.map((x, j) => (j === i ? e.target.value : x)))} maxLength={200} style={field} />
          </label>
        ))}
      {action === 'split' && parts.length < 5 && (
        <div>
          <Button appearance="subtle" onClick={() => setParts([...parts, ''])}>
            Add a part
          </Button>
        </div>
      )}
      {error && (
        <p role="alert" style={errorText}>
          {error}
        </p>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <Button type="submit" appearance="primary" isDisabled={saving}>
          Apply
        </Button>
        <Button onClick={onCancel}>Cancel</Button>
      </div>
    </form>
  );
}

/** The "Triage" toggle shown on each threat card for champions. */
export function ThreatTriage(props: { threat: Threat; others: Threat[]; api: PanelApi; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const returnTo = useFocusReturn(open, root);
  return (
    <div ref={root} style={{ display: 'grid', gap: 8 }}>
      <div>
        <Button appearance="subtle" aria-expanded={open} onClick={() => (returnTo('button[aria-expanded]'), setOpen(!open))}>
          Triage
        </Button>
      </div>
      {open && (
        <ThreatEditor
          {...props}
          onCancel={() => setOpen(false)}
          onDone={() => {
            setOpen(false);
            props.onDone();
          }}
        />
      )}
    </div>
  );
}
