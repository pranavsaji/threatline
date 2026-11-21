import { useCallback, useEffect, useId, useMemo, useRef, useState, type FormEvent } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type InboxApi, type InboxDecisionInput } from '../bridge.js';
import type { ApiError, InboxCluster, InboxDto, InboxItemResult, InboxRow } from '../types.js';
import { SeverityLozenge } from '../components/SeverityLozenge.js';
import { STRIDE_LABEL, StrideIcon } from '../components/StrideIcon.js';
import { useInFlight } from '../components/in-flight.js';
import { useInlineForm } from '../components/inline-form.js';
import { DISMISS_REASONS } from '../panel/ThreatEditor.js';
import { box, errorText as errorStyle, field, label } from '../panel/form-styles.js';
import { count } from '../text.js';

/** The server decides at most this many per call; a larger selection goes in batches. */
export const DECIDE_BATCH = 25;

export const SHORTCUTS: ReadonlyArray<readonly [string, string]> = [
  ['j', 'Next threat'],
  ['k', 'Previous threat'],
  ['x', 'Select or clear the current threat'],
  ['c', 'Confirm the selected threats (or the current one)'],
  ['d', 'Dismiss the selected threats (or the current one), with a reason'],
  ['?', 'Show or hide these shortcuts'],
];

type Key = string;
const keyOf = (r: Pick<InboxRow, 'issueId' | 'threatId'>): Key => `${r.issueId}|${r.threatId}`;

/** Typing in a text field, a list box or an editor: shortcuts stay off. Checkboxes and buttons are not typing. */
function isTyping(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  if (el.isContentEditable || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') return true;
  return el.tagName === 'INPUT' && !['checkbox', 'radio', 'button', 'submit', 'reset'].includes((el as HTMLInputElement).type);
}

const waiting = (now: string, at: string) => {
  const d = Math.max(0, Math.floor((Date.parse(now) - Date.parse(at)) / 86_400_000));
  return d === 0 ? 'Waiting since today' : `Waiting ${count(d, 'day')}`;
};

const clusterLabel = (c: InboxCluster) =>
  c.kind === 'duplicate'
    ? `${count(c.rows.length, 'threat')} on ${c.rows[0]!.issueKey} the verifier marked as duplicates`
    : `${count(c.rows.length, 'similar threat')} on ${count(new Set(c.rows.map((r) => r.issueId)).size, 'work item')}`;

const subtle = { color: token('color.text.subtle'), font: token('font.body.small') };
const link = { color: token('color.link'), textDecoration: 'underline', textUnderlineOffset: 2 };

function DismissForm({ n, busy, onSubmit, onCancel }: { n: number; busy: boolean; onSubmit: (reason: string, note: string) => void; onCancel: () => void }) {
  const id = useId();
  const [reason, setReason] = useState('');
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);
  const form = useInlineForm(onCancel);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!reason) return setError('Choose a reason.');
    setError(null);
    onSubmit(reason, note.trim());
  };
  return (
    <form ref={form.ref} onKeyDown={form.onKeyDown} aria-label="Dismiss threats" onSubmit={submit} style={box}>
      <label style={label}>
        Reason
        <select aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} style={field}>
          {[['', 'Choose a reason…'] as const, ...DISMISS_REASONS].map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </label>
      <label style={label} htmlFor={`${id}-note`}>
        Note (optional)
      </label>
      <textarea id={`${id}-note`} value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={500} style={field} />
      {error && (
        <p role="alert" style={errorStyle}>
          {error}
        </p>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <Button type="submit" appearance="primary" isDisabled={busy}>
          {`Dismiss ${count(n, 'threat')}`}
        </Button>
        <Button onClick={onCancel}>Cancel</Button>
      </div>
    </form>
  );
}

/**
 * One queue for security champions: every threat waiting for a person across the projects they can see, most urgent
 * first, grouped where the verifier marked duplicates or similar threats appear on several work items. Confirm accepts
 * a threat (it becomes a requirement); dismiss needs a reason. Each decision is made and ledgered on the server, one by
 * one, and failures are listed per threat.
 */
export function ChampionInbox({ api, initial, onLoaded }: { api: InboxApi; initial?: InboxDto; onLoaded?: (dto: InboxDto) => void }) {
  const id = useId();
  const [dto, setDto] = useState<InboxDto | null>(initial ?? null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<Key>>(new Set());
  const [active, setActive] = useState(0);
  const [dismissing, setDismissing] = useState<Key[] | null>(null);
  const [outcome, setOutcome] = useState<{ text: string; failures: string[] } | null>(null);
  const [help, setHelp] = useState(false);
  const { busy, run } = useInFlight();
  const more = useInFlight();
  const rowEls = useRef(new Map<Key, HTMLLIElement>());

  const rows = useMemo(() => dto?.clusters.flatMap((c) => c.rows) ?? [], [dto]);
  const byKey = useMemo(() => new Map(rows.map((r) => [keyOf(r), r])), [rows]);

  const current = useRef(dto);
  current.current = dto;
  const load = useCallback(
    async (cursor: number) => {
      const r = await api.list(cursor).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setError(errorText(r));
      const prev = current.current;
      const next = cursor > 0 && prev ? { ...r, clusters: [...prev.clusters, ...r.clusters] } : r;
      setError(null);
      setDto(next);
      onLoaded?.(next);
    },
    [api, onLoaded],
  );

  // The first page comes from the parent when it already has it.
  const loadedFirst = useRef(Boolean(initial));
  useEffect(() => {
    if (loadedFirst.current) return;
    loadedFirst.current = true;
    void load(0);
  }, [load]);

  useEffect(() => {
    if (active >= rows.length && rows.length > 0) setActive(rows.length - 1);
  }, [active, rows.length]);

  const focusRow = (i: number) => {
    const r = rows[i];
    if (!r) return;
    setActive(i);
    rowEls.current.get(keyOf(r))?.focus();
  };
  const toggle = (k: Key) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });
  /** What a bulk action applies to: the selection, or else the current threat. */
  const targets = (): Key[] => {
    const sel = [...selected].filter((k) => byKey.has(k));
    if (sel.length > 0) return sel;
    const r = rows[active];
    return r ? [keyOf(r)] : [];
  };

  const decide = (keys: Key[], input: { decision: 'confirm' } | { decision: 'dismiss'; reason: string; note?: string }) =>
    run(async () => {
      const items = keys.flatMap((k) => (byKey.has(k) ? [{ issueId: byKey.get(k)!.issueId, threatId: byKey.get(k)!.threatId }] : []));
      const results: InboxItemResult[] = [];
      for (let i = 0; i < items.length; i += DECIDE_BATCH) {
        const batch = items.slice(i, i + DECIDE_BATCH);
        const r = await api.decide({ ...input, items: batch } as InboxDecisionInput).catch((): ApiError => ({ error: 'unavailable' }));
        if (isError(r)) results.push(...batch.map((b): InboxItemResult => ({ ...b, ok: false, error: r.error, message: errorText(r) })));
        else results.push(...r.results);
      }
      const done = results.filter((r) => r.ok);
      const failed = results.flatMap((r) => (r.ok ? [] : [r]));
      const verb = input.decision === 'confirm' ? 'Confirmed' : 'Dismissed';
      setOutcome({
        text: `${verb} ${count(done.length, 'threat')}.${failed.length ? ` ${count(failed.length, 'threat')} could not be ${input.decision === 'confirm' ? 'confirmed' : 'dismissed'}.` : ''}`,
        failures: failed.map((f) => {
          const row = byKey.get(keyOf(f));
          return `${row ? `${row.issueKey} · ${row.title}` : f.threatId}: ${f.message ?? errorText({ error: f.error })}`;
        }),
      });
      const gone = new Set(done.map(keyOf));
      setSelected((s) => new Set([...s].filter((k) => !gone.has(k))));
      setDismissing(null);
      await load(0);
    });

  const confirm = (keys: Key[]) => keys.length > 0 && void decide(keys, { decision: 'confirm' });
  const openDismiss = (keys: Key[]) => keys.length > 0 && setDismissing(keys);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey || isTyping(e.target)) return;
      if (e.key === '?') {
        e.preventDefault();
        return setHelp((h) => !h);
      }
      // While a dismissal is being written or a decision is in flight, only the help key works.
      if (dismissing || busy || rows.length === 0) return;
      const handled = (() => {
        switch (e.key) {
          case 'j':
            return focusRow(Math.min(rows.length - 1, active + 1)), true;
          case 'k':
            return focusRow(Math.max(0, active - 1)), true;
          case 'x': {
            const r = rows[active];
            return r ? (toggle(keyOf(r)), true) : false;
          }
          case 'c':
            return confirm(targets()), true;
          case 'd':
            return openDismiss(targets()), true;
          default:
            return false;
        }
      })();
      if (handled) e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  if (!dto)
    return error ? (
      <div role="alert" style={{ display: 'grid', gap: 8, justifyItems: 'start' }}>
        <p style={{ margin: 0 }}>{error}</p>
        <Button onClick={() => void load(0)}>Try again</Button>
      </div>
    ) : (
      <p role="status" aria-label="Loading the champion inbox" style={{ margin: 0 }}>
        Loading the champion inbox…
      </p>
    );

  const sel = [...selected].filter((k) => byKey.has(k));
  let index = 0;
  return (
    <section aria-labelledby={`${id}-h`} style={{ display: 'grid', gap: 12, minWidth: 0 }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <h1 id={`${id}-h`} style={{ margin: 0, font: token('font.heading.medium') }}>
          Champion inbox
        </h1>
        <Button appearance="subtle" aria-expanded={help} onClick={() => setHelp(!help)}>
          Keyboard shortcuts
        </Button>
      </div>
      <p style={{ margin: 0 }}>
        {dto.total === 0 ? 'Nothing is waiting for a security champion.' : `${count(dto.total, 'threat')} waiting for a security champion, most severe and oldest first.`}
        {dto.hidden > 0 && ` ${count(dto.hidden, 'more threat')} ${dto.hidden === 1 ? 'rests' : 'rest'} only on sources you cannot open.`}
        {dto.truncated && ' Only the most urgent are listed; decide these to see the rest.'}
      </p>
      {help && (
        <ul aria-label="Keyboard shortcuts" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 2 }}>
          {SHORTCUTS.map(([k, what]) => (
            <li key={k}>
              <kbd style={{ font: token('font.code'), padding: '0 4px', border: `1px solid ${token('color.border')}`, borderRadius: 3 }}>{k}</kbd> {what}
            </li>
          ))}
          <li>Shortcuts are off while you type in a field.</li>
        </ul>
      )}
      <div role="status" aria-live="polite">
        {outcome && <p style={{ margin: 0 }}>{outcome.text}</p>}
      </div>
      {outcome && outcome.failures.length > 0 && (
        <div role="alert">
          <ul aria-label="Decisions that failed" style={{ margin: 0, paddingLeft: 18 }}>
            {outcome.failures.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        </div>
      )}
      {error && (
        <p role="alert" style={{ margin: 0 }}>
          {error}
        </p>
      )}
      {rows.length > 0 && (
        <div role="group" aria-label="Selected threats" style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <span>{`${sel.length} selected`}</span>
          <Button isDisabled={sel.length === 0 || busy} onClick={() => confirm(sel)}>
            Confirm selected
          </Button>
          <Button isDisabled={sel.length === 0 || busy} onClick={() => openDismiss(sel)}>
            Dismiss selected
          </Button>
          {sel.length > 0 && (
            <Button appearance="subtle" onClick={() => setSelected(new Set())}>
              Clear selection
            </Button>
          )}
        </div>
      )}
      {dismissing && (
        <DismissForm
          n={dismissing.length}
          busy={busy}
          onCancel={() => setDismissing(null)}
          onSubmit={(reason, note) => void decide(dismissing, { decision: 'dismiss', reason, ...(note ? { note } : {}) })}
        />
      )}
      {dto.clusters.map((c) => {
        const keys = c.rows.map(keyOf);
        const all = keys.every((k) => selected.has(k));
        return (
          <section key={c.id} aria-label={c.kind === 'single' ? c.rows[0]!.title : clusterLabel(c)} style={{ display: 'grid', gap: 6, padding: 8, borderRadius: 6, border: `1px solid ${token('color.border')}` }}>
            {c.kind !== 'single' && (
              <label style={{ display: 'flex', gap: 8, alignItems: 'center', font: token('font.body.small') }}>
                <input
                  type="checkbox"
                  checked={all}
                  onChange={() => setSelected((s) => (all ? new Set([...s].filter((k) => !keys.includes(k))) : new Set([...s, ...keys])))}
                />
                {`Select all ${c.rows.length}: ${clusterLabel(c)}`}
              </label>
            )}
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
              {c.rows.map((r) => {
                const i = index++;
                const k = keyOf(r);
                const current = i === active;
                return (
                  <li
                    key={k}
                    ref={(el) => void (el ? rowEls.current.set(k, el) : rowEls.current.delete(k))}
                    tabIndex={-1}
                    aria-current={current ? 'true' : undefined}
                    onFocus={() => setActive(i)}
                    style={{
                      display: 'flex', gap: 10, alignItems: 'flex-start', padding: 8, borderRadius: 4,
                      outline: current ? `2px solid ${token('color.border.focused')}` : 'none',
                      background: selected.has(k) ? token('color.background.selected') : 'transparent',
                    }}
                  >
                    <input type="checkbox" aria-label={`Select ${r.title} on ${r.issueKey}`} checked={selected.has(k)} onChange={() => toggle(k)} style={{ marginTop: 4 }} />
                    <div style={{ display: 'grid', gap: 4, flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <a href={r.url} target="_top" style={link}>
                          {r.issueKey}
                        </a>
                        <span style={subtle}>{r.summary}</span>
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <StrideIcon stride={r.stride} />
                        <strong>{r.title}</strong>
                        <SeverityLozenge severity={r.severity} />
                        <span style={subtle}>{STRIDE_LABEL[r.stride]}</span>
                      </div>
                      {r.plainLanguage && <p style={{ margin: 0 }}>{r.plainLanguage}</p>}
                      {r.reasons.map((x) => (
                        <p key={x.code} style={{ margin: 0, ...subtle }}>
                          {x.message}
                        </p>
                      ))}
                      <span style={subtle}>{waiting(dto.now, r.raisedAt)}</span>
                    </div>
                    <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                      <Button spacing="compact" isDisabled={busy} aria-label={`Confirm ${r.title} on ${r.issueKey}`} onClick={() => confirm([k])}>
                        Confirm
                      </Button>
                      <Button spacing="compact" isDisabled={busy} aria-label={`Dismiss ${r.title} on ${r.issueKey}`} onClick={() => openDismiss([k])}>
                        Dismiss
                      </Button>
                    </div>
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
      {dto.cursor !== null && (
        <div>
          <Button isDisabled={more.busy} onClick={() => void more.run(() => load(dto.cursor ?? 0))}>
            Show more
          </Button>
        </div>
      )}
    </section>
  );
}
