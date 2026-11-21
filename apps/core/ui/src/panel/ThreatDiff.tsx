import { useEffect, useId, useState } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type PanelApi } from '../bridge.js';
import type { ApiError, ThreatBrief, ThreatDiffDto } from '../types.js';
import { SeverityLozenge } from '../components/SeverityLozenge.js';
import { box, field } from './form-styles.js';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const STATE: Record<string, string> = { accepted: 'accepted', needs_human: 'needs a champion', dismissed: 'dismissed', proposed: 'proposed', suppressed: 'hidden by a team rule' };

function Item({ t }: { t: ThreatBrief }) {
  return (
    <li style={{ display: 'flex', gap: 6, alignItems: 'baseline', flexWrap: 'wrap', margin: 0 }}>
      <SeverityLozenge severity={t.severity} />
      <span>{t.title}</span>
      <span style={{ color: token('color.text.subtlest'), font: token('font.body.small') }}>{t.component}</span>
    </li>
  );
}

/**
 * R7: what the latest re-review changed. Threats on unchanged sources carry over with their triage, so this lists only
 * what is new, gone or different. Revisions can be compared with any earlier one.
 */
export function ThreatDiff({ api, revisions }: { api: PanelApi; revisions: number[] }) {
  const id = useId();
  const latest = revisions.at(-1)!;
  const earlier = revisions.filter((r) => r < latest);
  const [from, setFrom] = useState<number | undefined>(undefined);
  const [d, setD] = useState<ThreatDiffDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let live = true;
    void api
      .diff(from, from === undefined ? undefined : latest)
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => {
        if (!live) return;
        if (isError(r)) return setError(errorText(r));
        setError(null);
        setD(r);
      });
    return () => {
      live = false;
    };
  }, [api, from, latest]);

  if (error) return <p style={{ margin: 0, color: token('color.text.subtle'), font: token('font.body.small') }}>{`Could not compare revisions: ${error}`}</p>;
  if (!d) return null;
  const listStyle = { listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 4 } as const;

  return (
    <section aria-labelledby={`${id}-h`} style={{ ...box, gap: 6 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <h3 id={`${id}-h`} style={{ margin: 0, font: token('font.body'), fontWeight: token('font.weight.semibold') }}>
          {d.summary}
        </h3>
        <Button appearance="subtle" spacing="compact" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? 'Hide what changed' : 'Show what changed'}
        </Button>
      </div>
      {open && (
        <div style={{ display: 'grid', gap: 8 }}>
          {earlier.length > 1 && (
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
              <label htmlFor={`${id}-from`} style={{ font: token('font.body.small'), color: token('color.text.subtle') }}>
                {`Compare revision ${latest} with`}
              </label>
              <select id={`${id}-from`} value={d.from} onChange={(e) => setFrom(Number(e.target.value))} style={field}>
                {earlier.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
          )}
          {d.added.length > 0 && (
            <>
              <h4 style={{ margin: 0, font: token('font.body.small'), color: token('color.text.subtle') }}>New</h4>
              <ul aria-label="New threats" style={listStyle}>
                {d.added.map((t) => (
                  <Item key={t.id} t={t} />
                ))}
              </ul>
            </>
          )}
          {d.changed.length > 0 && (
            <>
              <h4 style={{ margin: 0, font: token('font.body.small'), color: token('color.text.subtle') }}>Changed</h4>
              <ul aria-label="Changed threats" style={listStyle}>
                {d.changed.map((c) => (
                  <li key={c.after.id} style={{ margin: 0 }}>
                    {c.after.title}:{' '}
                    {c.before.severity !== c.after.severity ? `${c.before.severity} → ${c.after.severity}` : `${STATE[c.before.state] ?? c.before.state} → ${STATE[c.after.state] ?? c.after.state}`}
                  </li>
                ))}
              </ul>
            </>
          )}
          {d.removed.length > 0 && (
            <>
              <h4 style={{ margin: 0, font: token('font.body.small'), color: token('color.text.subtle') }}>No longer raised</h4>
              <ul aria-label="Threats no longer raised" style={listStyle}>
                {d.removed.map((t) => (
                  <Item key={t.id} t={t} />
                ))}
              </ul>
            </>
          )}
          <p style={{ margin: 0, color: token('color.text.subtle'), font: token('font.body.small') }}>
            {`${plural(d.unchanged, 'threat')} carried over unchanged, with their triage. Only threats citing changed or new sources were looked at again.`}
          </p>
          {d.hidden > 0 && <p style={{ margin: 0, color: token('color.text.subtlest'), font: token('font.body.small') }}>{`${plural(d.hidden, 'threat')} ${d.hidden === 1 ? 'cites' : 'cite'} sources you cannot open and are left out.`}</p>}
        </div>
      )}
    </section>
  );
}
