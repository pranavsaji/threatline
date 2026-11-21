import { useEffect, useId, useState } from 'react';
import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type PostureApi } from '../bridge.js';
import type { ApiError, ControlsPostureDto } from '../types.js';
import { DrillDown, type DrillView } from './DrillDown.js';

type Control = ControlsPostureDto['frameworks'][number]['controls'][number];

const SHORT: Record<string, string> = { SOC2: 'SOC 2', ISO27001: 'ISO 27001', PCIDSS: 'PCI DSS' };
const STATE: Record<Control['state'], { label: string; appearance: 'removed' | 'moved' | 'success'; border: string }> = {
  open: { label: 'Open', appearance: 'removed', border: token('color.border.danger') },
  accepted: { label: 'Accepted risk', appearance: 'moved', border: token('color.border.warning') },
  verified: { label: 'Verified', appearance: 'success', border: token('color.border.success') },
};

const row = {
  display: 'grid',
  gridTemplateColumns: 'auto minmax(0, 1fr) auto',
  gap: 8,
  alignItems: 'center',
  width: '100%',
  padding: '8px 10px',
  borderRadius: 6,
  border: `1px solid ${token('color.border')}`,
  background: token('elevation.surface'),
  color: token('color.text'),
  font: 'inherit',
  textAlign: 'left' as const,
  cursor: 'pointer',
};
const small = { font: token('font.body.small'), color: token('color.text.subtle') };

/**
 * Compliance evidence on the posture page: per framework, each control with requirements behind it, red while any is
 * open, amber when the rest is accepted risk, green when all are verified. Counts only work items the viewer can browse
 * (the server scopes them); a control drills down to its work items. The mapping is indicative, not an audit opinion.
 */
export function ControlsView({ api, project }: { api: PostureApi; project: string }) {
  const id = useId();
  const [dto, setDto] = useState<ControlsPostureDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [framework, setFramework] = useState<string | null>(null);
  const [drill, setDrill] = useState<DrillView | null>(null);

  useEffect(() => {
    let live = true;
    setDto(null);
    setError(null);
    setDrill(null);
    void api
      .controls(project || undefined)
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => {
        if (!live) return;
        if (isError(r)) setError(errorText(r));
        else setDto(r);
      });
    return () => {
      live = false;
    };
  }, [api, project]);

  const open = (fw: string, c: Control) => {
    const title = `${fw} ${c.id}`;
    setDrill({ kind: 'loading', title });
    void api
      .controlDrill({ framework: fw, control: c.id, ...(project ? { project } : {}) })
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => setDrill(isError(r) ? { kind: 'error', title, message: errorText(r) } : { kind: 'items', title, dto: r }));
  };

  const shown = dto ? (dto.frameworks.find((f) => f.framework === framework) ?? dto.frameworks[0]) : undefined;
  const anything = dto?.frameworks.some((f) => f.controls.length > 0) ?? false;

  return (
    <section aria-labelledby={`${id}-h`} style={{ display: 'grid', gap: 8, minWidth: 0 }}>
      <h2 id={`${id}-h`} style={{ margin: 0, font: token('font.heading.small') }}>
        Controls (indicative)
      </h2>
      {error && (
        <p role="alert" style={{ margin: 0 }}>
          {error}
        </p>
      )}
      {!dto && !error && <p style={{ margin: 0, ...small }}>Loading controls…</p>}
      {dto && (
        <>
          <p style={{ margin: 0, ...small }}>{dto.disclaimer}</p>
          {!anything ? (
            <p style={{ margin: 0 }}>No requirements you can see map to a compliance control yet.</p>
          ) : (
            <>
              <div role="group" aria-label="Framework" style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {dto.frameworks.map((f) => {
                  const pressed = f.framework === shown?.framework;
                  return (
                    <button
                      key={f.framework}
                      type="button"
                      aria-pressed={pressed}
                      onClick={() => (setFramework(f.framework), setDrill(null))}
                      style={{ ...row, width: 'auto', display: 'inline-block', padding: '4px 10px', ...(pressed ? { border: `2px solid ${token('color.border.selected')}`, background: token('color.background.selected') } : {}) }}
                    >
                      {SHORT[f.framework] ?? f.framework}
                    </button>
                  );
                })}
              </div>
              {drill && <DrillDown view={drill} onClose={() => setDrill(null)} />}
              {shown && (
                <>
                  <span style={small}>
                    {shown.name} {shown.version}
                  </span>
                  <ul aria-label={`${shown.name} controls`} style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
                    {shown.controls.length === 0 && <li style={small}>No requirements you can see map to this framework.</li>}
                    {shown.controls.map((c) => {
                      const s = STATE[c.state];
                      const n = c.counts;
                      return (
                        <li key={c.id} style={{ margin: 0 }}>
                          <button
                            type="button"
                            style={{ ...row, borderLeft: `4px solid ${s.border}` }}
                            aria-label={`${c.id} ${c.title}. ${s.label}: ${n.open} open, ${n.verified} verified, ${n.acceptedRisk} accepted risk. Show the work items`}
                            onClick={() => open(shown.framework, c)}
                          >
                            <strong style={{ whiteSpace: 'nowrap' }}>{c.id}</strong>
                            <span style={{ minWidth: 0 }}>{c.title}</span>
                            <span style={{ display: 'flex', gap: 6, alignItems: 'center', ...small }}>
                              <Lozenge appearance={s.appearance}>{s.label}</Lozenge>
                              {`${n.open} open · ${n.verified} verified · ${n.acceptedRisk} accepted`}
                            </span>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </>
              )}
              {dto.truncated && <p style={{ margin: 0, ...small }}>Counted from the {dto.issuesCounted} most recently updated work items you can see.</p>}
            </>
          )}
        </>
      )}
    </section>
  );
}
