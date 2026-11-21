import { useCallback, useEffect, useId, useState } from 'react';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type DrillQuery, type PostureApi } from '../bridge.js';
import type { ApiError, PostureDto } from '../types.js';
import { KpiRow } from './KpiRow.js';
import { Heatmap } from './Heatmap.js';
import { TrendChart } from './TrendChart.js';
import { DrillDown, type DrillView } from './DrillDown.js';
import { Onboarding } from './Onboarding.js';
import { ReleaseReport } from './ReleaseReport.js';
import { ControlsView } from './ControlsView.js';

const skeleton = (h: number, w: number | string = '100%') => (
  <div aria-hidden="true" style={{ height: h, width: w, borderRadius: 6, background: token('color.skeleton') }} />
);

/** PR-1 global page: KPI row, heatmap, 30-day trend, drill-down and the release report. `compact` is the gadget (PR-5). */
export function PostureDashboard({ api, compact = false }: { api: PostureApi; compact?: boolean }) {
  const id = useId();
  const [project, setProject] = useState('');
  const [projects, setProjects] = useState<string[]>([]);
  const [dto, setDto] = useState<PostureDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [drill, setDrill] = useState<DrillView | null>(null);

  useEffect(() => {
    let live = true;
    setDto(null);
    setError(null);
    void api
      .get(project || undefined)
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => {
        if (!live) return;
        if (isError(r)) setError(errorText(r));
        else {
          setDto(r);
          if (!project) setProjects(r.projects);
        }
      });
    return () => {
      live = false;
    };
  }, [api, project]);

  const openDrill = useCallback(
    (q: DrillQuery, title: string) => {
      setDrill({ kind: 'loading', title });
      void api
        .drill(project && !q.team ? { ...q, team: project } : q)
        .catch((): ApiError => ({ error: 'unavailable' }))
        .then((r) => setDrill(isError(r) ? { kind: 'error', title, message: errorText(r) } : { kind: 'items', title, dto: r }));
    },
    [api, project],
  );

  const heading = (
    <h1 id={`${id}-h`} style={{ margin: 0, font: compact ? token('font.heading.small') : token('font.heading.medium') }}>
      Security posture
    </h1>
  );

  return (
    <main aria-labelledby={`${id}-h`} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 20, padding: 16, maxWidth: 1040, color: token('color.text'), background: token('elevation.surface') }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', justifyContent: 'space-between' }}>
        {heading}
        {!compact && projects.length > 1 && (
          <label style={{ display: 'flex', gap: 8, alignItems: 'center', font: token('font.body.small') }}>
            Project
            <select value={project} onChange={(e) => setProject(e.target.value)} style={{ font: 'inherit', padding: 4 }}>
              <option value="">All Threatline projects</option>
              {projects.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>

      {error && (
        <p role="alert" style={{ margin: 0 }}>
          {error}
        </p>
      )}
      {!dto && !error && (
        <div role="status" aria-label="Loading security posture" style={{ display: 'grid', gap: 12 }}>
          <div style={{ display: 'flex', gap: 8 }}>{[0, 1, 2, 3, 4].map((i) => <div key={i} style={{ flex: 1 }}>{skeleton(72)}</div>)}</div>
          {!compact && skeleton(160)}
          {!compact && skeleton(220)}
        </div>
      )}

      {dto && (dto.projects.length === 0 || dto.issuesCounted === 0) && <Onboarding projects={dto.projects} />}
      {dto && dto.projects.length > 0 && dto.issuesCounted > 0 && (
        <>
          <KpiRow dto={dto} onDrill={openDrill} onExpiring={() => setDrill({ kind: 'expiring', title: 'acceptances expiring in 14 days', items: dto.expiring.filter((a) => Date.parse(a.expiresAt) - Date.now() <= 14 * 86_400_000), hidden: dto.hiddenExpiring })} />
          {drill && <DrillDown view={drill} onClose={() => setDrill(null)} />}
          {!compact && (
            <>
              <section aria-labelledby={`${id}-map`} style={{ display: 'grid', gap: 8 }}>
                <h2 id={`${id}-map`} style={{ margin: 0, font: token('font.heading.small') }}>
                  Where the open requirements are
                </h2>
                <Heatmap dto={dto} onDrill={openDrill} />
              </section>
              <section aria-labelledby={`${id}-trend`} style={{ display: 'grid', gap: 8, minWidth: 0 }}>
                <h2 id={`${id}-trend`} style={{ margin: 0, font: token('font.heading.small') }}>
                  Trend
                </h2>
                <TrendChart trend={dto.trend} shown={dto.trendShown} />
              </section>
              <ControlsView api={api} project={project} />
            </>
          )}
        </>
      )}
      {!compact && <ReleaseReport api={api} />}
    </main>
  );
}
