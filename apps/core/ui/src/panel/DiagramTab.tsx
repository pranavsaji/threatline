import { useId, useState, type KeyboardEvent } from 'react';
import Button from '@atlaskit/button/new';
import SectionMessage from '@atlaskit/section-message';
import { token } from '@atlaskit/tokens';
import { SeverityLozenge } from '../components/SeverityLozenge.js';
import { count } from '../text.js';
import type { DiagramDto, Severity } from '../types.js';

type DiagramNode = DiagramDto['nodes'][number];
type Kind = DiagramNode['kind'];

const KIND: Record<Kind, string> = { external: 'External entity', process: 'Process', store: 'Data store' };

/** Fill and border by highest open severity (accent tokens follow the light and dark themes); the text says it too. */
const PAINT: Record<Severity | 'none', { fill: string; stroke: string; width: number }> = {
  Critical: { fill: token('color.background.accent.red.subtler'), stroke: token('color.border.accent.red'), width: 3 },
  High: { fill: token('color.background.accent.orange.subtler'), stroke: token('color.border.accent.orange'), width: 2 },
  Medium: { fill: token('color.background.accent.yellow.subtler'), stroke: token('color.border.accent.yellow'), width: 1.5 },
  Low: { fill: token('color.background.neutral'), stroke: token('color.border.bold'), width: 1 },
  none: { fill: token('elevation.surface.raised'), stroke: token('color.border.bold'), width: 1 },
};

const threatLine = (n: DiagramNode): string =>
  n.openCount > 0 ? `${count(n.openCount, 'open threat')} · ${n.maxSeverity}` : n.threatCount > 0 ? `${count(n.threatCount, 'threat')}, none open` : 'No threats';

const describeNode = (n: DiagramNode, boundary: string | undefined): string =>
  [n.name, KIND[n.kind], boundary ? `in ${boundary}` : '', n.inferred === 'threat' ? 'named only by a threat' : n.inferred === 'flow' ? 'named only in a flow' : '', threatLine(n)]
    .filter(Boolean)
    .join(', ');

function Shape({ n, focused, selected }: { n: DiagramNode; focused: boolean; selected: boolean }) {
  const p = PAINT[n.maxSeverity ?? 'none'];
  const { x, y, w, h } = n;
  return (
    <g data-node={n.id} data-kind={n.kind}>
      <title>{`${n.name}: ${threatLine(n)}`}</title>
      {n.kind === 'store' ? (
        <>
          <rect x={x} y={y} width={w} height={h} fill={p.fill} />
          {/* Open-ended store: top and bottom lines and the left side, open to the right. */}
          <path d={`M${x + w} ${y} H${x} V${y + h} H${x + w}`} fill="none" stroke={p.stroke} strokeWidth={p.width} />
        </>
      ) : (
        <rect x={x} y={y} width={w} height={h} rx={n.kind === 'external' ? 16 : 2} fill={p.fill} stroke={p.stroke} strokeWidth={p.width} />
      )}
      {(focused || selected) && (
        <rect x={x - 4} y={y - 4} width={w + 8} height={h + 8} rx={n.kind === 'external' ? 20 : 5} fill="none" stroke={token(focused ? 'color.border.focused' : 'color.border.selected')} strokeWidth={2} />
      )}
      <text x={x + 10} y={y + 20} fontSize={12} fontWeight={600} fill={token('color.text')}>
        {n.label}
      </text>
      <text x={x + 10} y={y + 37} fontSize={11} fill={token('color.text.subtle')}>
        {threatLine(n)}
      </text>
    </g>
  );
}

function Legend() {
  const item = (shape: JSX.Element, text: string) => (
    <li style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      <svg width={26} height={14} aria-hidden="true" focusable="false">
        {shape}
      </svg>
      {text}
    </li>
  );
  const stroke = token('color.border.bold');
  return (
    <ul aria-label="Legend" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: '4px 12px', font: token('font.body.small'), color: token('color.text.subtle') }}>
      {item(<rect x={1} y={1} width={24} height={12} rx={6} fill="none" stroke={stroke} />, 'External entity')}
      {item(<rect x={1} y={1} width={24} height={12} fill="none" stroke={stroke} />, 'Process')}
      {item(<path d="M25 1 H1 V13 H25" fill="none" stroke={stroke} />, 'Data store')}
      {item(<rect x={1} y={1} width={24} height={12} fill="none" stroke={stroke} strokeDasharray="4 2" />, 'Trust boundary')}
      {item(<path d="M1 7 H25" stroke={token('color.border.discovery')} strokeWidth={2} />, 'Flow across a trust boundary')}
      <li>Colour and text: highest open severity</li>
    </ul>
  );
}

const cell = { textAlign: 'left' as const, padding: 4, borderBottom: `1px solid ${token('color.border')}`, verticalAlign: 'top' as const };
const captionStyle = { textAlign: 'left' as const, font: token('font.body.small'), color: token('color.text.subtle') };

function Table({ caption, head, rows }: { caption: string; head: string[]; rows: Array<Array<string | number>> }) {
  return (
    <div style={{ overflowX: 'auto' }} tabIndex={0} role="region" aria-label={caption}>
      <table style={{ borderCollapse: 'collapse', width: '100%' }}>
        <caption style={captionStyle}>{caption}</caption>
        <thead>
          <tr>
            {head.map((h) => (
              <th key={h} scope="col" style={cell}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {r.map((c, j) => (
                <td key={j} style={{ padding: 4, verticalAlign: 'top' }}>
                  {c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The review's data-flow diagram, drawn from the layout the backend computed (scoped to this viewer). The drawing is
 * one role="img" with a summary; each element is a real button laid over it, so a click or keyboard focus filters the
 * threat list below to that element. Every text is a React child (escaped); there is no injected markup.
 */
export function DiagramTab({ diagram }: { diagram: DiagramDto | undefined }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [focused, setFocused] = useState<string | null>(null);
  const [showTable, setShowTable] = useState(false);
  const uid = useId().replace(/[^a-zA-Z0-9_-]/g, '');

  if (!diagram || diagram.nodes.length === 0)
    return (
      <div style={{ paddingTop: 8 }}>
        <p style={{ color: token('color.text.subtle') }}>
          {diagram?.sketchHidden
            ? 'The architecture of this review comes from sources you cannot open, so there is nothing to draw for you.'
            : 'No architecture to draw yet. The diagram appears once a review has extracted components or threats name them.'}
        </p>
      </div>
    );

  const m = diagram;
  const byId = new Map(m.nodes.map((n) => [n.id, n]));
  const boundaryName = new Map(m.boundaries.map((b) => [b.id, b.implied ? `${b.name} (implied)` : b.name]));
  const selectedNode = selected ? byId.get(selected) : undefined;
  const shown = selectedNode ? m.threats.filter((t) => t.nodeId === selectedNode.id) : m.threats;
  const marker = (kind: 'flow' | 'cross') => `tl-arrow-${kind}-${uid}`;
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') setSelected(null);
  };

  return (
    <div style={{ display: 'grid', gap: 8, paddingTop: 8, width: '100%', minWidth: 0 }}>
      {m.sketchHidden && (
        <SectionMessage appearance="information">
          Parts of the architecture come from sources you cannot open, so only the elements your threats name are drawn.
        </SectionMessage>
      )}
      <Legend />
      <div style={{ overflow: 'auto', maxHeight: 560, border: `1px solid ${token('color.border')}`, borderRadius: 4 }}>
        <div style={{ position: 'relative', width: m.width, height: m.height }}>
          <svg role="img" aria-label={m.summary} width={m.width} height={m.height} viewBox={`0 0 ${m.width} ${m.height}`} style={{ display: 'block' }}>
            <defs>
              {(['flow', 'cross'] as const).map((k) => (
                <marker key={k} id={marker(k)} viewBox="0 0 10 10" refX={9} refY={5} markerWidth={7} markerHeight={7} orient="auto-start-reverse">
                  <path d="M0 0 L10 5 L0 10 z" fill={token(k === 'cross' ? 'color.border.discovery' : 'color.border.bold')} />
                </marker>
              ))}
            </defs>
            {m.boundaries.map((b) => (
              <g key={b.id} data-boundary={b.id}>
                <title>{b.implied ? 'System boundary (implied: no named trust boundary matched an element)' : `Trust boundary: ${b.name}`}</title>
                <rect x={b.x} y={b.y} width={b.w} height={b.h} rx={8} fill="none" stroke={token('color.border.bold')} strokeDasharray="6 4" />
                <text x={b.x + 10} y={b.y + 19} fontSize={12} fontStyle="italic" fill={token('color.text.subtle')}>
                  {b.implied ? 'System (implied)' : b.label}
                </text>
              </g>
            ))}
            {m.edges.map((e) => {
              const cross = e.crossesBoundary;
              const dim = selected !== null && e.from !== selected && e.to !== selected;
              return (
                <g key={e.id} data-edge={e.id} opacity={dim ? 0.35 : 1}>
                  <title>{`${e.n}. ${byId.get(e.from)?.name} to ${byId.get(e.to)?.name}${e.data ? `: ${e.data}` : ''}${cross ? ' (crosses a trust boundary)' : ''}`}</title>
                  <path d={e.path} fill="none" stroke={token(cross ? 'color.border.discovery' : 'color.border.bold')} strokeWidth={cross ? 2 : 1.25} markerEnd={`url(#${marker(cross ? 'cross' : 'flow')})`} />
                  <text
                    x={e.labelX}
                    y={e.labelY}
                    textAnchor="middle"
                    fontSize={11}
                    fill={token('color.text.subtle')}
                    stroke={token('elevation.surface')}
                    strokeWidth={4}
                    paintOrder="stroke"
                  >
                    {e.caption}
                  </text>
                </g>
              );
            })}
            {m.nodes.map((n) => (
              <Shape key={n.id} n={n} focused={focused === n.id} selected={selected === n.id} />
            ))}
          </svg>
          {m.nodes.map((n) => (
            <button
              key={n.id}
              type="button"
              aria-label={describeNode(n, n.boundaryId ? boundaryName.get(n.boundaryId) : undefined)}
              aria-pressed={selected === n.id}
              onClick={() => setSelected(n.id)}
              onFocus={() => {
                setFocused(n.id);
                setSelected(n.id);
              }}
              onBlur={() => setFocused(null)}
              onKeyDown={onKey}
              style={{ position: 'absolute', left: n.x, top: n.y, width: n.w, height: n.h, padding: 0, margin: 0, border: 0, background: 'transparent', cursor: 'pointer', outline: 'none' }}
            />
          ))}
        </div>
      </div>

      <section aria-label="Threats on the diagram" style={{ display: 'grid', gap: 6 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <p aria-live="polite" style={{ margin: 0, font: token('font.body'), fontWeight: 600 }}>
            {selectedNode ? `${count(shown.length, 'threat')} on ${selectedNode.name}` : `${count(m.threats.length, 'threat')} on the diagram`}
          </p>
          {selectedNode && (
            <Button spacing="compact" appearance="subtle" onClick={() => setSelected(null)}>
              Show all threats
            </Button>
          )}
        </div>
        {shown.length === 0 ? (
          <p style={{ margin: 0, color: token('color.text.subtle') }}>{selectedNode ? 'No threats name this element.' : 'No threats yet.'}</p>
        ) : (
          <ul aria-label={selectedNode ? `Threats on ${selectedNode.name}` : 'Threats'} style={{ margin: 0, paddingLeft: 0, listStyle: 'none', display: 'grid', gap: 4 }}>
            {shown.map((t) => (
              <li key={t.id} style={{ display: 'flex', gap: 6, alignItems: 'baseline', flexWrap: 'wrap' }}>
                <SeverityLozenge severity={t.severity} />
                <span style={t.open ? undefined : { textDecoration: 'line-through', color: token('color.text.subtle') }}>{t.title}</span>
                <span style={{ color: token('color.text.subtlest'), font: token('font.body.small') }}>
                  {[!selectedNode ? (t.nodeId ? byId.get(t.nodeId)?.name : 'no element') : '', t.open ? '' : t.state === 'dismissed' ? 'dismissed' : 'requirement closed'].filter(Boolean).join(' · ')}
                </span>
              </li>
            ))}
          </ul>
        )}
        {m.unplacedBoundaries.length > 0 && (
          <p style={{ margin: 0, color: token('color.text.subtlest'), font: token('font.body.small') }}>
            Trust boundaries not tied to an element: {m.unplacedBoundaries.join('; ')}.
          </p>
        )}
      </section>

      <div>
        <Button appearance="subtle" aria-expanded={showTable} onClick={() => setShowTable(!showTable)}>
          {showTable ? 'Hide' : 'Show'} the diagram as tables
        </Button>
      </div>
      {showTable && (
        <div style={{ display: 'grid', gap: 12 }}>
          <Table
            caption="Elements"
            head={['Element', 'Type', 'Trust boundary', 'Open threats', 'Highest open severity']}
            rows={m.nodes.map((n) => [n.name, KIND[n.kind], n.boundaryId ? (boundaryName.get(n.boundaryId) ?? '') : '—', n.openCount, n.maxSeverity ?? '—'])}
          />
          <Table
            caption="Data flows"
            head={['#', 'From', 'To', 'Data', 'Crosses a trust boundary']}
            rows={m.edges.map((e) => [e.n, byId.get(e.from)?.name ?? '', byId.get(e.to)?.name ?? '', e.data || '—', e.crossesBoundary ? 'Yes' : 'No'])}
          />
          <Table
            caption="Trust boundaries"
            head={['Trust boundary', 'Elements inside']}
            rows={[
              ...m.boundaries.map((b) => [boundaryName.get(b.id) ?? b.name, b.nodeIds.map((id) => byId.get(id)?.name ?? '').join(', ')]),
              ...m.unplacedBoundaries.map((b) => [b, 'Not tied to an element']),
            ]}
          />
          <Table
            caption="Threats by element"
            head={['Threat', 'Severity', 'Element', 'State']}
            rows={m.threats.map((t) => [t.title, t.severity, t.nodeId ? (byId.get(t.nodeId)?.name ?? '') : '—', t.open ? 'Open' : t.state === 'dismissed' ? 'Dismissed' : 'Requirement closed'])}
          />
        </div>
      )}
    </div>
  );
}
