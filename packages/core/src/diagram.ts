import { ArchitectureSketchSchema, severityRank, type ArchitectureSketch, type Severity, type Threat } from '@threatline/shared';
import { scanForInjection } from './context/injection.js';
import { isFailedSample, type Sample } from './ports.js';

/**
 * The data-flow diagram of a review: a pure, deterministic layout of the architecture sketch and the threats on it.
 * No I/O, no randomness, no model: the same input always gives the same model. Every surface draws from this model
 * (the panel's SVG, the Confluence page's tables, get-review's text DFD), so they never disagree.
 */

/** The parts of an architecture sketch a diagram uses. Every part is optional (agent runs carry no flows). */
export type DiagramSketch = Partial<Pick<ArchitectureSketch, 'components' | 'dataStores' | 'externalServices' | 'trustBoundaries' | 'flows'>>;

export interface DiagramInput {
  sketch?: DiagramSketch | null;
  /** The threats the reader may see. Covered threats are left out; dismissed ones are listed but not counted. */
  threats: ReadonlyArray<Pick<Threat, 'id' | 'title' | 'component' | 'severity' | 'state'>>;
  /** Threats whose requirement is closed (verified, accepted as a risk, not applicable): counted, but not open. */
  resolvedThreatIds?: Iterable<string>;
}

/** DFD kinds: an external entity (actor or third-party service), a process (component), a data store. */
export type DiagramNodeKind = 'external' | 'process' | 'store';

export interface DiagramNode {
  id: string;
  kind: DiagramNodeKind;
  /** The full name, for a tooltip and the text alternative. */
  name: string;
  /** The name as drawn in the box (truncated with an ellipsis). */
  label: string;
  x: number;
  y: number;
  w: number;
  h: number;
  boundaryId: string | null;
  /** Not in the sketch's lists: named only as a flow endpoint, or only by a threat's component. */
  inferred?: 'flow' | 'threat';
  threatIds: string[];
  /** Threats not dismissed. */
  threatCount: number;
  /** Threats not dismissed whose requirement is still open. */
  openCount: number;
  /** Highest severity among the open threats, or null when none is open. */
  maxSeverity: Severity | null;
}

export interface DiagramEdge {
  id: string;
  /** 1-based number, shown on the edge and in the flows table. */
  n: number;
  from: string;
  to: string;
  data: string;
  label: string;
  /** What the drawing prints on the edge: "n. label", or just "n" when there are too many flows to label. */
  caption: string;
  crossesBoundary: boolean;
  /** SVG path data (a cubic curve) from the source's side to the target's. */
  path: string;
  /** Where the caption's text sits (centre, baseline), inside `captionBox`. */
  labelX: number;
  labelY: number;
  /** The caption's halo (drawn behind the text over the lines). Never overlaps another caption's; avoids boxes and boundary titles where it can. */
  captionBox: { x: number; y: number; w: number; h: number };
}

export interface DiagramBoundary {
  id: string;
  name: string;
  label: string;
  /** The system boundary drawn when no named trust boundary could be tied to an element. */
  implied: boolean;
  x: number;
  y: number;
  w: number;
  h: number;
  nodeIds: string[];
}

export interface DiagramThreat {
  id: string;
  title: string;
  severity: Severity;
  state: Threat['state'];
  nodeId: string | null;
  open: boolean;
}

export interface DiagramModel {
  width: number;
  height: number;
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  boundaries: DiagramBoundary[];
  /** Named trust boundaries no element could be tied to: listed, not drawn. */
  unplacedBoundaries: string[];
  threats: DiagramThreat[];
  /** Threats with no component to place them on. */
  unplacedThreats: number;
  /** One sentence for screen readers (the SVG's aria-label). */
  summary: string;
}

// Geometry (px). The column gap holds edge labels; the margin holds same-column and self-loop curves.
const NODE_W = 168;
const NODE_H = 48;
const COL_GAP = 160;
const ROW_GAP = 16;
const MARGIN = 40;
const BOX_PAD = 14;
const LANE_LABEL = 30;
const LANE_BOTTOM = 14;
const LANE_GAP = 16;
const BULGE = 32;
const NODE_CHARS = 22;
const EDGE_CHARS = 20;
const BOUNDARY_CHARS = 60;
const MAX_INFERRED = 30;
/** Up to this many flows, each edge is captioned with its data; past it only with its number. */
const CAPTIONED_EDGES = 12;
const CHAR_W = 6.2;
const CAPTION_H = 16;
/** Text baseline below the top of the caption's halo (11px text). */
const CAPTION_BASE = 12;
const CAPTION_GRID = 12;
const CAPTION_TS = [0.5, 0.4, 0.6, 0.3, 0.7, 0.2, 0.8, 0.12, 0.88];
const KINDS: DiagramNodeKind[] = ['external', 'process', 'store'];
/** Flow endpoints that read like a person or a client are drawn as external entities. */
const ACTOR = /\b(?:user|customer|client|browser|attacker|admin|administrator|operator|partner|visitor|employee|merchant|mobile app|internet)\b/;

/** A name for matching: lower case, punctuation as spaces, simple plurals folded ("Orders-DB" = "order db"). */
export const nameKey = (s: string): string =>
  s
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim()
    .split(' ')
    .filter(Boolean)
    .map((w) => (w.length > 3 && w.endsWith('s') && !w.endsWith('ss') ? w.slice(0, -1) : w))
    .join(' ');

const SIDES = /\s*(?:→|->|=>|⇒|\bto\b|\bvs\.?(?=\s)|\s\/\s|\|)\s*/i;
/** The part of a boundary's text that names its inside: the last side of a crossing, or all of it. */
const insideOf = (boundary: string): string => {
  const sides = boundary.split(SIDES).filter((x) => nameKey(x));
  return nameKey(sides[sides.length - 1] ?? boundary);
};
const within = (outer: string, inner: string) => inner.length >= 3 && ` ${outer} `.includes(` ${inner} `);
const words = (k: string) => (k ? k.split(' ') : []);

/**
 * The node a name refers to, by index: an exact match first, then a whole-word containment either way (the closest
 * in length wins), then a token overlap of at least half. Ties go to the earlier node. Null when nothing is close.
 */
export function matchNode(name: string, nodes: ReadonlyArray<{ name: string }>): number | null {
  const k = nameKey(name);
  if (!k) return null;
  const keys = nodes.map((n) => nameKey(n.name));
  const exact = keys.indexOf(k);
  if (exact >= 0) return exact;
  let best: { i: number; score: number } | null = null;
  const consider = (i: number, score: number) => {
    if (!best || score > best.score) best = { i, score };
  };
  const kw = words(k);
  keys.forEach((nk, i) => {
    if (!nk) return;
    const nw = words(nk);
    if (within(k, nk) || within(nk, k)) consider(i, 1 + Math.min(kw.length, nw.length) / Math.max(kw.length, nw.length));
    else {
      const A = new Set(kw);
      const B = new Set(nw);
      let inter = 0;
      for (const w of A) if (B.has(w)) inter++;
      const j = inter / (A.size + B.size - inter);
      if (j >= 0.5) consider(i, j);
    }
  });
  return (best as { i: number } | null)?.i ?? null;
}

/** Cuts to n code points (never half a surrogate pair), with an ellipsis. */
const truncate = (s: string, n: number): string => {
  const cps = Array.from(s);
  return cps.length <= n ? s : `${cps.slice(0, n - 1).join('').trimEnd()}…`;
};
const clean = (s: unknown): string | null => {
  if (typeof s !== 'string') return null;
  const t = s.trim().slice(0, 200);
  return t && !scanForInjection(t).suspected ? t : null;
};
const r1 = (n: number) => Math.round(n * 10) / 10;
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

interface Draft {
  kind: DiagramNodeKind;
  name: string;
  inferred?: 'flow' | 'threat';
}

/** Lays out the diagram: columns by kind (external → process → store), one horizontal lane per trust boundary. */
export function layoutDiagram(input: DiagramInput): DiagramModel {
  const sk = input.sketch ?? {};
  const drafts: Draft[] = [];
  const keys = new Set<string>();
  const add = (kind: DiagramNodeKind, raw: unknown, inferred?: Draft['inferred']): void => {
    const name = clean(raw);
    if (!name) return;
    const k = nameKey(name);
    if (!k || keys.has(k)) return;
    keys.add(k);
    drafts.push({ kind, name, ...(inferred ? { inferred } : {}) });
  };
  for (const s of (sk.externalServices ?? []).slice(0, 30)) add('external', s);
  for (const s of (sk.components ?? []).slice(0, 30)) add('process', s);
  for (const s of (sk.dataStores ?? []).slice(0, 30)) add('store', s);

  // Flows: each endpoint is a listed node when the name matches one; otherwise a new, inferred node.
  let inferredFlow = 0;
  const endpoint = (raw: string): number | null => {
    const name = clean(raw);
    if (!name || !nameKey(name)) return null;
    const hit = matchNode(name, drafts);
    if (hit !== null) return hit;
    if (inferredFlow >= MAX_INFERRED) return null;
    inferredFlow++;
    add(ACTOR.test(nameKey(name)) ? 'external' : 'process', name, 'flow');
    return drafts.length - 1;
  };
  const flowSeen = new Set<string>();
  const flows: Array<{ from: number; to: number; data: string }> = [];
  for (const f of (sk.flows ?? []).slice(0, 30)) {
    if (!f || typeof f !== 'object') continue;
    const data = clean(f.data) ?? '';
    if (typeof f.data === 'string' && f.data.trim() && !data) continue;
    const from = endpoint(f.from);
    const to = endpoint(f.to);
    if (from === null || to === null) continue;
    const key = `${from}|${to}|${nameKey(data)}`;
    if (flowSeen.has(key)) continue;
    flowSeen.add(key);
    flows.push({ from, to, data });
  }

  // Threats: placed on the node their component names; a component no node matches becomes an inferred node.
  const resolved = new Set(input.resolvedThreatIds ?? []);
  let inferredThreat = 0;
  const placed = input.threats
    .filter((t) => t.state !== 'covered')
    .map((t) => {
      const named = !!clean(t.component) && !!nameKey(t.component);
      let at = named ? matchNode(t.component, drafts) : null;
      if (at === null && named && inferredThreat < MAX_INFERRED) {
        inferredThreat++;
        add('process', t.component, 'threat');
        at = drafts.length - 1;
      }
      // Dismissed and team-suppressed threats are shown but never counted as open: neither has a requirement to close.
      const counted = t.state !== 'dismissed' && t.state !== 'suppressed';
      return { t, at, counted, open: counted && !resolved.has(t.id) };
    });

  // Trust boundaries: an element belongs to the first boundary whose text names it (whole words). A boundary written as
  // a crossing ("Internet → API", "Stripe to webhook endpoint") holds only what its last side names: the inside.
  const boundaryNames: string[] = [];
  const bKeys = new Set<string>();
  for (const b of (sk.trustBoundaries ?? []).slice(0, 30)) {
    const name = clean(b);
    if (!name || bKeys.has(nameKey(name))) continue;
    bKeys.add(nameKey(name));
    boundaryNames.push(name);
  }
  const inside = boundaryNames.map(insideOf);
  const memberOf = drafts.map((d) => {
    const k = nameKey(d.name);
    const i = inside.findIndex((b) => within(b, k));
    return i < 0 ? null : i;
  });
  const usedBoundaries = boundaryNames.map((_, i) => i).filter((i) => memberOf.includes(i));
  const kindsPresent = KINDS.filter((k) => drafts.some((d) => d.kind === k));
  const col = (k: DiagramNodeKind) => kindsPresent.indexOf(k);
  const colX = (c: number) => MARGIN + c * (NODE_W + COL_GAP);
  const contentW = kindsPresent.length * NODE_W + Math.max(0, kindsPresent.length - 1) * COL_GAP;
  const width = drafts.length ? MARGIN * 2 + contentW : 0;

  const free = drafts.map((_, i) => i).filter((i) => memberOf[i] === null);
  const implied = usedBoundaries.length === 0 && free.some((i) => drafts[i]!.kind === 'external') && free.some((i) => drafts[i]!.kind !== 'external');
  const lanes: Array<{ boundary: number | null; members: number[] }> = [];
  if (free.length) lanes.push({ boundary: null, members: free });
  for (const b of usedBoundaries) lanes.push({ boundary: b, members: drafts.map((_, i) => i).filter((i) => memberOf[i] === b) });

  const pos: Array<{ x: number; y: number }> = drafts.map(() => ({ x: 0, y: 0 }));
  const boundaries: DiagramBoundary[] = [];
  let y = drafts.length ? MARGIN / 2 : 0;
  for (const lane of lanes) {
    const labelled = lane.boundary !== null || implied;
    const top = y + (labelled ? LANE_LABEL : BOX_PAD);
    let rows = 0;
    for (const k of kindsPresent) {
      const inCol = lane.members.filter((i) => drafts[i]!.kind === k);
      inCol.forEach((i, r) => (pos[i] = { x: colX(col(k)), y: top + r * (NODE_H + ROW_GAP) }));
      rows = Math.max(rows, inCol.length);
    }
    const bottom = top + rows * NODE_H + Math.max(0, rows - 1) * ROW_GAP + LANE_BOTTOM;
    if (lane.boundary !== null) {
      const name = boundaryNames[lane.boundary]!;
      boundaries.push({ id: `b${lane.boundary + 1}`, name, label: truncate(name, BOUNDARY_CHARS), implied: false, x: MARGIN - BOX_PAD, y, w: contentW + BOX_PAD * 2, h: bottom - y, nodeIds: [] });
    } else if (implied) {
      const internal = kindsPresent.filter((k) => k !== 'external').map(col);
      const x0 = colX(Math.min(...internal)) - BOX_PAD;
      const x1 = colX(Math.max(...internal)) + NODE_W + BOX_PAD;
      boundaries.push({ id: 'b0', name: 'System', label: 'System', implied: true, x: x0, y, w: x1 - x0, h: bottom - y, nodeIds: [] });
    }
    y = bottom + LANE_GAP;
  }
  const height = drafts.length ? y - LANE_GAP + MARGIN / 2 : 0;

  const zone = (i: number): string => {
    const b = memberOf[i];
    if (b !== null && b !== undefined) return `b${b + 1}`;
    return implied && drafts[i]!.kind !== 'external' ? 'b0' : 'outside';
  };
  const nodeId = (i: number) => `n${i + 1}`;
  const nodes: DiagramNode[] = drafts.map((d, i) => {
    const mine = placed.filter((p) => p.at === i);
    const open = mine.filter((p) => p.open);
    const max = open.reduce<Severity | null>((m, p) => (m === null || severityRank(p.t.severity) > severityRank(m) ? p.t.severity : m), null);
    const z = zone(i);
    return {
      id: nodeId(i), kind: d.kind, name: d.name, label: truncate(d.name, NODE_CHARS), x: pos[i]!.x, y: pos[i]!.y, w: NODE_W, h: NODE_H,
      boundaryId: z === 'outside' ? null : z, ...(d.inferred ? { inferred: d.inferred } : {}),
      threatIds: mine.map((p) => p.t.id), threatCount: mine.filter((p) => p.counted).length, openCount: open.length, maxSeverity: max,
    };
  });
  for (const b of boundaries) b.nodeIds = nodes.filter((n) => n.boundaryId === b.id).map((n) => n.id);

  // Edges: curves between node sides; parallel flows between the same two nodes are spread apart vertically.
  const pairCount = new Map<string, number>();
  const pairKey = (a: number, b: number) => (a < b ? `${a}|${b}` : `${b}|${a}`);
  for (const f of flows) pairCount.set(pairKey(f.from, f.to), (pairCount.get(pairKey(f.from, f.to)) ?? 0) + 1);
  const pairSeen = new Map<string, number>();
  // Captions take the first spot along their curve that is clear of the boxes, the boundary titles and earlier captions.
  // Failing that, the nearest spot clear of earlier captions (scanning the whole canvas): two captions never overlap.
  type Box = { x: number; y: number; w: number; h: number };
  const overlap = (r: Box, o: Box) => r.x < o.x + o.w && o.x < r.x + r.w && r.y < o.y + o.h && o.y < r.y + r.h;
  const solid: Box[] = [...nodes, ...boundaries.map((b) => ({ x: b.x + 6, y: b.y + 4, w: Array.from(b.implied ? 'System (implied)' : b.label).length * CHAR_W + 8, h: 20 }))];
  const captions: Box[] = [];
  const clearOfCaptions = (r: Box) => !captions.some((o) => overlap(r, o));
  const clear = (r: Box) => clearOfCaptions(r) && !solid.some((o) => overlap(r, o));
  const captioned = flows.length <= CAPTIONED_EDGES;
  const edges: DiagramEdge[] = flows.map((f, i) => {
    const pk = pairKey(f.from, f.to);
    const k = pairSeen.get(pk) ?? 0;
    pairSeen.set(pk, k + 1);
    const spread = (k - ((pairCount.get(pk) ?? 1) - 1) / 2) * 10;
    const offset = Math.max(-NODE_H / 2 + 6, Math.min(NODE_H / 2 - 6, spread));
    const a = nodes[f.from]!;
    const b = nodes[f.to]!;
    let p: [number, number, number, number, number, number, number, number];
    if (f.from === f.to) {
      const x = a.x + a.w;
      p = [x, a.y + a.h * 0.3, x + BULGE, a.y - 4, x + BULGE, a.y + a.h + 4, x, a.y + a.h * 0.7];
    } else if (a.x === b.x) {
      const x = a.x + a.w;
      const ya = a.y + a.h / 2 + offset;
      const yb = b.y + b.h / 2 + offset;
      p = [x, ya, x + BULGE, ya, x + BULGE, yb, x, yb];
    } else {
      const forward = a.x < b.x;
      const sx = forward ? a.x + a.w : a.x;
      const ex = forward ? b.x : b.x + b.w;
      const sy = a.y + a.h / 2 + offset;
      const ey = b.y + b.h / 2 + offset;
      const dx = (ex - sx) / 2;
      p = [sx, sy, sx + dx, sy, ex - dx, ey, ex, ey];
    }
    const [x0, y0, x1, y1, x2, y2, x3, y3] = p.map(r1) as typeof p;
    const label = truncate(f.data, EDGE_CHARS);
    const caption = captioned && label ? `${i + 1}. ${label}` : String(i + 1);
    const cw = Math.min(width - 4, Array.from(caption).length * CHAR_W + 8);
    /** The caption's halo centred on (cx, cy), kept 2px inside the canvas. */
    const boxAt = (cx: number, cy: number): Box => ({
      x: r1(Math.max(2, Math.min(width - cw - 2, cx - cw / 2))),
      y: r1(Math.max(2, Math.min(height - CAPTION_H - 2, cy - CAPTION_H / 2))),
      w: r1(cw),
      h: CAPTION_H,
    });
    const point = (t: number) => {
      const u = 1 - t;
      return [u * u * u * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x3, u * u * u * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y3] as const;
    };
    const [mx, my] = point(0.5);
    const along = [0, -CAPTION_H, CAPTION_H, -2 * CAPTION_H, 2 * CAPTION_H].flatMap((dy) => CAPTION_TS.map((t) => boxAt(point(t)[0], point(t)[1] + dy)));
    let box = along.find(clear);
    if (!box) {
      const grid: Box[] = [];
      for (let gy = 0; gy <= height; gy += CAPTION_GRID) for (let gx = 0; gx <= width; gx += CAPTION_GRID) grid.push(boxAt(gx, gy));
      const dist = (r: Box) => (r.x + r.w / 2 - mx) ** 2 + (r.y + r.h / 2 - my) ** 2;
      grid.sort((a, b) => dist(a) - dist(b) || a.y - b.y || a.x - b.x);
      box = grid.find(clear) ?? along.find(clearOfCaptions) ?? grid.find(clearOfCaptions) ?? along[0]!;
    }
    captions.push(box);
    return {
      id: `e${i + 1}`, n: i + 1, from: a.id, to: b.id, data: f.data, label, caption, crossesBoundary: zone(f.from) !== zone(f.to),
      path: `M${x0} ${y0} C${x1} ${y1} ${x2} ${y2} ${x3} ${y3}`,
      labelX: r1(box.x + box.w / 2), labelY: r1(box.y + CAPTION_BASE), captionBox: box,
    };
  });

  const threats: DiagramThreat[] = placed.map((p) => ({ id: p.t.id, title: p.t.title, severity: p.t.severity, state: p.t.state, nodeId: p.at === null ? null : nodeId(p.at), open: p.open }));
  const unplacedBoundaries = boundaryNames.filter((_, i) => !usedBoundaries.includes(i));
  const model: DiagramModel = { width, height, nodes, edges, boundaries, unplacedBoundaries, threats, unplacedThreats: threats.filter((t) => t.nodeId === null).length, summary: '' };
  model.summary = summarise(model, boundaryNames.length);
  return model;
}

function summarise(m: DiagramModel, namedBoundaries: number): string {
  if (m.nodes.length === 0) return 'No architecture was extracted for this review.';
  const n = (k: DiagramNodeKind) => m.nodes.filter((x) => x.kind === k).length;
  const parts: string[] = [];
  if (n('external')) parts.push(plural(n('external'), 'external entity', 'external entities'));
  if (n('process')) parts.push(plural(n('process'), 'process', 'processes'));
  if (n('store')) parts.push(plural(n('store'), 'data store', 'data stores'));
  const crossing = m.edges.filter((e) => e.crossesBoundary).length;
  parts.push(`${plural(m.edges.length, 'data flow', 'data flows')}${crossing ? ` (${crossing} ${crossing === 1 ? 'crosses' : 'cross'} a trust boundary)` : ''}`);
  if (namedBoundaries) parts.push(plural(namedBoundaries, 'trust boundary', 'trust boundaries'));
  const open = m.nodes.reduce((s, x) => s + x.openCount, 0);
  const on = m.nodes.filter((x) => x.openCount > 0);
  const max = on.reduce<Severity | null>((acc, x) => (acc === null || severityRank(x.maxSeverity!) > severityRank(acc) ? x.maxSeverity : acc), null);
  const threats = open ? `${plural(open, 'open threat', 'open threats')} on ${plural(on.length, 'element', 'elements')}; highest open severity ${max}.` : 'No open threats on the diagram.';
  return `Data-flow diagram: ${parts.join(', ')}. ${threats}`;
}

/**
 * The diagram as compact text for coding agents (get-review): elements with their boundary and threats, then numbered
 * flows, then the trust boundaries. `refOf` turns a threat id into the caller's short ref (T-n); threats without one
 * are only counted. Cut to `limit` characters.
 */
export function diagramText(m: DiagramModel, refOf: (threatId: string) => string | undefined = () => undefined, limit = 6000): string {
  if (m.nodes.length === 0) return m.summary;
  const byId = new Map(m.nodes.map((x) => [x.id, x]));
  const bName = new Map(m.boundaries.map((b) => [b.id, b.name]));
  const lines = [m.summary, 'Elements:'];
  for (const x of m.nodes) {
    let line = `- [${x.kind}] ${x.name}`;
    if (x.boundaryId) line += ` (in: ${bName.get(x.boundaryId)})`;
    if (x.inferred) line += x.inferred === 'flow' ? ' (named only in a flow)' : ' (named only by a threat)';
    if (x.threatCount) {
      const refs = x.threatIds.map(refOf).filter((r): r is string => !!r);
      line += ` - ${x.openCount ? `${plural(x.openCount, 'open threat', 'open threats')}, highest ${x.maxSeverity}` : `${plural(x.threatCount, 'threat', 'threats')}, none open`}${refs.length ? `: ${refs.join(', ')}` : ''}`;
    }
    lines.push(line);
  }
  if (m.edges.length) {
    lines.push('Flows:');
    for (const e of m.edges) lines.push(`${e.n}. ${byId.get(e.from)!.name} -> ${byId.get(e.to)!.name}${e.data ? `: ${e.data}` : ''}${e.crossesBoundary ? ' [crosses a trust boundary]' : ''}`);
  }
  if (m.boundaries.length || m.unplacedBoundaries.length) {
    lines.push('Trust boundaries:');
    for (const b of m.boundaries) lines.push(`- ${b.name}${b.implied ? ' (implied)' : ''}: ${b.nodeIds.map((id) => byId.get(id)!.name).join(', ')}`);
    for (const b of m.unplacedBoundaries) lines.push(`- ${b} (not tied to an element)`);
  }
  if (m.unplacedThreats) lines.push(`${plural(m.unplacedThreats, 'threat names', 'threats name')} no component.`);
  const all = lines.join('\n');
  if (all.length <= limit) return all;
  const tail = '\n… (truncated)';
  const out: string[] = [];
  let size = 0;
  for (const l of lines) {
    if (size + l.length + 1 + tail.length > limit) break;
    out.push(l);
    size += l.length + 1;
  }
  return out.join('\n') + tail;
}

const SKETCH_LISTS = ['components', 'dataStores', 'externalServices', 'trustBoundaries'] as const;

/**
 * The sketch a review's diagram is drawn from: the engine's injection-check sketch (it has flows) when the stage
 * completed, else the union of the agent runs' sketches (no flows). Strings that read like instructions to an AI are
 * dropped. Null when there is nothing to draw.
 */
export function sketchForDiagram(extractCheckpoint: unknown, samples: readonly Sample[]): Required<DiagramSketch> | null {
  const parsed = ArchitectureSketchSchema.safeParse((extractCheckpoint as { sketch?: unknown } | null | undefined)?.sketch);
  const out: Required<DiagramSketch> = { components: [], dataStores: [], externalServices: [], trustBoundaries: [], flows: [] };
  const seen = new Map<string, Set<string>>(SKETCH_LISTS.map((k) => [k, new Set()]));
  const push = (k: (typeof SKETCH_LISTS)[number], v: unknown) => {
    const name = clean(v);
    if (!name || out[k].length >= 30 || seen.get(k)!.has(nameKey(name))) return;
    seen.get(k)!.add(nameKey(name));
    out[k].push(name);
  };
  if (parsed.success) {
    for (const k of SKETCH_LISTS) for (const v of parsed.data[k]) push(k, v);
    out.flows = parsed.data.flows.filter((f) => clean(f.from) && clean(f.to) && (!f.data.trim() || clean(f.data)));
  } else {
    for (const s of samples) {
      if (isFailedSample(s) || !s.sketch) continue;
      for (const k of SKETCH_LISTS) for (const v of s.sketch[k] ?? []) push(k, v);
    }
  }
  return SKETCH_LISTS.some((k) => out[k].length > 0) || out.flows.length > 0 ? out : null;
}
