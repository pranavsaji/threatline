import type { AgentThreat, Stride } from '@threatline/shared';
import { jaccard, normalizeText } from './text.js';

interface Comparable {
  stride: Stride;
  title: string;
  component: string;
}

const TITLE_THRESHOLD = 0.5;
const COMPONENT_THRESHOLD = 0.5;

/** Same STRIDE category, title-token Jaccard >= 0.5, and (unless ignored) the same or overlapping component. */
export function similar(a: Comparable, b: Comparable, opts: { ignoreComponent?: boolean } = {}): boolean {
  if (a.stride !== b.stride) return false;
  if (jaccard(a.title, b.title) < TITLE_THRESHOLD) return false;
  if (opts.ignoreComponent) return true;
  return a.component.trim().toLowerCase() === b.component.trim().toLowerCase() || jaccard(a.component, b.component) >= COMPONENT_THRESHOLD;
}

const EVIDENCE_THRESHOLD = 0.6;
const LOOSE_TITLE_THRESHOLD = 0.2;
const LOOSE_TEXT_THRESHOLD = 0.25;

/** Two quotes point at the same passage: one contains the other, or their words overlap strongly. */
function sameEvidence(a: AgentThreat, b: AgentThreat): boolean {
  for (const x of a.evidence)
    for (const y of b.evidence) {
      const nx = normalizeText(x.quote);
      const ny = normalizeText(y.quote);
      if (nx.length > 0 && ny.length > 0 && (nx.includes(ny) || ny.includes(nx) || jaccard(x.quote, y.quote) >= EVIDENCE_THRESHOLD)) return true;
    }
  return false;
}

const componentsMatch = (a: Comparable, b: Comparable) =>
  a.component.trim().toLowerCase() === b.component.trim().toLowerCase() || jaccard(a.component, b.component) >= COMPONENT_THRESHOLD;

/**
 * Whether two agent runs reported the same threat. Runs word titles and name components differently, so besides the
 * strict rule (similar titles and components) two threats also match when they share a STRIDE category, cite the same
 * passage, and their titles or scenarios overlap at least loosely.
 */
export function sameThreat(a: AgentThreat, b: AgentThreat): boolean {
  if (a.stride !== b.stride) return false;
  const t = jaccard(a.title, b.title);
  const e = sameEvidence(a, b);
  if (t >= TITLE_THRESHOLD && (componentsMatch(a, b) || e)) return true;
  return e && (componentsMatch(a, b) || t >= LOOSE_TITLE_THRESHOLD || jaccard(`${a.title} ${a.scenario}`, `${b.title} ${b.scenario}`) >= LOOSE_TEXT_THRESHOLD);
}

const CROSS_STRIDE_THRESHOLD = 0.4;

/**
 * The same attack filed under a different STRIDE category by another run: runs disagree on the category of about one
 * threat in five ("any service can mint tokens" is Spoofing in one run and Elevation of privilege in the next), and a
 * strict category match then splits one threat into two minority clusters that both get voted out. Stricter than
 * `sameThreat`: the same passage, and titles or scenarios that overlap clearly. Only used across runs, never to merge
 * two threats one run reported separately.
 */
export function sameThreatAnyCategory(a: AgentThreat, b: AgentThreat): boolean {
  if (a.stride === b.stride) return sameThreat(a, b);
  if (!sameEvidence(a, b)) return false;
  return jaccard(a.title, b.title) >= CROSS_STRIDE_THRESHOLD || jaccard(`${a.title} ${a.scenario}`, `${b.title} ${b.scenario}`) >= CROSS_STRIDE_THRESHOLD;
}

export interface Cluster {
  representative: AgentThreat;
  members: AgentThreat[];
  /** The run each member came from (parallel to `members`). */
  memberSamples: number[];
  sampleIndexes: number[];
}

const RESTATED_THRESHOLD = 0.3;

/**
 * One run listing the same threat twice: a match by the usual rule whose titles nearly agree, or whose titles and
 * scenarios overlap clearly (a restatement, such as "account takeover via email change without the password" and "no
 * email verification enables account hijacking"). Measured on the recorded runs: Opus 5 never restates (its same-run
 * pairs citing one passage overlap at most 0.19), Sonnet 4.5 often does (0.3 and up), and two different threats on one
 * passage ("no stated authentication" and "other customers' invoices by changing the id") sit at 0.24.
 */
const repeated = (a: AgentThreat, b: AgentThreat) =>
  sameThreat(a, b) && ((jaccard(a.title, b.title) >= TITLE_THRESHOLD && componentsMatch(a, b)) || jaccard(`${a.title} ${a.scenario}`, `${b.title} ${b.scenario}`) >= RESTATED_THRESHOLD);

const richness = (t: AgentThreat): [number, number] => [t.evidence.length, t.scenario.length];

/** The category most members gave; on a tie, the first member's. */
function majorityStride(c: Cluster): Stride {
  const count = new Map<Stride, number>();
  for (const m of c.members) count.set(m.stride, (count.get(m.stride) ?? 0) + 1);
  let best = c.members[0]!.stride;
  for (const [stride, n] of count) if (n > count.get(best)!) best = stride;
  return best;
}

const wording = (t: AgentThreat) => `${t.title} ${t.scenario}`;

/**
 * Of the clusters with a member that `matches`, the one whose matching member is worded most like `threat` (first on a
 * tie). Taking the first match instead let a threat join a neighbour's cluster: runs [[A], [A, B], [B]] with A and B on
 * one passage put run 3's B with A, leaving B one vote and A replaced by B as the representative.
 */
function closest(clusters: Cluster[], threat: AgentThreat, matches: (cl: Cluster, m: AgentThreat, i: number) => boolean): Cluster | undefined {
  let best: { c: Cluster; score: number } | undefined;
  for (const cl of clusters)
    cl.members.forEach((m, i) => {
      if (!matches(cl, m, i)) return;
      const score = jaccard(wording(m), wording(threat));
      if (!best || score > best.score) best = { c: cl, score };
    });
  return best?.c;
}

/**
 * Greedy clustering across samples; a cluster's votes are the distinct samples it appears in. A threat joins the closest
 * cluster (see `closest`) its run has not contributed to yet: one of its own category first, then one of another category (see
 * `sameThreatAnyCategory`). It joins a cluster its run already contributed to only when it repeats that member (the
 * run listed one threat twice): two different threats one run reported, citing the same passage, stay two threats
 * (live finding: "read other customers' invoices" and "no stated authentication" were chained into one). The cluster
 * then takes the category most of its members gave.
 */
export function clusterSamples(samples: ReadonlyArray<readonly AgentThreat[]>): Cluster[] {
  const clusters: Cluster[] = [];
  samples.forEach((sample, idx) => {
    for (const threat of sample) {
      const fresh = (cl: Cluster) => !cl.sampleIndexes.includes(idx);
      const c =
        closest(clusters, threat, (cl, m) => fresh(cl) && sameThreat(m, threat)) ??
        closest(clusters, threat, (cl, m) => fresh(cl) && sameThreatAnyCategory(m, threat)) ??
        closest(clusters, threat, (cl, m, i) => cl.memberSamples[i] === idx && repeated(m, threat));
      if (c) {
        c.members.push(threat);
        c.memberSamples.push(idx);
        if (!c.sampleIndexes.includes(idx)) c.sampleIndexes.push(idx);
      } else clusters.push({ representative: threat, members: [threat], memberSamples: [idx], sampleIndexes: [idx] });
    }
  });
  for (const c of clusters) {
    const stride = majorityStride(c);
    c.representative = c.members.filter((m) => m.stride === stride).reduce((best, m) => {
      const [be, bs] = richness(best);
      const [me, ms] = richness(m);
      return me > be || (me === be && ms > bs) ? m : best;
    });
    c.sampleIndexes.sort((a, b) => a - b);
  }
  return clusters;
}

/** A strict majority of the samples that answered: 2 of 2, 2 of 3, 3 of 4, 3 of 5 (spec: "keep if votes at least 3 of 5"). */
export const voteThreshold = (totalSamples: number): number => Math.floor(Math.max(1, totalSamples) / 2) + 1;

export function consensus(clusters: Cluster[], totalSamples: number): { kept: Cluster[]; discarded: Array<{ cluster: Cluster; reason: 'low_votes' }> } {
  const need = voteThreshold(totalSamples);
  const kept: Cluster[] = [];
  const discarded: Array<{ cluster: Cluster; reason: 'low_votes' }> = [];
  for (const c of clusters) {
    if (c.sampleIndexes.length >= need) kept.push(c);
    else discarded.push({ cluster: c, reason: 'low_votes' });
  }
  return { kept, discarded };
}
