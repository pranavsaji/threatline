import { strideDefaults } from '@threatline/frameworks';
import type { Stride, Threat } from '@threatline/shared';
import { normalizeText } from './threats/text.js';

/**
 * "Seen before" (docs/MEMORY.md): deterministic, explainable matching of a threat against the site's history — past
 * incidents, and the same threat on other work items' reviews. No model call. Every match carries the one-line reason
 * it was made, built only from what the two sides share.
 */

/** At most this many history items per threat. */
export const MEMORY_MAX_PER_THREAT = 3;

/**
 * Words that say nothing about which threat it is: they appear in almost every threat or incident ("an attacker could
 * access the data of another user"). Matched after the light stemming below, so plurals are covered.
 */
const GENERIC = new Set([
  'a', 'an', 'the', 'in', 'via', 'of', 'to', 'for', 'through', 'by', 'with', 'on', 'and', 'or', 'from', 'into', 'is', 'are', 'be', 'been', 'being',
  'can', 'could', 'may', 'might', 'would', 'should', 'will', 'its', 'it', 'their', 'they', 'them', 'this', 'that', 'these', 'those', 'there', 'here',
  'was', 'were', 'has', 'have', 'had', 'do', 'doe', 'did', 'not', 'no', 'any', 'all', 'some', 'just', 'also', 'when', 'after', 'before', 'while',
  'so', 'as', 'at', 'if', 'then', 'than', 'out', 'up', 'one', 'two', 'over', 'under', 'without', 'within', 'about', 'only', 'more', 'less', 'very',
  'other', 'another', 'someone', 'anyone', 'everyone', 'somebody', 'anybody', 'attacker', 'malicious', 'user', 'person', 'people', 'thing',
  'data', 'information', 'system', 'service', 'app', 'application', 'feature', 'issue', 'problem', 'risk', 'threat', 'security', 'way', 'make',
  'get', 'got', 'let', 'allow', 'allowed', 'allowing', 'use', 'used', 'using', 'able', 'which', 'who', 'what', 'how', 'why', 'where', 'his', 'her',
  'again', 'twice', 'once', 'we', 'our', 'us', 'you', 'your', 'i', 'my', 'me', 'him', 'she', 'he', 'new', 'old', 'same', 'each', 'every', 'many', 'much', 'own',
]);

/**
 * Plurals and the -ed / -ing verb endings, so "addresses" meets "address", "refunds" meets "refund" and "returned" meets
 * "returns". Deliberately light: both sides go through the same function, so a crude stem still compares like with like.
 */
export function memoryStem(w: string): string {
  if (w.length > 5 && w.endsWith('ing')) return w.slice(0, -3);
  if (w.length > 4 && w.endsWith('ed') && !w.endsWith('eed')) return w.slice(0, -2);
  if (w.length > 4 && w.endsWith('ies')) return `${w.slice(0, -3)}y`;
  if (w.length > 4 && /(ss|x|ch|sh)es$/.test(w)) return w.slice(0, -2);
  if (w.length > 3 && w.endsWith('s') && !w.endsWith('ss') && !w.endsWith('us') && !w.endsWith('is')) return w.slice(0, -1);
  return w;
}

/** Memo for memoryWords: a review is matched against up to a thousand past threats, each pair re-reading both texts. */
const WORDS = new Map<string, ReadonlySet<string>>();
const WORDS_MAX = 5000;

/** The distinctive words of a text: normalised, stemmed, generic words and single characters dropped. */
export function memoryWords(text: string): ReadonlySet<string> {
  const hit = WORDS.get(text);
  if (hit) return hit;
  if (WORDS.size >= WORDS_MAX) WORDS.clear();
  const out = new Set<string>();
  for (const raw of normalizeText(text).split(' ')) {
    if (raw.length < 2 || /^\d+$/.test(raw)) continue;
    const w = memoryStem(raw);
    if (!GENERIC.has(w) && !GENERIC.has(raw)) out.add(w);
  }
  WORDS.set(text, out);
  return out;
}

const shared = (a: ReadonlySet<string>, b: ReadonlySet<string>): string[] => [...a].filter((w) => b.has(w)).sort();
const lower = (xs: readonly string[]) => xs.map((x) => x.trim().toLowerCase()).filter((x) => x.length > 0);
const CWE_REF = /\bCWE-(\d{1,5})\b/gi;

/** The threat's CWE ids, and which of them say more than its STRIDE category (every threat gets that one's first CWE). */
export function cwesOf(t: Pick<Threat, 'mappings' | 'stride'>): { all: string[]; specific: string[] } {
  const all = [...new Set(t.mappings.filter((m) => m.framework === 'CWE').map((m) => m.refId.toUpperCase()))];
  const generic = strideDefaults(t.stride).cwe[0]?.toUpperCase();
  return { all, specific: all.filter((c) => c !== generic) };
}

/** What a threat is matched on. */
export type MemoryThreat = Pick<Threat, 'id' | 'stride' | 'title' | 'plainLanguage' | 'component' | 'mappings'>;

/** A past incident: a work item the site's incident rule recognises (docs/INCIDENTS.md). */
export interface MemoryIncident {
  id: string;
  key: string;
  summary: string;
  description: string;
  components: readonly string[];
  /** Linked to the work item under review. */
  linked: boolean;
}

export interface MemoryMatch {
  /** Higher is closer; only for ordering. */
  score: number;
  /** One line a person can check: "same component payments; shared words: refund, webhook, retry". */
  reason: string;
}

/** Thresholds, exported for docs/MEMORY.md and the tests. */
export const MEMORY_RULES = {
  /** An incident on the same component as the work item (or linked to it): shared distinctive words and their share of the threat's words. */
  incidentNearby: { words: 3, coverage: 0.25 },
  /** An incident anywhere else on the site must share more. */
  incidentAnywhere: { words: 4, coverage: 0.4 },
  /** The same threat elsewhere through a CWE that says more than the STRIDE category. */
  threatCwe: { words: 2, jaccard: 0.2 },
  /** The same threat elsewhere through the same STRIDE category and asset (component). */
  threatAsset: { words: 2, jaccard: 0.25 },
  /** The same threat elsewhere through the same STRIDE category alone. */
  threatStride: { words: 3, jaccard: 0.4 },
} as const;

const wordsList = (w: readonly string[], max = 4) => `${w.slice(0, max).join(', ')}${w.length > max ? '…' : ''}`;
const threatText = (t: Pick<Threat, 'title' | 'plainLanguage'>) => `${t.title} ${t.plainLanguage}`;

/**
 * A past incident matches a threat when the incident names one of the threat's CWEs, or when it shares enough
 * distinctive words with the threat's title and plain-language line: fewer when the incident is on one of the work
 * item's components or linked to it, more when it is anywhere else on the site.
 */
export function matchIncident(t: MemoryThreat, workItemComponents: readonly string[], inc: MemoryIncident): MemoryMatch | null {
  const tw = memoryWords(threatText(t));
  if (tw.size === 0) return null;
  const text = `${inc.summary} ${inc.description}`;
  const iw = memoryWords(text);
  const common = shared(tw, iw);
  const coverage = common.length / tw.size;
  const named = [...text.matchAll(CWE_REF)].map((m) => `CWE-${m[1]}`);
  const cwe = cwesOf(t).all.find((c) => named.includes(c));
  const mine = new Set(lower(workItemComponents));
  const component = inc.components.find((c) => mine.has(c.trim().toLowerCase()));
  const nearby = component !== undefined || inc.linked;
  const rule = nearby ? MEMORY_RULES.incidentNearby : MEMORY_RULES.incidentAnywhere;
  const byWords = common.length >= rule.words && coverage >= rule.coverage;
  if (!cwe && !byWords) return null;
  const why = [
    ...(cwe ? [`names ${cwe}`] : []),
    ...(component ? [`same component ${component}`] : inc.linked ? ['linked to this work item'] : []),
    ...(common.length > 0 ? [`shared words: ${wordsList(common)}`] : []),
  ];
  return { score: coverage + (cwe ? 1 : 0) + (nearby ? 0.3 : 0), reason: why.join('; ') };
}

const STRIDE_WORDS: Record<Stride, string> = {
  Spoofing: 'Spoofing',
  Tampering: 'Tampering',
  Repudiation: 'Repudiation',
  InformationDisclosure: 'Information disclosure',
  DenialOfService: 'Denial of service',
  ElevationOfPrivilege: 'Elevation of privilege',
};

/**
 * The same threat on another work item's review: a CWE beyond the STRIDE default in common and similar wording; or the
 * same STRIDE category and asset (component) and similar wording; or the same STRIDE category and closely similar
 * wording. Similar wording is the Jaccard overlap of the distinctive words of title and plain-language line.
 */
export function matchPastThreat(t: MemoryThreat, past: MemoryThreat): MemoryMatch | null {
  const a = memoryWords(threatText(t));
  const b = memoryWords(threatText(past));
  const common = shared(a, b);
  const union = a.size + b.size - common.length;
  const j = union === 0 ? 0 : common.length / union;
  const pastCwes = new Set(cwesOf(past).specific);
  const cwe = cwesOf(t).specific.find((c) => pastCwes.has(c));
  const sameStride = t.stride === past.stride;
  const ca = memoryWords(t.component);
  const cb = memoryWords(past.component);
  const assetCommon = shared(ca, cb);
  const sameAsset = assetCommon.length > 0 && assetCommon.length / (ca.size + cb.size - assetCommon.length) >= 0.5;
  const R = MEMORY_RULES;
  const viaCwe = cwe !== undefined && common.length >= R.threatCwe.words && j >= R.threatCwe.jaccard;
  const viaAsset = sameStride && sameAsset && common.length >= R.threatAsset.words && j >= R.threatAsset.jaccard;
  const viaStride = sameStride && common.length >= R.threatStride.words && j >= R.threatStride.jaccard;
  if (!viaCwe && !viaAsset && !viaStride) return null;
  const why = [
    ...(viaCwe ? [`same ${cwe}`] : sameStride ? [`same STRIDE category (${STRIDE_WORDS[t.stride]})`] : []),
    ...(sameAsset ? [`same asset (${past.component.trim()})`] : []),
    `shared words: ${wordsList(common)}`,
  ];
  return { score: j + (viaCwe ? 0.5 : 0) + (sameStride ? 0.2 : 0) + (sameAsset ? 0.2 : 0), reason: why.join('; ') };
}

/** "PR #41" from a Bitbucket, GitHub or GitLab pull request link; null when the link names no number. */
export function pullRequestNumber(url: string): string | null {
  const m = /\/(?:pull-requests|pull|merge_requests)\/(\d{1,9})(?:[/?#]|$)/.exec(url);
  return m ? m[1]! : null;
}
