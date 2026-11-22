import {
  AgentThreatModelSchema,
  MAX_SKETCH_STRING,
  err,
  ok,
  severityRank,
  type AgentThreat,
  ThreatRatingSchema,
  type AgentThreatModel,
  type Citation,
  type ContextBundle,
  type ContextFact,
  type DismissReason,
  type Mapping,
  type Result,
  type Review,
  type ReviewStatus,
  type SitePolicy,
  type Stride,
  type Threat,
} from '@threatline/shared';
import { sha256Hex } from '@threatline/crypto';
import { extractSignals, type Signals } from './context/signals.js';
import { htmlToText } from './context/normalize.js';
import { baselineThreats, coveredByText } from './baseline/rules.js';
import { clusterSamples, consensus, similar, voteThreshold } from './threats/cluster.js';
import { groundQuote } from './threats/grounding.js';
import { mapThreat } from './threats/mapping.js';
import { plainLanguageFor } from './threats/plain-language.js';
import { boundedScores, ratedScores, severityOf } from './threats/severity.js';
import { normalizeText } from './threats/text.js';
import { riskScore } from './scoring.js';
import { diffBundles, threatsToReevaluate } from './incremental.js';
import { isFailedSample, type DiscardedThreat, type Sample } from './ports.js';
import { applySuppressions, type ActiveSuppression } from './suppressions.js';

export const AGENT_SCHEMA_MARKER = 'threatline.threatmodel.v1';
const LEGACY_SCHEMA_MARKER = 'redline.threatmodel.v1';
export const MAX_AGENT_RESPONSE_BYTES = 200 * 1024;
const MAX_CANDIDATES = 50;
const MAX_CITATIONS = 4;

export type ExtractErrorCode = 'no_json' | 'invalid_json' | 'schema' | 'wrong_issue' | 'too_large';

/** Top-level `{...}` spans, string- and escape-aware. */
function balancedObjects(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length && out.length < MAX_CANDIDATES; i++) {
    const c = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"' && depth > 0) inString = true;
    else if (c === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (c === '}' && depth > 0) {
      depth--;
      if (depth === 0 && start >= 0) out.push(text.slice(start, i + 1));
    }
  }
  return out;
}

function candidates(text: string): string[] {
  const list = [text.trim()];
  for (const m of text.matchAll(/```(?:json)?\s*([\s\S]*?)```/g)) if (m[1]) list.push(m[1].trim());
  list.push(...balancedObjects(text));
  return list;
}

/** First JSON object found in model output (bare, fenced or embedded), or null. Used by the pipeline stages. */
export function parseFirstObject(text: string): Record<string, unknown> | null {
  for (const c of candidates(text)) {
    if (!c.startsWith('{')) continue;
    try {
      const v: unknown = JSON.parse(c);
      if (typeof v === 'object' && v !== null && !Array.isArray(v)) return v as Record<string, unknown>;
    } catch {
      /* next candidate */
    }
  }
  return null;
}

function tryExtract(text: string, expectedIssueKey: string): Result<AgentThreatModel, { code: ExtractErrorCode; message: string }> {
  const parsed: unknown[] = [];
  for (const c of candidates(text)) {
    if (!c.startsWith('{')) continue;
    try {
      parsed.push(JSON.parse(c));
    } catch {
      /* not this candidate */
    }
  }
  const objects = parsed.filter((p): p is Record<string, unknown> => typeof p === 'object' && p !== null && !Array.isArray(p));
  const marked = objects.find((o) => o.schema === AGENT_SCHEMA_MARKER || o.schema === LEGACY_SCHEMA_MARKER);
  if (!marked) {
    if (objects.length > 0) return err({ code: 'schema', message: `no JSON object with "schema": "${AGENT_SCHEMA_MARKER}"` });
    return err(text.includes('{') ? { code: 'invalid_json', message: 'JSON could not be parsed (truncated or malformed)' } : { code: 'no_json', message: 'no JSON found in agent response' });
  }
  if (typeof marked.issueKey !== 'string' || marked.issueKey.toUpperCase() !== expectedIssueKey.toUpperCase())
    return err({ code: 'wrong_issue', message: `threat model is for ${String(marked.issueKey)}, expected ${expectedIssueKey}` });
  const r = AgentThreatModelSchema.safeParse(marked);
  if (!r.success) {
    const first = r.error.issues[0];
    return err({ code: 'schema', message: `schema: ${first ? `${first.path.join('.')}: ${first.message}` : 'invalid'}` });
  }
  return ok(r.data);
}

/** Tolerant parser for agent output: bare JSON, fenced, embedded in prose, or HTML-escaped by a smart value. Never throws. */
export function extractAgentJson(raw: string, expectedIssueKey: string): Result<AgentThreatModel, { code: ExtractErrorCode; message: string }> {
  if (raw.length > MAX_AGENT_RESPONSE_BYTES) return err({ code: 'too_large', message: `agent response exceeds ${MAX_AGENT_RESPONSE_BYTES} bytes` });
  const first = tryExtract(raw, expectedIssueKey);
  if (first.ok || (first.error.code !== 'no_json' && first.error.code !== 'invalid_json') || !/&quot;|&#34;/.test(raw)) return first;
  const decoded = tryExtract(htmlToText(raw), expectedIssueKey);
  return decoded.ok ? decoded : first;
}

export interface AssembleInput {
  review: Review;
  bundle: ContextBundle;
  samples: Sample[];
  samplesExpected: number;
  priorDismissed: Array<{ title: string; stride: Stride; reason: DismissReason }>;
  policy: SitePolicy;
  promptVersion: string;
  now: Date;
  /** 'final' is used by the timeout sweeper: assemble with whatever arrived. */
  mode?: 'progress' | 'final';
  /** Extra injection signal from outside the facts (e.g. the quarantined extractor flagged the material). */
  injectionSuspected?: boolean;
  /** Off only to replay how a review looked before coverage existed (eval recordings); default on. */
  coverage?: boolean;
  /**
   * R7: the previous revision's threats and facts. Threats whose citations all point at unchanged sources are carried
   * over with their votes, state and triage; agent output then only adds threats (or raises a carried one's severity).
   */
  prior?: { threats: readonly Threat[]; facts: ReadonlyArray<Pick<ContextFact, 'id' | 'sourceAri' | 'version'>> };
  /**
   * Team suppression rules of the work item's project, and those a champion unhid on this work item. None in the eval.
   * Never applied under suspected injection, and never to a threat at or above the blocking threshold.
   */
  suppressions?: { rules: readonly ActiveSuppression[]; unhidden?: readonly string[] };
}
export interface AssembleOutput {
  threats: Threat[];
  discarded: DiscardedThreat[];
  riskScore: number;
  status: ReviewStatus;
  /** Why a review with some valid runs still did not settle (e.g. "only 1 of 3 analyses completed"). */
  failureReason?: string;
  injectionSuspected: boolean;
  signals: Signals;
}

const EXPOSURE_ORDER = ['internal', 'partner', 'public'] as const;

/** The agent sketch may raise exposure, data classes and LLM features above the deterministic signals, never lower them. */
function raiseSignals(signals: Signals, models: AgentThreatModel[]): Signals {
  let exposure = signals.exposure;
  const dataClasses = new Set(signals.dataClasses);
  let llm = signals.llmFeatures;
  for (const m of models) {
    const s = m.sketch;
    if (!s) continue;
    if (s.exposure && EXPOSURE_ORDER.indexOf(s.exposure) > EXPOSURE_ORDER.indexOf(exposure)) exposure = s.exposure;
    for (const d of s.dataClasses ?? []) dataClasses.add(d);
    if (s.llmFeatures) llm = true;
  }
  return { ...signals, exposure, dataClasses: [...dataClasses], llmFeatures: llm, payment: signals.payment || dataClasses.has('payment') };
}

/** The signals a review is scored on: the deterministic ones from the facts, raised by the agent sketches. */
export function reviewSignals(facts: readonly ContextFact[], samples: readonly Sample[]): Signals {
  return raiseSignals(extractSignals([...facts]), samples.filter((s): s is AgentThreatModel => !isFailedSample(s)));
}

const threatId = (reviewId: string, origin: string, stride: string, title: string, extra?: string): string =>
  `thr_${sha256Hex(`${reviewId}|${origin}|${stride}|${normalizeText(title)}${extra === undefined ? '' : `|${extra}`}`).slice(0, 16)}`;

/**
 * Threat ids are unique within a review (they are the threats table's primary key). The first threat of a kind and
 * title keeps the plain id; a distinct one with the same kind and title (another component) gets its component, then a
 * counter, in its id. Deterministic, so re-assembling the same samples gives the same ids.
 */
function claimId(taken: ReadonlySet<string>, reviewId: string, origin: string, t: Pick<Threat, 'stride' | 'title' | 'component'>): string {
  const plain = threatId(reviewId, origin, t.stride, t.title);
  if (!taken.has(plain)) return plain;
  const component = normalizeText(t.component);
  for (let n = 1; ; n++) {
    const id = threatId(reviewId, origin, t.stride, t.title, n === 1 ? component : `${component}|${n}`);
    if (!taken.has(id)) return id;
  }
}
const idsOf = (threats: readonly Threat[], except?: number) => new Set(threats.filter((_, n) => n !== except).map((t) => t.id));

const maxSeverity = <T extends { severity: Threat['severity'] }>(a: T, b: T) => (severityRank(a.severity) >= severityRank(b.severity) ? a : b);

function mergeMappings(a: Mapping[], b: Mapping[]): Mapping[] {
  const out = [...a];
  for (const m of b) if (!out.some((x) => x.framework === m.framework && x.refId === m.refId)) out.push(m);
  return out;
}

function addCitations(into: Citation[], extra: Citation[]): Citation[] {
  const out = [...into];
  for (const c of extra) if (out.length < MAX_CITATIONS && !out.some((x) => x.factId === c.factId && x.quote === c.quote)) out.push(c);
  return out;
}

/**
 * Deterministic review assembly. The contract the gates rely on:
 * baseline threats always present; agent threats need majority votes and a resolvable citation; the agent can raise severity
 * or exposure but never lower them; weakly grounded or injection-touched agent threats go to needs_human.
 */
/** A threat with a rating gets Threatline's likelihood and impact for it; the model's own numbers are a fallback. */
const rated = (t: AgentThreat): AgentThreat => (t.rating ? { ...t, ...boundedScores(ratedScores(t.rating), t) } : t);

/** The median of 1–5 scores; with an even count, the upper of the two middle values (never below a majority). */
export function centralScore(xs: readonly number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)]!;
}

export function assembleReview(i: AssembleInput): AssembleOutput {
  const facts = i.bundle.facts;
  const valid = i.samples.filter((s): s is AgentThreatModel => !isFailedSample(s));
  const discarded: DiscardedThreat[] = i.samples.flatMap((s, n) => (isFailedSample(s) ? [{ title: `Agent run ${n + 1}: ${s.failed}`, reason: 'schema' as const }] : []));
  const signals = reviewSignals(facts, valid);
  const injectionSuspected = facts.some((f) => f.injectionSuspected) || i.injectionSuspected === true;
  const factById = new Map(facts.map((f) => [f.id, f]));
  const voteBase = Math.max(1, valid.length);
  // When the material shows signs of injection, earlier dismissals are not applied: suppression must never be steerable by attacker text.
  const isDismissed = (t: { stride: Stride; title: string; component: string }) =>
    !injectionSuspected && i.priorDismissed.some((d) => similar(t, { ...d, component: t.component }, { ignoreComponent: true }));

  // 1. Baseline threats (deterministic, always cited verbatim).
  const threats: Threat[] = [];
  for (const b of baselineThreats(signals)) {
    if (isDismissed(b)) {
      discarded.push({ title: b.title, stride: b.stride, reason: 'duplicate_of_dismissed' });
      continue;
    }
    const citations = b.evidence.flatMap((e) => {
      const g = groundQuote(e.quote, facts);
      return g.factId ? [{ factId: g.factId, quote: e.quote }] : [];
    });
    if (citations.length === 0) continue;
    threats.push({
      id: claimId(idsOf(threats), i.review.id, 'baseline', b),
      reviewId: i.review.id,
      stride: b.stride,
      title: b.title,
      scenario: b.scenario,
      component: b.component,
      likelihood: b.likelihood,
      impact: b.impact,
      severity: severityOf(b.likelihood, b.impact),
      votes: i.samplesExpected,
      samples: i.samplesExpected,
      grounding: 'supported',
      confidence: 1,
      state: 'accepted',
      origin: 'baseline',
      citations,
      mappings: mapThreat(b, signals.llmFeatures),
      plainLanguage: plainLanguageFor(b),
    });
  }
  const baselineCount = threats.length;

  // 2. Agent threats: cluster across samples, keep majority.
  const { kept: majority, discarded: lowVotes } = consensus(clusterSamples(valid.map((m) => m.threats.map(rated))), voteBase);
  // Under suspected injection a minority threat may be one the injection silenced in the other runs: keep it (it still
  // needs a verbatim quote, and becomes needs_human below) rather than let the attacker's text vote it out.
  const kept = injectionSuspected ? [...majority, ...lowVotes.map((d) => d.cluster)] : majority;
  if (!injectionSuspected) for (const d of lowVotes) discarded.push({ title: d.cluster.representative.title, stride: d.cluster.representative.stride, reason: 'low_votes' });

  for (const cluster of kept) {
    const rep: AgentThreat = cluster.representative;
    const quotes = [...new Set(cluster.members.flatMap((m) => m.evidence.map((e) => e.quote)))];
    const grounded = quotes.map((q) => ({ q, g: groundQuote(q, facts) })).filter((x) => x.g.grounding !== 'unsupported' && x.g.factId);
    if (grounded.length === 0) {
      discarded.push({ title: rep.title, stride: rep.stride, reason: 'unsupported_citation' });
      continue;
    }
    if (isDismissed(rep)) {
      discarded.push({ title: rep.title, stride: rep.stride, reason: 'duplicate_of_dismissed' });
      continue;
    }
    const citations = grounded.slice(0, MAX_CITATIONS).map((x) => ({ factId: x.g.factId!, quote: x.q }));
    const supported = grounded.some((x) => x.g.grounding === 'supported');
    // The runs' central score, not the highest: one run's outlier should not decide what blocks Done. Under suspected
    // injection the highest stands, so attacker text that talks one run down cannot lower the outcome.
    const pick = injectionSuspected ? (xs: number[]) => Math.max(...xs) : centralScore;
    const likelihood = pick(cluster.members.map((m) => m.likelihood));
    const impact = pick(cluster.members.map((m) => m.impact));
    const agentSeverity = severityOf(likelihood, impact);

    const touchedByInjection = citations.some((c) => factById.get(c.factId)?.injectionSuspected) || injectionSuspected;
    const trusted = supported && !touchedByInjection;

    const baseIdx = threats.slice(0, baselineCount).findIndex((b) => similar(b, rep, { ignoreComponent: true }));
    if (baseIdx >= 0) {
      const b = threats[baseIdx]!;
      const raised = maxSeverity(b, { ...b, severity: agentSeverity });
      // Raising severity is always safe. Text and citations only merge from a well-grounded, injection-free cluster,
      // so attacker-influenced output can never rewrite what a deterministic threat asks people to do.
      threats[baseIdx] = {
        ...b,
        severity: raised.severity,
        likelihood: Math.max(b.likelihood, likelihood),
        impact: Math.max(b.impact, impact),
        ...(trusted
          ? {
              citations: addCitations(b.citations, citations),
              mappings: mergeMappings(b.mappings, mapThreat(rep, signals.llmFeatures)),
              ...(rep.requirement && !b.suggestedRequirement ? { suggestedRequirement: rep.requirement } : {}),
            }
          : {}),
      };
      continue;
    }

    threats.push({
      id: claimId(idsOf(threats), i.review.id, 'agent', rep),
      reviewId: i.review.id,
      stride: rep.stride,
      title: rep.title,
      scenario: rep.scenario,
      component: rep.component,
      likelihood,
      impact,
      severity: agentSeverity,
      votes: cluster.sampleIndexes.length,
      samples: voteBase,
      grounding: supported ? 'supported' : 'weak',
      confidence: Math.min(1, (cluster.sampleIndexes.length / voteBase) * (supported ? 1 : 0.6)),
      state: !supported || touchedByInjection ? 'needs_human' : 'accepted',
      origin: 'agent',
      citations,
      mappings: mapThreat(rep, signals.llmFeatures),
      plainLanguage: plainLanguageFor(rep),
      ...(rep.requirement ? { suggestedRequirement: rep.requirement } : {}),
    });
  }

  const carried = i.prior ? carryOver(threats, i.prior, facts, i.review.id, injectionSuspected, i.samples.length >= i.samplesExpected, i.policy) : new Set<string>();

  // Team suppression rules, before coverage: a hidden AI threat covers nothing, and a hidden rule-based one is not covered.
  applySuppressions(threats, i.suppressions?.rules ?? [], { blockAtOrAbove: i.policy.blockAtOrAbove, injectionSuspected, now: i.now, unhidden: new Set(i.suppressions?.unhidden ?? []) });

  // 3. Noise: a generic rule-based threat stands back (state `covered`) when a trusted AI threat (majority-voted,
  // quoted word for word, untouched by injection) of the same kind and on the same topic covers it, rated at most one
  // level below it: the specific threat's rating (from the facts it states) replaces the generic rule's default severity,
  // so "personal data exposed" (High by default) does not return as a High duplicate of a Medium user-enumeration threat.
  // It stays stored and comes back if that AI threat is dismissed. Its framework mappings move to the AI threat. Never
  // under suspected injection (attacker text must not steer what is shown), and never for a rule-based threat carried
  // from an earlier revision, whose triage stands.
  if (!injectionSuspected && i.coverage !== false) {
    for (const b of threats) {
      if (b.origin !== 'baseline' || b.state !== 'accepted' || carried.has(b.id)) continue;
      const cover = threats.find(
        (t) => t.origin === 'agent' && t.state === 'accepted' && t.grounding === 'supported' && severityRank(t.severity) >= severityRank(b.severity) - 1 && coveredByText(b.title, t),
      );
      if (!cover) continue;
      cover.mappings = mergeMappings(cover.mappings, b.mappings);
      b.state = 'covered';
      b.coveredBy = cover.id;
    }
  }

  threats.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.votes - a.votes || a.title.localeCompare(b.title));

  const received = i.samples.length;
  // Fail closed: a review settles only when a majority of the expected runs produced a valid analysis (2 of 3), so one
  // unchecked run never decides. Failed runs (AI errors) count as missing, like runs that never arrived.
  const enough = valid.length > 0 && valid.length >= voteThreshold(i.samplesExpected);
  const shortfall = `only ${valid.length} of ${i.samplesExpected} analyses completed`;
  let status: ReviewStatus;
  if (i.mode === 'final') status = enough ? 'ready' : 'agent_timeout';
  else if (received < i.samplesExpected) status = 'awaiting_agent';
  else status = enough ? 'ready' : 'failed';
  const failureReason = (status === 'failed' || status === 'agent_timeout') && valid.length > 0 ? shortfall : undefined;

  return {
    threats,
    discarded,
    riskScore: riskScore(threats, signals),
    status,
    ...(failureReason ? { failureReason } : {}),
    injectionSuspected,
    signals,
  };
}

/**
 * R7, in place: prior threats citing only unchanged facts carry over with their votes, state and triage. A fresh
 * threat is folded into its carried counterpart only when it too cites only unchanged facts; one citing a new or
 * changed source stays new, so new evidence is never hidden behind an old decision. The stricter state wins (a fresh
 * needs_human is never downgraded), and when the material shows injection an earlier dismissal does not suppress the
 * fresh threat. Severity only rises. Prior threats citing a changed or removed source are not carried, nor are rule-based
 * threats the rules no longer raise, nor (once the new runs are all in) AI threats none of them raised again.
 */
function carryOver(threats: Threat[], prior: NonNullable<AssembleInput['prior']>, facts: readonly ContextFact[], reviewId: string, injectionSuspected: boolean, complete = false, policy?: Pick<SitePolicy, 'blockAtOrAbove'>): Set<string> {
  const present = new Set(facts.map((f) => f.id));
  const unchanged = new Set(prior.facts.map((f) => f.id).filter((id) => present.has(id)));
  const onlyUnchanged = (t: Pick<Threat, 'citations'>) => t.citations.length > 0 && t.citations.every((c) => unchanged.has(c.factId));
  const { keep } = threatsToReevaluate([...prior.threats], prior.facts, diffBundles(prior.facts, facts));
  const matched = new Set<number>();
  for (const old of keep) {
    // A covered rule-based threat is not a decision: coverage is worked out afresh for each revision. Nor is a
    // suppressed one: the project's rules are applied afresh too (a rule may have expired or been revoked).
    if (old.state === 'covered' || old.state === 'suppressed') continue;
    if (!onlyUnchanged(old)) continue;
    const idx = threats.findIndex((t, n) => !matched.has(n) && onlyUnchanged(t) && similar(t, old, { ignoreComponent: true }));
    const fresh = idx >= 0 ? threats[idx] : undefined;
    if (fresh) {
      matched.add(idx);
      // Under injection, the fresh assessment stands: an old dismissal must not be steerable into hiding it.
      if (injectionSuspected && old.state === 'dismissed') continue;
      const id = claimId(idsOf(threats, idx), reviewId, old.origin, old);
      const { dismissReason: _d, ...rest } = old;
      const raised = severityRank(fresh.severity) > severityRank(old.severity);
      // A dismissal (by a person or the verifier) was made at the old severity. Once the threat is re-raised at a
      // severity that gates Done, that decision no longer covers it: a champion looks again.
      const staleDismissal = raised && old.state === 'dismissed' && (!policy || isBlockingSeverity(fresh, policy));
      const stricter = staleDismissal || (fresh.state === 'needs_human' && old.state !== 'needs_human');
      threats[idx] = {
        ...(stricter ? { ...rest, state: 'needs_human' as const } : old),
        id,
        reviewId,
        ...(raised ? { severity: fresh.severity, likelihood: Math.max(old.likelihood, fresh.likelihood), impact: Math.max(old.impact, fresh.impact) } : {}),
      };
    } else {
      // Rule-based threats are derived afresh each time from the same facts: one the rules no longer raise (a rule was
      // corrected) is gone, not carried. Agent threats carry, because model runs vary from one review to the next.
      if (old.origin === 'baseline') continue;
      // Once this revision's runs are all in, a below-threshold AI threat none of them raised again goes, unless a
      // person dismissed it. Blocking ones always carry: re-running until a model misses a Critical must not pass Done
      // (the verifier can still fold a carried duplicate under the threat it repeats).
      if (complete && old.state !== 'dismissed' && policy && !isBlockingSeverity(old, policy)) continue;
      // A fresh threat with the same title but new evidence keeps its id; the carried one gets its own.
      const taken = idsOf(threats);
      const id = threatId(reviewId, old.origin, old.stride, old.title);
      const free = taken.has(id) ? claimId(taken, reviewId, `${old.origin}+prior`, old) : id;
      threats.push({ ...old, id: free, reviewId });
      matched.add(threats.length - 1);
    }
  }
  return new Set([...matched].map((n) => threats[n]!.id));
}

export const isBlockingSeverity = (t: Pick<Threat, 'severity'>, policy: Pick<SitePolicy, 'blockAtOrAbove'>): boolean =>
  severityRank(t.severity) >= severityRank(policy.blockAtOrAbove);

const AGENT_THREAT_KEYS = ['stride', 'title', 'scenario', 'component', 'likelihood', 'impact', 'evidence', 'asvs', 'cwe', 'plainLanguage', 'rating', 'requirement'] as const;
const SKETCH_KEYS = ['components', 'dataStores', 'externalServices', 'trustBoundaries', 'dataClasses', 'exposure', 'llmFeatures'] as const;
const trimWords = (v: unknown, n: number) => (typeof v === 'string' && v.length > n ? `${v.slice(0, n - 1).trimEnd()}…` : v);
const toScore = (v: unknown) => {
  const n = typeof v === 'string' && /^\d+$/.test(v.trim()) ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) ? Math.min(5, Math.max(1, Math.round(n))) : n;
};

/**
 * Threatline Engine: fits a strong model's threat model to the contract before validation. The model's own wording is
 * trimmed to the length limits, lists are capped and unknown keys dropped. A quote is only shortened from the end (no
 * ellipsis), so it stays a verbatim substring of its source and still has to be found there. Substance is not invented:
 * a threat without evidence still fails.
 */
export function fitAgentModel(raw: unknown): unknown {
  if (typeof raw !== 'object' || raw === null || !Array.isArray((raw as { threats?: unknown }).threats)) return raw;
  const o = raw as Record<string, unknown>;
  const threats = (o.threats as unknown[]).slice(0, 25).map((t) => {
    if (typeof t !== 'object' || t === null) return t;
    const x = t as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of AGENT_THREAT_KEYS) if (x[k] !== undefined && x[k] !== null) out[k] = x[k];
    out.title = trimWords(out.title, 120);
    out.scenario = trimWords(out.scenario, 600);
    out.component = trimWords(out.component, 80);
    if ('plainLanguage' in out) out.plainLanguage = trimWords(out.plainLanguage, 200);
    // A malformed rating is dropped, not fatal: severity then falls back to the model's likelihood and impact.
    if ('rating' in out && !ThreatRatingSchema.safeParse(out.rating).success) delete out.rating;
    out.likelihood = toScore(out.likelihood);
    out.impact = toScore(out.impact);
    if (Array.isArray(out.evidence))
      out.evidence = out.evidence
        .map((e) => (typeof e === 'object' && e !== null && typeof (e as { quote?: unknown }).quote === 'string' ? { quote: (e as { quote: string }).quote.slice(0, 200).trim() } : e))
        .filter((e) => !(typeof e === 'object' && e !== null && (e as { quote?: string }).quote === ''))
        .slice(0, 3);
    for (const k of ['asvs', 'cwe'] as const) if (Array.isArray(out[k])) out[k] = (out[k] as unknown[]).filter((v) => typeof v === 'string' && v.length <= 20).slice(0, 10);
    const r = out.requirement as Record<string, unknown> | undefined;
    if (r && typeof r === 'object') out.requirement = { title: trimWords(r.title, 200), given: trimWords(r.given, 300), when: trimWords(r.when, 300), then: trimWords(r.then, 300) };
    return out;
  });
  const result: Record<string, unknown> = { schema: o.schema, issueKey: o.issueKey, threats };
  if (typeof o.sketch === 'object' && o.sketch !== null) {
    const sk = o.sketch as Record<string, unknown>;
    const fitted: Record<string, unknown> = {};
    for (const k of SKETCH_KEYS) {
      const v = sk[k];
      if (v === undefined || v === null) continue;
      fitted[k] = Array.isArray(v) && k !== 'dataClasses' ? v.filter((x) => typeof x === 'string').map((x) => (x as string).slice(0, MAX_SKETCH_STRING)).slice(0, 30) : v;
    }
    result.sketch = fitted;
  }
  return result;
}
