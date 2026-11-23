import { severityRank, type Result, type Severity, type Threat } from '@threatline/shared';
import { FittedVerifySchema, verifyPrompt } from '@threatline/prompts';
import { appError, err, ok } from '@threatline/shared';
import { callStage, type PipelineDeps, type Usage } from './pipeline.js';

export interface Verdict4 {
  threatId: string;
  keep: boolean;
  reason: string;
  /** The threat (by id) this one repeats, when the verifier says so. */
  duplicateOf?: string;
}

/** A gap-check threat still waiting for the verifier: hidden (dismissed, `unconfirmed`) and never verified. */
export const isGapCandidate = (t: Threat): boolean => t.foundBy === 'gap_check' && t.state === 'dismissed' && t.dismissReason === 'unconfirmed' && !t.verification;

/**
 * The threats the verifier sees: accepted AI threats, then gap-check candidates (listed last, so a candidate that
 * repeats a threat points back at it). Rule-based ones are never sent; needs-human ones already wait.
 */
const verifiable = (t: Threat) => (t.origin === 'agent' && t.state === 'accepted') || isGapCandidate(t);
const candidatesLast = (a: Threat, b: Threat) => Number(isGapCandidate(a)) - Number(isGapCandidate(b));

/**
 * Threatline Engine stage 4: one call on a stronger model checks each accepted AI threat against the quotes it rests on.
 * Its answer is only a request; applyVerification decides what it does. Every id must get a verdict, or nothing changes.
 */
export async function engineVerify(deps: Pick<PipelineDeps, 'llm' | 'policy'>, threats: readonly Threat[], usage: Usage, nonce: string): Promise<Result<Verdict4[]>> {
  const items = threats.filter(verifiable).sort(candidatesLast).slice(0, 80);
  if (items.length === 0) return ok([]);
  const ids = items.map((_, n) => `T${n + 1}`);
  const p = verifyPrompt(
    items.map((t, n) => ({ id: ids[n]!, stride: t.stride, severity: t.severity, title: t.title, scenario: t.scenario, component: t.component, quotes: t.citations.map((c) => c.quote), ...(isGapCandidate(t) ? { added: true } : {}) })),
    nonce,
  );
  const r = await callStage(deps, usage, { ...p, purpose: 'verify', tier: 'deep', maxOutputTokens: 6000 }, FittedVerifySchema, null);
  if (!r.ok) return r;
  const byId = new Map(r.value.verdicts.map((v) => [v.id, v]));
  if (byId.size !== ids.length || ids.some((id) => !byId.has(id))) return err(appError('schema', 'verifier must give one verdict per threat'));
  // The verifier refers to threats by its own ids ("repeats T1"): people see the threat's title instead.
  const named = (reason: string) => reason.replace(/\bT(\d{1,3})\b/g, (m, d: string) => {
    const t = items[Number(d) - 1];
    return t ? `“${t.title}”` : m;
  });
  return ok(
    items.map((t, n) => {
      const v = byId.get(ids[n]!)!;
      const dup = v.duplicateOf ? items[Number(v.duplicateOf.slice(1)) - 1] : undefined;
      return { threatId: t.id, keep: v.keep, reason: named(v.reason), ...(dup && dup.id !== t.id ? { duplicateOf: dup.id } : {}) };
    }),
  );
}

/**
 * Deterministic: what the verifier's verdicts do. Kept threats are marked verified. A rejected threat below the site's
 * blocking threshold is dismissed (reason recorded); one at or above it goes to a security champion instead, so the
 * verifier (which reads untrusted quotes) can never remove anything that gates Done or merge.
 * A below-threshold threat the verifier calls a duplicate of a kept, at-least-as-severe threat stands back under it
 * (state `covered`); a blocking one still goes to a champion.
 * A threat covered by a threat that is no longer accepted is active again. Under suspected injection, or for
 * a threat that cites a flagged source, nothing is demoted: attacker text must not steer what is dropped.
 */
export function applyVerification(
  threats: readonly Threat[],
  verdicts: readonly Verdict4[],
  opts: { injectionSuspected: boolean; taintedFacts?: ReadonlySet<string>; blockAtOrAbove?: Severity },
): { threats: Threat[]; changed: Threat[] } {
  if (opts.injectionSuspected) return { threats: [...threats], changed: [] };
  const byId = new Map(verdicts.map((v) => [v.threatId, v]));
  const changed = new Map<string, Threat>();
  const next = threats.map((t) => {
    const v = byId.get(t.id);
    if (!v || !verifiable(t)) return t;
    const verification = { keep: v.keep, reason: v.reason.slice(0, 300) };
    let u: Threat;
    const cover = v.duplicateOf ? threats.find((x) => x.id === v.duplicateOf) : undefined;
    // A gap-check candidate becomes active only when kept and resting on clean sources; otherwise it stays hidden, now
    // with the verifier's reason. Activating one only ever adds to what gates Done.
    if (isGapCandidate(t)) {
      const { dismissReason: _r, ...rest } = t;
      u = v.keep && !t.citations.some((c) => opts.taintedFacts?.has(c.factId)) ? { ...rest, state: 'accepted', verification } : { ...t, verification };
    } else if (v.keep) u = { ...t, verification };
    else if (t.citations.some((c) => opts.taintedFacts?.has(c.factId))) u = { ...t, verification };
    // Security: the verifier reads untrusted quotes, so it may never remove anything that would gate Done or merge,
    // not even by calling it a duplicate (fixing the cover might not fix it). A champion decides, seeing the reason.
    // The champion inbox groups it with the threat it repeats (`duplicateOf`), so both can be decided together.
    else if (severityRank(t.severity) >= severityRank(opts.blockAtOrAbove ?? 'High'))
      u = { ...t, state: 'needs_human', verification: { ...verification, ...(cover && cover.id !== t.id ? { duplicateOf: cover.id } : {}) } };
    // A below-threshold duplicate stands back under the threat it repeats, when that one was kept, is in force, is at
    // least as severe and rests on clean sources.
    else if (cover && byId.get(cover.id)?.keep === true && cover.state === 'accepted' && severityRank(cover.severity) >= severityRank(t.severity) && !cover.citations.some((c) => opts.taintedFacts?.has(c.factId)))
      u = { ...t, state: 'covered', coveredBy: cover.id, verification };
    else u = { ...t, state: 'dismissed', dismissReason: 'false_positive', verification };
    changed.set(u.id, u);
    return u;
  });
  // A threat sent to a person (needs_human) is still in force: it gates Done and stays visible, so what it covers stays
  // covered. Only a dismissed or covered cover brings the covered threat back.
  const active = new Set(next.filter((t) => t.state === 'accepted' || t.state === 'needs_human').map((t) => t.id));
  const out = next.map((t) => {
    if (t.state !== 'covered' || (t.coveredBy && active.has(t.coveredBy))) return t;
    const { coveredBy: _c, ...rest } = t;
    const back: Threat = { ...rest, state: 'accepted' };
    changed.set(back.id, back);
    return back;
  });
  return { threats: out, changed: [...changed.values()] };
}
