import { describe, expect, it } from 'vitest';
import type { Threat } from '@threatline/shared';
import { applyVerification, engineVerify } from '../src/index.js';
import { FakeLlm } from './fakes/fake-llm.js';
import { DEFAULT_SITE_POLICY } from '../src/index.js';

const threat = (o: Partial<Threat>): Threat => ({
  id: 'thr_x', reviewId: 'rev_1', stride: 'Tampering', title: 'T', scenario: 's', component: 'c', likelihood: 3, impact: 3, severity: 'Medium',
  votes: 3, samples: 3, grounding: 'supported', confidence: 1, state: 'accepted', origin: 'agent', citations: [{ factId: 'f1', quote: 'The agent can issue refunds.' }],
  mappings: [], plainLanguage: 'p', ...o,
});
const refund = threat({ id: 'thr_refund', title: 'Refund abuse', severity: 'High', likelihood: 4, impact: 4 });
const generic = threat({ id: 'thr_generic', title: 'Use HTTPS everywhere', severity: 'Medium' });
const loud = threat({ id: 'thr_loud', title: 'Admin takeover', severity: 'Critical', likelihood: 5, impact: 5 });
const base = threat({ id: 'thr_base', origin: 'baseline', title: 'Tool misuse by an over-privileged agent', state: 'covered', coveredBy: 'thr_generic' });
const human = threat({ id: 'thr_human', title: 'Weakly grounded', state: 'needs_human', grounding: 'weak' });

describe('engineVerify (Threatline Engine stage 4)', () => {
  it('asks once about every accepted AI threat (never rule-based ones), with its quotes, and maps verdicts back to threat ids', async () => {
    const llm = new FakeLlm({
      verify: [JSON.stringify({ verdicts: [{ id: 'T1', keep: true, reason: 'quotes show refunds' }, { id: 'T2', keep: false, reason: 'generic hygiene' }, { id: 'T3', keep: false, reason: 'not in design' }] })],
    });
    const usage = { tokensIn: 0, tokensOut: 0, modelIds: new Set<string>() };
    const r = await engineVerify({ llm, policy: DEFAULT_SITE_POLICY }, [refund, generic, loud, base, human], usage, 'n0nce');
    expect(r.ok && r.value).toEqual([
      { threatId: 'thr_refund', keep: true, reason: 'quotes show refunds' },
      { threatId: 'thr_generic', keep: false, reason: 'generic hygiene' },
      { threatId: 'thr_loud', keep: false, reason: 'not in design' },
    ]);
    expect(llm.calls).toHaveLength(1);
    expect(llm.calls[0]!.user).toContain('<evidence-n0nce>The agent can issue refunds.</evidence-n0nce>');
    expect(llm.calls[0]!.user).not.toContain('Tool misuse');
    expect(usage.tokensIn).toBeGreaterThan(0);
  });

  it("names the threat a reason refers to (\"repeats T1\") instead of the verifier's own id", async () => {
    const llm = new FakeLlm({ verify: [JSON.stringify({ verdicts: [{ id: 'T1', keep: true, reason: 'ok' }, { id: 'T2', keep: false, reason: 'Repeats T1; see also T9' }] })] });
    const r = await engineVerify({ llm, policy: DEFAULT_SITE_POLICY }, [refund, generic], { tokensIn: 0, tokensOut: 0, modelIds: new Set<string>() }, 'n');
    expect(r.ok && r.value[1]!.reason).toBe('Repeats “Refund abuse”; see also T9');
  });

  it('a reply that misses an id fails (so nothing is changed on a partial answer)', async () => {
    const llm = new FakeLlm({ verify: () => JSON.stringify({ verdicts: [{ id: 'T1', keep: true, reason: 'ok' }] }) });
    const r = await engineVerify({ llm, policy: DEFAULT_SITE_POLICY }, [refund, generic], { tokensIn: 0, tokensOut: 0, modelIds: new Set() }, 'n');
    expect(r.ok).toBe(false);
  });
});

describe('applyVerification (deterministic: the verifier asks, code decides)', () => {
  const verdicts = [
    { threatId: 'thr_refund', keep: true, reason: 'quotes show refunds' },
    { threatId: 'thr_generic', keep: false, reason: 'generic hygiene' },
    { threatId: 'thr_loud', keep: false, reason: 'not in design' },
  ];

  it('a rejected Medium/Low threat is dismissed; a rejected High/Critical one goes to a champion; kept ones are marked verified', () => {
    const out = applyVerification([refund, generic, loud, base, human], verdicts, { injectionSuspected: false });
    const by = new Map(out.threats.map((t) => [t.id, t]));
    expect(by.get('thr_refund')).toMatchObject({ state: 'accepted', verification: { keep: true } });
    expect(by.get('thr_generic')).toMatchObject({ state: 'dismissed', dismissReason: 'false_positive', verification: { keep: false, reason: 'generic hygiene' } });
    expect(by.get('thr_loud')).toMatchObject({ state: 'needs_human', verification: { keep: false } });
    expect(by.get('thr_human')!.state).toBe('needs_human');
  });

  it('a rule-based threat covered by a threat the verifier rejected becomes active again', () => {
    const out = applyVerification([refund, generic, loud, base, human], verdicts, { injectionSuspected: false });
    const b = out.threats.find((t) => t.id === 'thr_base')!;
    expect(b.state).toBe('accepted');
    expect(b.coveredBy).toBeUndefined();
    expect(out.changed.map((t) => t.id).sort()).toEqual(['thr_base', 'thr_generic', 'thr_loud', 'thr_refund']);
  });

  it('a below-threshold duplicate stands back under the kept threat it repeats; a blocking duplicate still goes to a champion', () => {
    const twin = threat({ id: 'thr_twin', title: 'Refund abuse, again', severity: 'Medium' });
    const r = applyVerification([refund, twin], [{ threatId: 'thr_refund', keep: true, reason: 'ok' }, { threatId: 'thr_twin', keep: false, reason: 'same', duplicateOf: 'thr_refund' }], { injectionSuspected: false, blockAtOrAbove: 'High' });
    expect(r.threats.find((t) => t.id === 'thr_twin')).toMatchObject({ state: 'covered', coveredBy: 'thr_refund' });
    // Security: a blocking threat is never folded away by the verifier, even as a "duplicate".
    const highTwin = threat({ id: 'thr_hightwin', title: 'IDOR on export', severity: 'High', likelihood: 4, impact: 4 });
    const r2 = applyVerification([refund, highTwin], [{ threatId: 'thr_refund', keep: true, reason: 'ok' }, { threatId: 'thr_hightwin', keep: false, reason: 'same', duplicateOf: 'thr_refund' }], { injectionSuspected: false, blockAtOrAbove: 'High' });
    expect(r2.threats.find((t) => t.id === 'thr_hightwin')!.state).toBe('needs_human');
    // Champion inbox: the champion sees which threat it repeats, so a cluster can be decided at once.
    expect(r2.threats.find((t) => t.id === 'thr_hightwin')!.verification).toEqual({ keep: false, reason: 'same', duplicateOf: 'thr_refund' });
    // A cover the verifier rejected covers nothing: the usual rule applies (a Medium is dismissed).
    const r3 = applyVerification([refund, twin], [{ threatId: 'thr_refund', keep: false, reason: 'no' }, { threatId: 'thr_twin', keep: false, reason: 'same', duplicateOf: 'thr_refund' }], { injectionSuspected: false, blockAtOrAbove: 'High' });
    expect(r3.threats.find((t) => t.id === 'thr_twin')!.state).toBe('dismissed');
  });

  it('security: under suspected injection nothing changes (attacker text must not steer the verifier)', () => {
    const out = applyVerification([refund, generic, loud, base], verdicts, { injectionSuspected: true });
    expect(out.changed).toEqual([]);
    expect(out.threats).toEqual([refund, generic, loud, base]);
  });

  it('security: the verifier can never dismiss a threat at or above the blocking threshold (it goes to a champion)', () => {
    const medium = { ...generic };
    const out = applyVerification([medium], [{ threatId: 'thr_generic', keep: false, reason: 'r' }], { injectionSuspected: false, blockAtOrAbove: 'Medium' });
    expect(out.threats[0]!.state).toBe('needs_human');
    const low = { ...generic, severity: 'Low' as const };
    expect(applyVerification([low], [{ threatId: 'thr_generic', keep: false, reason: 'r' }], { injectionSuspected: false, blockAtOrAbove: 'Medium' }).threats[0]!.state).toBe('dismissed');
  });

  it('security: a threat citing a source flagged for injection is never demoted', () => {
    const tainted = { ...generic, citations: [{ factId: 'f-poison', quote: 'x' }] };
    const out = applyVerification([tainted], [{ threatId: 'thr_generic', keep: false, reason: 'r' }], { injectionSuspected: false, taintedFacts: new Set(['f-poison']) });
    expect(out.threats[0]!.state).toBe('accepted');
  });
});
