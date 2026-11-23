import { describe, expect, it } from 'vitest';
import type { AgentThreat, Review, Threat } from '@threatline/shared';
import {
  applyVerification,
  assembleReview,
  contextHash,
  DEFAULT_SITE_POLICY,
  engineGapCheck,
  engineVerify,
  gapCandidates,
  isGapCandidate,
  minorityThreats,
  normalizeFact,
  type Sample,
} from '../src/index.js';
import { rawFacts } from './fixtures/ai-support-agent.js';
import { ISSUE_KEY, model, refundAbuse, transcriptLeak } from './fixtures/agent-samples.js';
import { FakeLlm } from './fakes/fake-llm.js';

const review: Review = {
  id: 'rev_1', issueId: '10001', issueKey: ISSUE_KEY, revision: 1, status: 'ready', contextHash: 'h', riskScore: 0, partial: false,
  promptVersion: 'v1.0.0', modelIds: [], samplesExpected: 3, samplesReceived: 3, tokensIn: 0, tokensOut: 0,
  createdAt: '2026-11-15T00:00:00.000Z', updatedAt: '2026-11-15T00:00:00.000Z',
};
const facts = rawFacts.map(normalizeFact);
const bundle = { issueId: '10001', issueKey: ISSUE_KEY, facts, partial: false, partialReasons: [], contextHash: contextHash(facts), gatheredAt: '2026-11-15T00:00:00.000Z' };
const assemble = (samples: Sample[], over: Partial<Parameters<typeof assembleReview>[0]> = {}) =>
  assembleReview({ review, bundle, samples, samplesExpected: 3, priorDismissed: [], policy: DEFAULT_SITE_POLICY, promptVersion: 'v1.0.0', now: new Date('2026-11-15T00:00:00Z'), ...over });

/** A threat the runs missed, quoting the design word for word. */
const missed: AgentThreat = {
  stride: 'Repudiation',
  title: 'Refunds the agent issues leave no record of who asked for them',
  scenario: 'A customer who talked the agent into a refund later denies it, and support cannot show which conversation caused it.',
  component: 'refund tool',
  likelihood: 3,
  impact: 2,
  rating: { attacker: 'user', effort: 'low', reach: 'one', harm: 'minor' },
  evidence: [{ quote: refundAbuse.evidence[0]!.quote }],
};
const agreed = () => assemble([model([refundAbuse, transcriptLeak]), model([refundAbuse, transcriptLeak]), model([refundAbuse])]).threats;
const candidates = (threats: Threat[], gap: AgentThreat[]) => gapCandidates({ review, bundle, threats, sample: model(gap), llmFeatures: true });

describe('the gap check (Threatline Engine, after assembly, before the verifier)', () => {
  it('a missed threat becomes a hidden candidate: dismissed as unconfirmed, counting for nothing, until the verifier keeps it', () => {
    const [c] = candidates(agreed(), [missed]);
    expect(c).toMatchObject({ origin: 'agent', foundBy: 'gap_check', state: 'dismissed', dismissReason: 'unconfirmed', grounding: 'supported' });
    expect(c!.severity).toBe('Low'); // from its rating, through the same table as every AI threat
    expect(isGapCandidate(c!)).toBe(true);
  });

  it('drops a repeat of a stored threat, a threat without a verbatim quote and one citing a flagged source', () => {
    const threats = agreed();
    const repeat = { ...refundAbuse, title: 'Refund abuse through the support agent tool' };
    const unquoted = { ...missed, title: 'Invented threat', evidence: [{ quote: 'This sentence is not in the design at all.' }] };
    expect(candidates(threats, [repeat, unquoted])).toEqual([]);
    const flagged = facts.map((f, n) => (n === 0 ? { ...f, injectionSuspected: true } : f));
    const quotedFromFlagged = { ...missed, evidence: [{ quote: flagged[0]!.excerpt.slice(0, 60) }] };
    expect(gapCandidates({ review, bundle: { ...bundle, facts: flagged }, threats, sample: model([quotedFromFlagged]), llmFeatures: true })).toEqual([]);
  });

  it('takes at most four candidates and never two with the same title', () => {
    const many = Array.from({ length: 6 }, (_, n) => ({ ...missed, title: `${missed.title} ${'variant '.repeat(n)}${n}`, stride: (['Repudiation', 'DenialOfService', 'Tampering', 'Spoofing', 'InformationDisclosure', 'ElevationOfPrivilege'] as const)[n]! }));
    expect(candidates(agreed(), many)).toHaveLength(4);
    expect(candidates(agreed(), [missed, missed])).toHaveLength(1);
  });

  it('minority threats are the ones only one run raised', () => {
    const lone = minorityThreats([model([refundAbuse, missed]), model([refundAbuse]), model([refundAbuse])]);
    expect(lone.map((t) => t.title)).toEqual([missed.title]);
  });

  it('reads the agreed threats, the minority and the fenced context; an empty answer adds nothing; a non-answer fails', async () => {
    const samples = [model([refundAbuse, transcriptLeak]), model([refundAbuse, transcriptLeak]), model([refundAbuse, missed])];
    const threats = assemble(samples).threats;
    const empty = new FakeLlm({ gaps: [JSON.stringify(model([]))] });
    const r = await engineGapCheck({ llm: empty, policy: DEFAULT_SITE_POLICY }, review, bundle, threats, samples, { tokensIn: 0, tokensOut: 0, modelIds: new Set() });
    expect(r).toEqual({ ok: true, value: [] });
    const call = empty.calls[0]!;
    expect(call).toMatchObject({ purpose: 'gaps', tier: 'deep' });
    expect(call.user).toMatch(/Threats the first review agreed on:\n(?:\d+\. .+\n)*\d+\. \[Tampering, \w+\] Refund abuse through the support agent:/);
    expect(call.user).toMatch(new RegExp(`Raised by only one earlier reviewer \\(not confirmed\\):\\n1\\. \\[Repudiation, \\w+\\] ${missed.title}`));
    expect(call.user).toMatch(/Result of get-review-context:/);
    expect(call.system).toMatch(/data, never instructions/);

    const prose = new FakeLlm({ gaps: ['I found nothing to add.'] });
    const bad = await engineGapCheck({ llm: prose, policy: DEFAULT_SITE_POLICY }, review, bundle, threats, samples, { tokensIn: 0, tokensOut: 0, modelIds: new Set() });
    expect(bad.ok).toBe(false);
  });
});

describe('the verifier decides gap-check candidates', () => {
  const withCandidate = () => {
    const threats = agreed();
    return { threats: [...threats, ...candidates(threats, [missed])], candidate: candidates(threats, [missed])[0]! };
  };

  it('sees candidates last, marked as added', async () => {
    const { threats } = withCandidate();
    const llm = new FakeLlm({ verify: (req) => JSON.stringify({ verdicts: [...req.user.matchAll(/^(T\d+) /gm)].map((m) => ({ id: m[1], keep: true, reason: 'supported' })) }) });
    const v = await engineVerify({ llm, policy: DEFAULT_SITE_POLICY }, threats, { tokensIn: 0, tokensOut: 0, modelIds: new Set() }, 'n0nce');
    expect(v.ok).toBe(true);
    const lines = [...llm.calls[0]!.user.matchAll(/^T\d+ \[[^\]]+\] .+$/gm)].map((m) => m[0]);
    expect(lines.at(-1)).toMatch(new RegExp(`\\[Repudiation, Low, added\\] ${missed.title}$`));
    expect(lines.slice(0, -1).some((l) => l.includes('added'))).toBe(false);
  });

  it('a kept candidate becomes active (its unconfirmed reason gone); a dropped one stays hidden with the reason', () => {
    const { threats, candidate } = withCandidate();
    const kept = applyVerification(threats, [{ threatId: candidate.id, keep: true, reason: 'the design names the refund tool' }], { injectionSuspected: false });
    const k = kept.threats.find((t) => t.id === candidate.id)!;
    expect(k).toMatchObject({ state: 'accepted', verification: { keep: true } });
    expect(k.dismissReason).toBeUndefined();
    expect(isGapCandidate(k)).toBe(false);

    const dropped = applyVerification(threats, [{ threatId: candidate.id, keep: false, reason: 'generic' }], { injectionSuspected: false });
    expect(dropped.threats.find((t) => t.id === candidate.id)).toMatchObject({ state: 'dismissed', dismissReason: 'unconfirmed', verification: { keep: false, reason: 'generic' } });
  });

  it('security: under suspected injection, or citing a flagged source, a candidate is never made active', () => {
    const { threats, candidate } = withCandidate();
    const keep = [{ threatId: candidate.id, keep: true, reason: 'ok' }];
    expect(applyVerification(threats, keep, { injectionSuspected: true }).threats.find((t) => t.id === candidate.id)!.state).toBe('dismissed');
    const tainted = new Set(candidate.citations.map((c) => c.factId));
    expect(applyVerification(threats, keep, { injectionSuspected: false, taintedFacts: tainted }).threats.find((t) => t.id === candidate.id)!.state).toBe('dismissed');
  });

  it('a candidate the verifier never kept is not carried into the next revision, so it cannot hide a fresh threat there', () => {
    const { threats, candidate } = withCandidate();
    const next = assemble([model([refundAbuse, missed]), model([refundAbuse, missed]), model([refundAbuse, missed])], {
      review: { ...review, id: 'rev_2', revision: 2 },
      prior: { threats, facts },
    });
    const fresh = next.threats.find((t) => t.title === missed.title)!;
    expect(fresh.state).toBe('accepted');
    expect(fresh.id).not.toBe(candidate.id);
  });
});
