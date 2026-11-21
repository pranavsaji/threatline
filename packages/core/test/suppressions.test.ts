import { describe, expect, it } from 'vitest';
import type { Review, Threat } from '@threatline/shared';
import {
  applySuppressions,
  assembleReview,
  computeVerdict,
  contextHash,
  gateThreats,
  DEFAULT_SITE_POLICY,
  normalizeFact,
  requirementsFor,
  riskScore,
  ruleMatches,
  suggestSuppressions,
  unhidden,
  type ActiveSuppression,
  type DismissalRow,
  type Sample,
} from '../src/index.js';
import { poisonedRawFact, rawFacts } from './fixtures/ai-support-agent.js';
import { ISSUE_KEY, model, refundAbuse, transcriptLeak } from './fixtures/agent-samples.js';

const facts = rawFacts.map(normalizeFact);
const bundle = (fs = facts) => ({ issueId: '10001', issueKey: ISSUE_KEY, facts: fs, partial: false, partialReasons: [], contextHash: contextHash(fs), gatheredAt: '2026-11-15T00:00:00.000Z' });
const review: Review = {
  id: 'rev_1', issueId: '10001', issueKey: ISSUE_KEY, revision: 1, status: 'awaiting_agent', contextHash: 'h', riskScore: 0, partial: false,
  promptVersion: 'v1.0.0', modelIds: [], samplesExpected: 3, samplesReceived: 0, tokensIn: 0, tokensOut: 0,
  createdAt: '2026-11-15T00:00:00.000Z', updatedAt: '2026-11-15T00:00:00.000Z',
};
const NOW = new Date('2026-11-15T00:00:00Z');
const assemble = (samples: Sample[], over: Partial<Parameters<typeof assembleReview>[0]> = {}) =>
  assembleReview({ review, bundle: bundle(), samples, samplesExpected: 3, priorDismissed: [], policy: DEFAULT_SITE_POLICY, promptVersion: 'v1.0.0', now: NOW, ...over });
const three = (m = model([refundAbuse, transcriptLeak])) => [m, m, m];
const byTitle = (out: { threats: Threat[] }, title: string) => out.threats.find((t) => t.title === title)!;

const rule = (o: Partial<ActiveSuppression> = {}): ActiveSuppression => ({
  id: 'sup_1', stride: 'InformationDisclosure', title: 'Conversation transcripts expose customer data', reason: 'Transcripts are encrypted and access-logged in every PAY service.', expiresAt: '2027-02-13T00:00:00.000Z', ...o,
});
const UPLOAD = 'Malicious file upload executes code';

describe('team suppression rules at assembly', () => {
  it('hides a matching AI threat below the blocking threshold: state suppressed, no requirement, not scored', () => {
    const plain = assemble(three());
    const out = assemble(three(), { suppressions: { rules: [rule({ title: 'Transcripts of conversations expose customer data' })] } });
    const leak = byTitle(out, transcriptLeak.title);
    expect(leak.severity).toBe('Medium');
    expect(leak).toMatchObject({ state: 'suppressed', suppression: { ruleId: 'sup_1', outcome: 'hidden', restoreTo: 'accepted', reason: rule().reason, expiresAt: rule().expiresAt } });
    expect(requirementsFor(out.threats, { issueId: '10001', issueKey: ISSUE_KEY }).some((r) => r.threatId === leak.id)).toBe(false);
    expect(out.threats.length).toBe(plain.threats.length);
    // Scoring excludes it, exactly like a dismissed threat.
    expect(riskScore([{ severity: 'Medium', state: 'suppressed' }], { dataClasses: [], exposure: 'internal' })).toBe(0);
    expect(riskScore([{ severity: 'Medium', state: 'accepted' }], { dataClasses: [], exposure: 'internal' })).toBe(5);
  });

  it('hides a rule-based threat below the threshold too', () => {
    const out = assemble(three(model([])), { suppressions: { rules: [rule({ id: 'sup_up', stride: 'ElevationOfPrivilege', title: UPLOAD })] } });
    expect(byTitle(out, UPLOAD)).toMatchObject({ origin: 'baseline', state: 'suppressed', suppression: { ruleId: 'sup_up', outcome: 'hidden' } });
  });

  it('never hides a threat at or above the blocking threshold: it stands, and records that the rule matched', () => {
    const out = assemble(three(), { suppressions: { rules: [rule({ id: 'sup_refund', stride: 'Tampering', title: refundAbuse.title })] } });
    const refund = byTitle(out, refundAbuse.title);
    expect(refund.severity).toBe('High');
    expect(refund.state).toBe('accepted');
    expect(refund.suppression).toEqual({ ruleId: 'sup_refund', reason: rule().reason, expiresAt: rule().expiresAt, outcome: 'blocking' });
    expect(requirementsFor(out.threats, { issueId: '10001', issueKey: ISSUE_KEY }).some((r) => r.threatId === refund.id)).toBe(true);
  });

  it('the verdict stays correct: a blocking threat a rule matched still blocks Done; a hidden one creates no requirement', () => {
    const out = assemble(three(), {
      suppressions: { rules: [rule(), rule({ id: 'sup_refund', stride: 'Tampering', title: refundAbuse.title })] },
    });
    const reqs = requirementsFor(out.threats, { issueId: '10001', issueKey: ISSUE_KEY });
    const v = computeVerdict({
      issueId: '10001', review: { ...review, status: 'ready' }, currentContextHash: 'h', threats: out.threats, requirements: reqs.map((r) => ({ ...r, createdAt: 'x' })),
      acceptances: [], policy: DEFAULT_SITE_POLICY, projectKey: 'PROJ', championConfirmations: [], breakGlass: [], budgetPaused: false, injectionSuspected: false, now: NOW, panelUrl: 'https://x/p',
    });
    expect(v.state).toBe('block');
    const refund = byTitle(out, refundAbuse.title);
    expect(v.reasons.find((r) => r.code === 'open_requirement')?.requirementIds).toEqual(expect.arrayContaining([reqs.find((r) => r.threatId === refund.id)!.id]));
    expect(reqs.some((r) => r.threatId === byTitle(out, transcriptLeak.title).id)).toBe(false);
  });

  it('a hidden AI threat covers nothing: the rule-based threat it would have covered stays active', () => {
    const policy = { ...DEFAULT_SITE_POLICY, blockAtOrAbove: 'Critical' as const };
    const plain = assemble(three(), { policy });
    expect(byTitle(plain, 'Tool misuse by an over-privileged agent').state).toBe('covered');
    const out = assemble(three(), { policy, suppressions: { rules: [rule({ id: 'sup_refund', stride: 'Tampering', title: refundAbuse.title })] } });
    expect(byTitle(out, refundAbuse.title).state).toBe('suppressed');
    expect(byTitle(out, 'Tool misuse by an over-privileged agent').state).toBe('accepted');
  });

  it('security: under suspected injection no rule applies', () => {
    const poisoned = bundle([...facts, normalizeFact(poisonedRawFact)]);
    const out = assemble(three(), { bundle: poisoned, suppressions: { rules: [rule(), rule({ id: 'sup_up', stride: 'ElevationOfPrivilege', title: UPLOAD })] } });
    expect(out.injectionSuspected).toBe(true);
    expect(out.threats.some((t) => t.state === 'suppressed' || t.suppression)).toBe(false);
    // The quarantined check's flag counts the same as a flagged fact.
    const flagged = assemble(three(), { injectionSuspected: true, suppressions: { rules: [rule()] } });
    expect(flagged.threats.some((t) => t.state === 'suppressed')).toBe(false);
  });

  it('an expired rule never applies, even if the hourly job has not marked it yet', () => {
    const out = assemble(three(), { suppressions: { rules: [rule({ expiresAt: '2026-11-14T23:59:59.000Z' })] } });
    expect(byTitle(out, transcriptLeak.title).state).toBe('accepted');
  });

  it('a rule with a component matches only that component', () => {
    expect(byTitle(assemble(three(), { suppressions: { rules: [rule({ component: 'billing api' })] } }), transcriptLeak.title).state).toBe('accepted');
    expect(byTitle(assemble(three(), { suppressions: { rules: [rule({ component: 'support database' })] } }), transcriptLeak.title).state).toBe('suppressed');
  });

  it('a rule a champion unhid on this work item only marks its threats', () => {
    const out = assemble(three(), { suppressions: { rules: [rule()], unhidden: ['sup_1'] } });
    expect(byTitle(out, transcriptLeak.title)).toMatchObject({ state: 'accepted', suppression: { ruleId: 'sup_1', outcome: 'unhidden' } });
  });

  it('dismissed threats are left alone; a weakly grounded below-threshold threat waiting for a champion can be hidden and restored', () => {
    const t = (o: Partial<Threat>): Threat => ({
      id: 'thr_1', reviewId: 'rev_1', stride: 'InformationDisclosure', title: transcriptLeak.title, scenario: 's', component: 'c', likelihood: 3, impact: 3, severity: 'Medium',
      votes: 3, samples: 3, grounding: 'weak', confidence: 0.6, state: 'needs_human', origin: 'agent', citations: [{ factId: 'f', quote: 'q' }], mappings: [], plainLanguage: 'p', ...o,
    });
    const list = [t({}), t({ id: 'thr_2', state: 'dismissed', dismissReason: 'false_positive' })];
    expect([...applySuppressions(list, [rule()], { blockAtOrAbove: 'High', injectionSuspected: false, now: NOW })]).toEqual(['thr_1']);
    expect(list[1]!.state).toBe('dismissed');
    expect(unhidden(list[0]!)).toMatchObject({ state: 'needs_human', suppression: { outcome: 'unhidden' } });
    expect(unhidden(list[1]!)).toBe(list[1]);
  });

  it('re-review: a suppressed threat is not carried as a decision; with the rule gone the fresh threat is shown', () => {
    const first = assemble(three(), { suppressions: { rules: [rule()] } });
    expect(byTitle(first, transcriptLeak.title).state).toBe('suppressed');
    const second = assemble(three(), { review: { ...review, id: 'rev_2', revision: 2 }, prior: { threats: first.threats, facts } });
    const leak = byTitle(second, transcriptLeak.title);
    expect(leak.state).toBe('accepted');
    expect(leak.suppression).toBeUndefined();
  });

  it('the eval is unaffected: no rules gives exactly the assembly it gave before', () => {
    expect(assemble(three(), { suppressions: { rules: [] } })).toEqual(assemble(three()));
  });

  it('ruleMatches: STRIDE must agree, titles must be similar', () => {
    const t = { stride: 'InformationDisclosure' as const, title: 'Customer data exposed in conversation transcripts', component: 'x' };
    expect(ruleMatches(rule(), t)).toBe(true);
    expect(ruleMatches(rule({ stride: 'Tampering' }), t)).toBe(false);
    expect(ruleMatches(rule({ title: 'Refunds issued above policy' }), t)).toBe(false);
  });
});

describe('suggestSuppressions', () => {
  const d = (n: number, o: Partial<DismissalRow> = {}): DismissalRow => ({
    threatId: `t${n}`, component: 'reset api', title: 'Reset endpoint can be flooded', stride: 'DenialOfService', actor: 'acc-champ', reason: 'false_positive',
    issueId: `1000${n}`, issueKey: `PAY-${n}`, projectKey: 'PAY', at: `2026-11-0${n}T00:00:00.000Z`, ...o,
  });

  it('suggests a rule once the same kind of threat was dismissed on three different work items of a project', () => {
    expect(suggestSuppressions([d(1), d(2)], [])).toEqual([]);
    const s = suggestSuppressions([d(1), d(2), d(3, { title: 'Password reset endpoint flooded with requests' })], []);
    expect(s).toEqual([
      {
        projectKey: 'PAY', stride: 'DenialOfService', title: 'Reset endpoint can be flooded', component: 'reset api', workItems: 3,
        suggestedReason: 'Dismissed as a false positive on 3 work items (PAY-3, PAY-2, PAY-1).',
        evidence: [3, 2, 1].map((n) => ({ issueKey: `PAY-${n}`, title: n === 3 ? 'Password reset endpoint flooded with requests' : 'Reset endpoint can be flooded', reason: 'false_positive', actor: 'acc-champ', at: `2026-11-0${n}T00:00:00.000Z` })),
      },
    ]);
  });

  it('counts work items, not dismissals; ignores duplicates, other projects and other STRIDE categories', () => {
    expect(suggestSuppressions([d(1), d(2), d(3, { issueId: '10001', issueKey: 'PAY-1' })], [])).toEqual([]);
    expect(suggestSuppressions([d(1), d(2), d(3, { reason: 'duplicate' })], [])).toEqual([]);
    expect(suggestSuppressions([d(1), d(2), d(3, { projectKey: 'OPS', issueKey: 'OPS-3' })], [])).toEqual([]);
    expect(suggestSuppressions([d(1), d(2), d(3, { stride: 'Spoofing' })], [])).toEqual([]);
  });

  it('no component when the dismissals name different ones; nothing an active rule of the project already covers', () => {
    const rows = [d(1), d(2, { component: 'auth service' }), d(3)];
    expect(suggestSuppressions(rows, [])[0]?.component).toBeUndefined();
    expect(suggestSuppressions(rows, [{ projectKey: 'PAY', stride: 'DenialOfService', title: 'Reset endpoint flooding' }])).toEqual([]);
    expect(suggestSuppressions(rows, [{ projectKey: 'OPS', stride: 'DenialOfService', title: 'Reset endpoint flooding' }])).toHaveLength(1);
  });
});

describe('the gate never trusts a stale suppression (fail closed)', () => {
  const t = (o: Partial<Threat> = {}): Threat => ({
    id: 'thr_s', reviewId: 'rev_1', stride: 'InformationDisclosure', title: transcriptLeak.title, scenario: 's', component: 'c', likelihood: 3, impact: 3, severity: 'Medium',
    votes: 3, samples: 3, grounding: 'supported', confidence: 1, state: 'suppressed', origin: 'agent', citations: [{ factId: 'f', quote: 'q' }], mappings: [], plainLanguage: 'p',
    suppression: { ruleId: 'sup_1', reason: 'r', expiresAt: '2027-02-13T00:00:00.000Z', outcome: 'hidden', restoreTo: 'accepted' }, ...o,
  });
  const gate = (x: Threat, o: Partial<Parameters<typeof gateThreats>[1]> = {}) => gateThreats([x], { blockAtOrAbove: 'High', now: NOW, ...o })[0]!;

  it('a valid suppression stands: below the threshold, before expiry, rule active', () => {
    expect(gate(t()).state).toBe('suppressed');
    expect(gate(t(), { activeRuleIds: new Set(['sup_1']) }).state).toBe('suppressed');
  });

  it('counts as its earlier state when its severity reached the threshold, the threshold was lowered, it expired or its rule is no longer active', () => {
    expect(gate(t({ severity: 'High' })).state).toBe('accepted');
    expect(gate(t(), { blockAtOrAbove: 'Medium' }).state).toBe('accepted');
    expect(gate(t({ suppression: { ...t().suppression!, expiresAt: '2026-11-14T00:00:00.000Z' } })).state).toBe('accepted');
    expect(gate(t(), { activeRuleIds: new Set() }).state).toBe('accepted');
    expect(gate(t({ suppression: { ...t().suppression!, restoreTo: 'needs_human' } }), { activeRuleIds: new Set() }).state).toBe('needs_human');
    expect(gate(t({ suppression: undefined })).state).toBe('accepted');
  });

  it('computeVerdict: a suppressed threat now at the threshold blocks Done (with no requirement yet it counts as open)', () => {
    const verdict = (threats: Threat[], o: { blockAtOrAbove?: 'Medium' | 'High'; activeSuppressions?: ReadonlySet<string> } = {}) =>
      computeVerdict({
        issueId: '10001', review: { ...review, status: 'ready' }, currentContextHash: 'h', threats, requirements: [], acceptances: [], policy: { ...DEFAULT_SITE_POLICY, blockAtOrAbove: o.blockAtOrAbove ?? 'High' },
        projectKey: 'PROJ', championConfirmations: [], breakGlass: [], budgetPaused: false, injectionSuspected: false, now: NOW, panelUrl: 'https://x/p',
        ...(o.activeSuppressions ? { activeSuppressions: o.activeSuppressions } : {}),
      });
    expect(verdict([t()]).state).toBe('pass');
    expect(verdict([t({ severity: 'High' })]).state).toBe('block');
    expect(verdict([t()], { blockAtOrAbove: 'Medium' }).state).toBe('block');
    expect(verdict([t({ severity: 'High', suppression: { ...t().suppression!, restoreTo: 'needs_human' } })]).reasons.map((r) => r.code)).toContain('needs_human');
    expect(verdict([t()], { activeSuppressions: new Set() }).state).toBe('pass');
  });
});
