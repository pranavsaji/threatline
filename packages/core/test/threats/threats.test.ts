import { describe, expect, it } from 'vitest';
import type { AgentThreat } from '@threatline/shared';
import {
  baselineThreats,
  clusterSamples,
  consensus,
  voteThreshold,
  extractSignals,
  groundQuote,
  mapThreat,
  normalizeFact,
  plainLanguageFor,
  riskScore,
  severityOf,
  similar,
} from '../../src/index.js';
import { rawFacts } from '../fixtures/ai-support-agent.js';

const facts = rawFacts.map(normalizeFact);
const t = (o: Partial<AgentThreat>): AgentThreat => ({
  stride: 'Tampering',
  title: 'Thing',
  scenario: 's',
  component: 'api',
  likelihood: 3,
  impact: 3,
  evidence: [{ quote: 'q' }],
  ...o,
});

describe('severityOf', () => {
  it('maps likelihood x impact to the spec bands', () => {
    expect(severityOf(4, 5)).toBe('Critical');
    expect(severityOf(3, 4)).toBe('High');
    expect(severityOf(2, 3)).toBe('Medium');
    expect(severityOf(1, 5)).toBe('Low');
  });
});

describe('groundQuote', () => {
  it('supports an exact quote despite case, whitespace and punctuation differences', () => {
    const r = groundQuote('the agent can ISSUE refunds   up to $200 through the Stripe payment API', facts);
    expect(r.grounding).toBe('supported');
    expect(r.factId).toBe(facts[1]!.id);
  });
  it('rates a paraphrase that shares most words as weak', () => {
    expect(groundQuote('agent issue refunds through Stripe payment', facts).grounding).toBe('weak');
  });
  it('rates invented text as unsupported', () => {
    expect(groundQuote('the service stores credit cards in plaintext on an FTP server', facts).grounding).toBe('unsupported');
  });
  it('never supports a trivially short quote', () => {
    expect(groundQuote('the', facts).grounding).not.toBe('supported');
  });
});

describe('similar', () => {
  it('treats reworded titles in the same stride and component as similar', () => {
    expect(similar(t({ stride: 'Tampering', title: 'SQL injection in search API', component: 'search api' }), t({ stride: 'Tampering', title: 'SQL Injection via the search endpoint', component: 'search api' }))).toBe(true);
  });
  it('different STRIDE categories are never similar', () => {
    expect(similar(t({ stride: 'Spoofing', title: 'Same title' }), t({ stride: 'Tampering', title: 'Same title' }))).toBe(false);
  });
  it('can ignore the component when matching against baseline threats', () => {
    const a = t({ title: 'Agent goal hijack', component: 'agent service' });
    const b = t({ title: 'Agent goal hijack through injected instructions', component: 'AI agent' });
    expect(similar(a, b)).toBe(false);
    expect(similar(a, b, { ignoreComponent: true })).toBe(true);
  });
});

describe('clusterSamples + consensus', () => {
  const A = t({ title: 'Refund abuse by the agent', stride: 'Tampering' });
  const B = t({ title: 'Prompt injection hijacks agent', stride: 'ElevationOfPrivilege' });
  const C = t({ title: 'Logs missing for refunds', stride: 'Repudiation' });
  it('keeps threats seen in a majority of samples and discards the rest as low_votes', () => {
    const clusters = clusterSamples([[A, B], [A, B, C], [{ ...A, title: 'Refund abuse via the agent' }]]);
    const { kept, discarded } = consensus(clusters, 3);
    expect(kept.map((c) => c.representative.stride).sort()).toEqual(['ElevationOfPrivilege', 'Tampering']);
    expect(kept.find((c) => c.representative.stride === 'Tampering')!.sampleIndexes).toEqual([0, 1, 2]);
    expect(discarded).toHaveLength(1);
    expect(discarded[0]!.reason).toBe('low_votes');
  });
  it('counts a threat repeated within one sample only once', () => {
    const [c] = clusterSamples([[A, A], [B]]);
    expect(c!.sampleIndexes).toEqual([0]);
  });
  it('uses ceil(total/2) as the vote threshold (1 sample keeps everything)', () => {
    expect(consensus(clusterSamples([[A, B]]), 1).kept).toHaveLength(2);
    expect(consensus(clusterSamples([[A], [A], [B], [], []]), 5).kept).toHaveLength(0);
  });
  it('picks the member with the most evidence, then the longest scenario, as representative', () => {
    const rich = { ...A, scenario: 'longer scenario text', evidence: [{ quote: 'a' }, { quote: 'b' }] };
    const [c] = clusterSamples([[A], [rich]]);
    expect(c!.representative).toEqual(rich);
  });
});

describe('clusterSamples: the same threat in different words (live finding, PAY-6)', () => {
  const run = (title: string, component: string, quote: string, stride: AgentThreat['stride'] = 'Spoofing'): AgentThreat => ({
    stride, title, component, scenario: 'An attacker reuses an old sign-in link to take over the account.', likelihood: 4, impact: 4, evidence: [{ quote }],
  });
  const Q = 'Tokens are stored in the users table and do not expire until used.';

  it('merges runs that cite the same evidence even when titles and components are worded differently', () => {
    const clusters = clusterSamples([
      [run('Permanent magic links allow account takeover if email is compromised', 'magic link', Q)],
      [run('Non-expiring tokens allow long-term account takeover', 'auth tokens', 'Tokens are stored in the users table and do not expire until used')],
      [run('Permanent account takeover via non-expiring tokens', 'password reset service', Q)],
    ]);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.sampleIndexes).toEqual([0, 1, 2]);
  });

  it('merges one threat that two runs filed under different STRIDE categories, taking the majority category (live finding, api-06)', () => {
    const clusters = clusterSamples([
      [run('Magic links never expire', 'auth', Q)],
      [run('Magic links never expire', 'auth', Q, 'InformationDisclosure')],
      [run('Magic links never expire, so old links work', 'auth', Q, 'InformationDisclosure')],
    ]);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.sampleIndexes).toEqual([0, 1, 2]);
    expect(clusters[0]!.representative.stride).toBe('InformationDisclosure');
  });

  it('does not merge different categories without the same passage and clearly similar wording', () => {
    expect(clusterSamples([[run('Magic links never expire', 'auth', Q)], [run('Magic links never expire', 'auth', 'Links are emailed to the user.', 'InformationDisclosure')]])).toHaveLength(2);
    expect(clusterSamples([[run('Magic links never expire', 'auth', Q)], [{ ...run('No record of who used a link', 'audit', Q, 'Repudiation'), scenario: 'Nobody can tell later who signed in.' }]])).toHaveLength(2);
  });

  it('keeps two threats one run reported apart even when they cite the same passage (live finding, web-04)', () => {
    const idor = { ...run('Any customer can read another customer\'s invoice by changing the id', 'download', Q, 'InformationDisclosure'), scenario: 'A signed-in customer edits the number in the URL and downloads a stranger\'s invoice.' };
    const enumerate = { ...run('Sequential ids reveal how many customers there are', 'download', Q, 'InformationDisclosure'), scenario: 'A competitor counts upward through the numbers to learn the order volume.' };
    const clusters = clusterSamples([[idor, enumerate], [idor, enumerate], [idor]]);
    expect(clusters.map((c) => c.sampleIndexes)).toEqual([[0, 1, 2], [0, 1]]);
    // A run that lists the same threat twice, or restates it in other words, still counts once.
    expect(clusterSamples([[idor, { ...idor, title: 'Any customer can read another customer\'s invoices by changing the id' }]])).toHaveLength(1);
    expect(clusterSamples([[idor, { ...idor, title: 'Invoice ids are not checked against the signed-in customer' }]])).toHaveLength(1);
  });

  it('does not merge same-category threats with unrelated evidence and titles', () => {
    expect(
      clusterSamples([[run('Magic links never expire', 'auth', Q)], [run('Support staff impersonate customers', 'admin console', 'Support staff can sign in as any customer from the admin console.')]]),
    ).toHaveLength(2);
  });
});

describe('mapThreat', () => {
  it('drops invalid agent ids, keeps valid ones and adds STRIDE defaults', () => {
    const m = mapThreat(t({ stride: 'Spoofing', asvs: ['V99.1.1', 'V6.2.1'], cwe: ['287', 'CWE-0'] }), false);
    expect(m).toContainEqual({ framework: 'ASVS5', refId: 'V6.2.1' });
    expect(m).toContainEqual({ framework: 'CWE', refId: 'CWE-287' });
    expect(m.some((x) => x.refId === 'V99.1.1' || x.refId === 'CWE-0')).toBe(false);
    expect(m.some((x) => x.framework === 'ASI10')).toBe(false);
  });
  it('adds ASI01 and LLM01 for goal hijack when the design has LLM features', () => {
    const m = mapThreat(t({ stride: 'ElevationOfPrivilege', title: 'Agent goal hijack via prompt injection' }), true);
    expect(m).toContainEqual({ framework: 'ASI10', refId: 'ASI01' });
    expect(m).toContainEqual({ framework: 'LLM10', refId: 'LLM01' });
  });
  it('has no duplicate mappings', () => {
    const m = mapThreat(t({ stride: 'Spoofing', asvs: ['V6.3.1', 'V6.3.1'] }), false);
    expect(new Set(m.map((x) => `${x.framework}:${x.refId}`)).size).toBe(m.length);
  });
});

describe('riskScore', () => {
  it('is 0 with no threats and internal exposure', () => {
    expect(riskScore([], { dataClasses: [], exposure: 'internal' })).toBe(0);
  });
  it('matches the documented formula', () => {
    const threats = [
      { severity: 'High' as const, state: 'accepted' as const },
      { severity: 'High' as const, state: 'accepted' as const },
      { severity: 'High' as const, state: 'needs_human' as const },
      { severity: 'Critical' as const, state: 'accepted' as const },
      { severity: 'Critical' as const, state: 'dismissed' as const },
    ];
    expect(riskScore(threats, { dataClasses: ['pii'], exposure: 'public' })).toBe(87);
  });
  it('caps at 100', () => {
    const many = Array.from({ length: 10 }, () => ({ severity: 'Critical' as const, state: 'accepted' as const }));
    expect(riskScore(many, { dataClasses: ['pii', 'payment', 'credentials'], exposure: 'public' })).toBe(100);
  });
});

describe('baselineThreats', () => {
  const signals = extractSignals(facts);
  const base = baselineThreats(signals);
  it('includes both agentic threats for an LLM feature', () => {
    expect(base.map((b) => b.title)).toEqual(
      expect.arrayContaining(['Agent goal hijack through injected instructions', 'Tool misuse by an over-privileged agent']),
    );
  });
  it('every evidence quote grounds as supported against the bundle', () => {
    for (const b of base) for (const e of b.evidence) expect(groundQuote(e.quote, facts).grounding, b.title).toBe('supported');
  });
  it('rule-based scenarios stay generic: no refunds, orders, chat or customers the work item may not have (eval judge finding)', () => {
    const all = baselineThreats({ ...signals, auth: true, payment: true, fileUpload: true, llmFeatures: true, exposure: 'public', dataClasses: ['pii', 'credentials'], thirdParty: ['stripe'], evidence: new Proxy({}, { get: () => ({ quote: 'q' }) }) as never });
    expect(all.length).toBeGreaterThanOrEqual(8);
    for (const t of all) expect(t.scenario, t.title).not.toMatch(/refund|order|chat|customer/i);
  });
  it('produces nothing for an empty bundle', () => {
    expect(baselineThreats(extractSignals([]))).toEqual([]);
  });
  it('every baseline threat carries valid ASVS ids', () => {
    for (const b of base) expect(mapThreat(b, signals.llmFeatures).some((m) => m.framework === 'ASVS5')).toBe(true);
  });
});

describe('plainLanguageFor', () => {
  it('leads with plain words, not jargon', () => {
    expect(plainLanguageFor(t({ stride: 'Spoofing', component: 'login page' }))).toMatch(/pretend/i);
  });
});

describe('consensus needs a strict majority (spec: "keep if votes at least 3 of 5")', () => {
  it.each([
    [1, 1],
    [2, 2],
    [3, 2],
    [4, 3],
    [5, 3],
  ])('%i samples need %i votes', (n, need) => expect(voteThreshold(n)).toBe(need));
});
