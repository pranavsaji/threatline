import { describe, expect, it } from 'vitest';
import { ok, type ContextBundle } from '@threatline/shared';
import { normalizeFact, contextHash } from '@threatline/core';
import { getReviewContext } from '../src/actions/get-review-context.js';
import { ingestSample, submitThreatModel } from '../src/actions/submit-threat-model.js';
import { handleJob } from '../src/consumers/review-consumer.js';
import { coreDeps, drain, jiraIssue } from './support/core-deps.js';
import type { CoreDeps } from '../src/deps.js';

/** The agent's real sequence: fetch context (gets a single-use token), then submit with it. */
async function submit(deps: CoreDeps, issueKey: string, threatModelJson: unknown, accountId = 'acc-1') {
  const c = await getReviewContext({ issueKey, ...ctx(accountId) }, deps);
  const submissionToken = 'submissionToken' in c ? c.submissionToken : 'none';
  return submitThreatModel({ issueKey, threatModelJson: threatModelJson as string, submissionToken, ...ctx(accountId) }, deps);
}

const KEY = 'PAY-7';
const ctx = (accountId?: string) => ({ context: accountId ? { accountId, agentId: 'agent-1', cloudId: 'c' } : {} });
const MODEL = {
  schema: 'threatline.threatmodel.v1',
  issueKey: KEY,
  threats: [
    {
      stride: 'Spoofing',
      title: 'Forged refund webhooks',
      scenario: 'An attacker posts a fake refund event.',
      component: 'webhook endpoint',
      likelihood: 4,
      impact: 4,
      evidence: [{ quote: 'Public webhook that receives refund events' }],
    },
  ],
};
const proseWrapped = `Here is the threat model for ${KEY}.\n\n\`\`\`json\n${JSON.stringify(MODEL, null, 2)}\n\`\`\`\n\nLet me know if you need more.`;

/** The configured review author (the Automation rule owner): only their runs feed the out-of-credits signal. */
async function asAuthor(t: ReturnType<typeof setup>, author = 'acc-1') {
  const p = await t.deps.config.site();
  if (!p.ok) throw new Error('policy');
  await t.deps.config.setSite({ ...p.value, reviewAuthors: [author] });
}

function setup(over: { canBrowse?: boolean; canEdit?: boolean } = {}) {
  const t = coreDeps({ issues: [jiraIssue({ id: '10042', key: KEY })] });
  t.jira.canBrowse = async () => ok(over.canBrowse ?? true);
  t.jira.canEdit = async () => ok(over.canEdit ?? true);
  return t;
}

describe('get-review-context (GET action)', () => {
  it('a caller without browse permission gets { error: "not_found" } — the same as a missing issue', async () => {
    const t = setup({ canBrowse: false });
    expect(await getReviewContext({ issueKey: KEY, ...ctx('acc-x') }, t.deps)).toEqual({ error: 'not_found' });
    expect(await getReviewContext({ issueKey: 'PAY-404', ...ctx('acc-x') }, t.deps)).toEqual({ error: 'not_found' });
    expect(await getReviewContext({ issueKey: KEY, ...ctx() }, t.deps)).toEqual({ error: 'not_found' });
    expect(t.gatherer.calls).toHaveLength(0);
  });

  it('wraps every untrusted fact in nonce delimiters and stays under 200 KB for a 1 MB page', async () => {
    const t = setup();
    const huge = 'The webhook trusts the X-Signature header. '.repeat(25_000);
    t.deps.gatherer = {
      async gather(issueId, opts) {
        const page = (i: number, text: string) =>
          normalizeFact({ sourceAri: `ari:cloud:confluence:c:page/${i}`, sourceType: 'confluence_page', title: `Page ${i}`, url: '', text, version: '1', trusted: false, origin: 'rest' });
        const facts = [page(0, huge), ...Array.from({ length: 150 }, (_, i) => page(i + 1, huge.slice(0, 1990)))];
        expect(opts?.actorAccountId).toBe('acc-1');
        const b: ContextBundle = { issueId, issueKey: KEY, facts, partial: false, partialReasons: [], contextHash: contextHash(facts), gatheredAt: 't', components: [] };
        return ok(b);
      },
    };
    t.deps.confluence = { canRead: async () => ok(true) } as never;
    const dto = await getReviewContext({ issueKey: KEY, ...ctx('acc-1') }, t.deps);
    if ('error' in dto) throw new Error(dto.error);
    expect(JSON.stringify(dto).length).toBeLessThanOrEqual(200 * 1024);
    expect(dto.truncated).toBe(true);
    for (const f of dto.facts.filter((x) => x.trust === 'untrusted')) expect(f.text.startsWith(`<<DATA-${dto.nonce} id="${f.id}">>`)).toBe(true);
    expect(dto.revision).toBe(1);
  });

  it('drops facts the caller cannot read (viewer scope)', async () => {
    const t = setup();
    t.deps.gatherer = {
      async gather(issueId) {
        const facts = [
          normalizeFact({ sourceAri: `ari:cloud:jira:c:issue/${issueId}`, sourceType: 'jira_issue', title: 'Main', url: '', text: 'main text', version: '1', trusted: false, origin: 'rest' }),
          normalizeFact({ sourceAri: 'ari:cloud:jira:c:issue/999', sourceType: 'jira_issue', title: 'Secret link', url: '', text: 'secret linked text', version: '1', trusted: false, origin: 'rest' }),
        ];
        return ok({ issueId, issueKey: KEY, facts, partial: false, partialReasons: [], contextHash: contextHash(facts), gatheredAt: 't', components: [] });
      },
    };
    t.jira.canBrowse = async (_a, id) => ok(id !== '999');
    const dto = await getReviewContext({ issueKey: KEY, ...ctx('acc-1') }, t.deps);
    if ('error' in dto) throw new Error(dto.error);
    expect(JSON.stringify(dto)).not.toContain('secret linked text');
  });
});

describe('race fix: agent runs saved at the same moment', () => {
  it('both are kept, numbered 1 and 2, instead of one overwriting the other', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    const [a, b] = await Promise.all([ingestSample(t.deps, KEY, JSON.stringify(MODEL), 'agent', 'acc-1'), ingestSample(t.deps, KEY, JSON.stringify(MODEL), 'agent', 'acc-1')]);
    expect(a.ok && b.ok).toBe(true);
    expect([a.ok && a.value.received, b.ok && b.value.received].sort()).toEqual([1, 2]);
    const latest = await t.deps.reviews.latest('10042');
    const s = latest.ok && latest.value ? await t.deps.reviews.samples(latest.value.id) : null;
    expect(s && s.ok && s.value.length).toBe(2);
  });
});

describe('security: only the configured review authors can submit agent runs (gap: developers steering their own review)', () => {
  const withAuthors = async (t: ReturnType<typeof setup>, authors: string[]) => {
    const p = await t.deps.config.site();
    if (!p.ok) throw new Error('policy');
    await t.deps.config.setSite({ ...p.value, reviewAuthors: authors });
  };

  it('a developer who can edit the work item but is not a review author is refused, and the attempt is ledgered', async () => {
    const t = setup();
    await withAuthors(t, ['acc-automation']);
    expect(await submit(t.deps, KEY, JSON.stringify(MODEL), 'acc-dev')).toEqual({ saved: false, error: 'not_review_author' });
    const rows = await t.deps.ledger.ofTypes(['review.sample_rejected']);
    expect(rows.ok && rows.value).toEqual([expect.objectContaining({ actor: 'acc-dev', payload: expect.objectContaining({ issueKey: KEY, reason: 'not_review_author' }) })]);
    const latest = await t.deps.reviews.latest('10042');
    const samples = latest.ok && latest.value ? await t.deps.reviews.samples(latest.value.id) : null;
    expect(samples && samples.ok ? samples.value.length : 0).toBe(0);
  });

  it('the configured author (the Automation rule owner) still submits', async () => {
    const t = setup();
    await withAuthors(t, ['acc-automation']);
    expect(await submit(t.deps, KEY, JSON.stringify(MODEL), 'acc-automation')).toMatchObject({ saved: true });
  });

  it('with no authors configured, anyone who can edit the work item may submit (the default)', async () => {
    const t = setup();
    expect(await submit(t.deps, KEY, JSON.stringify(MODEL), 'acc-dev')).toMatchObject({ saved: true });
  });
});

describe('submit-threat-model (CREATE action) and ingestSample', () => {
  it('prose-wrapped JSON is stored as a valid sample and pushes assemble', async () => {
    const t = setup();
    await asAuthor(t);
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    t.pushed.length = 0;
    const r = await submit(t.deps, KEY, proseWrapped);
    expect(r).toMatchObject({ saved: true, valid: true, received: 1, expected: 3 });
    const rev = (await t.deps.reviews.latest('10042')) as { ok: true; value: { id: string } };
    const samples = await t.deps.reviews.samples(rev.value.id);
    expect(samples.ok && samples.value[0]).toMatchObject({ schema: 'threatline.threatmodel.v1' });
    expect(t.pushed).toEqual([{ kind: 'assemble', reviewId: rev.value.id }]);
    expect(t.kv.data.get('ingest:recent')).toEqual([true]);
  });

  it('a run that writes past the contract (long title, extra keys) is fitted and stored valid, not as "Agent output was not valid"', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    const long = { ...MODEL, threats: [{ ...MODEL.threats[0]!, title: `Forged refund webhooks ${'accepted without a signature '.repeat(8)}`, confidence: 'high' }] };
    const r = await submit(t.deps, KEY, JSON.stringify(long));
    expect(r).toMatchObject({ saved: true, valid: true, received: 1 });
    const rev = (await t.deps.reviews.latest('10042')) as { ok: true; value: { id: string } };
    const samples = (await t.deps.reviews.samples(rev.value.id)) as { ok: true; value: Array<{ threats: Array<{ title: string; evidence: unknown }> }> };
    expect(samples.value[0]!.threats[0]!.title.length).toBeLessThanOrEqual(120);
    expect(samples.value[0]!.threats[0]!.evidence).toEqual(MODEL.threats[0]!.evidence);
  });

  it('garbage is stored as a failed sample and still pushes assemble', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    t.pushed.length = 0;
    const r = await submit(t.deps, KEY, 'I could not find anything.');
    expect(r).toMatchObject({ saved: true, valid: false, received: 1 });
    const rev = (await t.deps.reviews.latest('10042')) as { ok: true; value: { id: string } };
    const samples = await t.deps.reviews.samples(rev.value.id);
    expect(samples.ok && samples.value[0]).toEqual({ failed: 'no_json' });
    expect(t.pushed.map((j) => j.kind)).toEqual(['assemble']);
  });

  it('an empty agent response from a configured review author counts toward the Rovo-credits signal', async () => {
    const t = setup();
    await asAuthor(t);
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    await submit(t.deps, KEY, '  ');
    expect(t.kv.data.get('ingest:recent')).toEqual([false]);
  });

  it('security: with no review authors configured, an editor\'s empty response is not counted (it could pause the site)', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    await submit(t.deps, KEY, '  ');
    expect(t.kv.data.get('ingest:recent')).toBeUndefined();
  });

  it('a non-empty submission records when the Automation agent last delivered (setup checklist)', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    await submit(t.deps, KEY, '  ');
    expect(t.kv.data.has('ingest:lastAt')).toBe(false);
    await submit(t.deps, KEY, '{"schema":"threatline.threatmodel.v1","issueKey":"PAY-7","threats":[]}');
    expect(t.kv.data.get('ingest:lastAt')).toBe('2026-11-15T12:00:00.000Z');
  });

  it('the 3rd sample sets status ready after the consumer runs', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    for (let i = 0; i < 3; i++) await submit(t.deps, KEY, JSON.stringify(MODEL));
    await drain((j) => handleJob(t.deps, j), t.pushed);
    const l = await t.deps.reviews.latest('10042');
    expect(l.ok && l.value).toMatchObject({ status: 'ready', samplesReceived: 3 });
  });

  it('a 4th sample is refused once all agent runs are in', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    for (let i = 0; i < 3; i++) await submit(t.deps, KEY, JSON.stringify(MODEL));
    const r = await submit(t.deps, KEY, JSON.stringify(MODEL));
    expect(r).toMatchObject({ saved: false, error: 'complete' });
  });

  it('with no open review, a submission first creates one (synchronous gather), then stores the sample', async () => {
    const t = setup();
    const r = await submit(t.deps, KEY, JSON.stringify(MODEL));
    expect(r).toMatchObject({ saved: true, received: 1 });
    const l = await t.deps.reviews.latest('10042');
    expect(l.ok && l.value).toMatchObject({ revision: 1, status: 'awaiting_agent' });
  });

  it('final review C2: every saved agent run is ledgered with who submitted it, so a self-written review is auditable', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    await submit(t.deps, KEY, JSON.stringify(MODEL), 'acc-dev');
    await submit(t.deps, KEY, 'not json', 'acc-agent');
    const rows = await t.deps.ledger.all();
    const samples = (rows.ok ? rows.value : []).filter((e) => e.eventType === 'review.sample');
    expect(samples.map((e) => ({ actor: e.actor, ...e.payload }))).toEqual([
      { actor: 'acc-dev', issueId: '10042', reviewId: 'rev_10042_1', n: 1, valid: true, threats: 1 },
      { actor: 'acc-agent', issueId: '10042', reviewId: 'rev_10042_1', n: 2, valid: false, threats: 0 },
    ]);
  });

  it('a caller who cannot edit the work item cannot submit (and learns nothing about it)', async () => {
    const t = setup({ canEdit: false });
    const r = await submit(t.deps, KEY, JSON.stringify(MODEL));
    expect(r).toEqual({ saved: false, error: 'not_found' });
  });

  it('a project that is not enabled is refused', async () => {
    const t = coreDeps({ issues: [jiraIssue({ id: '10042', key: 'HR-1', project: { id: '9', key: 'HR' } })] });
    const r = await submit(t.deps, 'HR-1', JSON.stringify({ ...MODEL, issueKey: 'HR-1' }));
    expect(r).toEqual({ saved: false, error: 'project_not_enabled' });
  });

  it('a threat model for a different issue is a failed sample (wrong_issue)', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    const r = await ingestSample(t.deps, KEY, JSON.stringify({ ...MODEL, issueKey: 'PAY-999' }), 'agent', 'acc-1');
    expect(r.ok && r.value).toMatchObject({ received: 1, valid: false });
  });

  it('rejects malformed inputs without touching anything', async () => {
    const t = setup();
    expect(await submitThreatModel({ issueKey: 'not a key', threatModelJson: '{}', submissionToken: 'x', ...ctx('acc-1') }, t.deps)).toEqual({ saved: false, error: 'invalid_input' });
    expect(await submitThreatModel({ issueKey: KEY, threatModelJson: 42 as never, submissionToken: 'x', ...ctx('acc-1') }, t.deps)).toEqual({ saved: false, error: 'invalid_input' });
    expect(t.gatherer.calls).toHaveLength(0);
  });

  describe('security: a submission must carry the single-use token from get-review-context', () => {
    const ready = async () => {
      const t = setup();
      await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
      return t;
    };
    const tokenFor = async (t: ReturnType<typeof setup>, issueKey: string, accountId = 'acc-1') => {
      const c = await getReviewContext({ issueKey, ...ctx(accountId) }, t.deps);
      if (!('submissionToken' in c)) throw new Error('no token');
      return c.submissionToken;
    };

    it('no token, an unknown token, or a token reused a second time is refused', async () => {
      const t = await ready();
      const base = { issueKey: KEY, threatModelJson: JSON.stringify(MODEL), ...ctx('acc-1') };
      expect(await submitThreatModel(base, t.deps)).toEqual({ saved: false, error: 'invalid_token' });
      expect(await submitThreatModel({ ...base, submissionToken: 'deadbeef'.repeat(4) }, t.deps)).toEqual({ saved: false, error: 'invalid_token' });
      const tok = await tokenFor(t, KEY);
      expect(await submitThreatModel({ ...base, submissionToken: tok }, t.deps)).toMatchObject({ saved: true });
      expect(await submitThreatModel({ ...base, submissionToken: tok }, t.deps)).toEqual({ saved: false, error: 'invalid_token' });
    });

    it('a token issued for another work item cannot submit for this one (no cross-issue writes)', async () => {
      const t = coreDeps({ issues: [jiraIssue({ id: '10042', key: KEY }), jiraIssue({ id: '10043', key: 'PAY-8' })] });
      await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
      const tok = await tokenFor(t as never, 'PAY-8');
      const r = await submitThreatModel({ issueKey: KEY, threatModelJson: JSON.stringify(MODEL), submissionToken: tok, ...ctx('acc-1') }, t.deps);
      expect(r).toEqual({ saved: false, error: 'invalid_token' });
    });

    it('a token issued to another caller is refused', async () => {
      const t = await ready();
      const tok = await tokenFor(t, KEY, 'acc-other');
      const r = await submitThreatModel({ issueKey: KEY, threatModelJson: JSON.stringify(MODEL), submissionToken: tok, ...ctx('acc-1') }, t.deps);
      expect(r).toEqual({ saved: false, error: 'invalid_token' });
    });

    it('a token expires after 30 minutes', async () => {
      const t = await ready();
      const tok = await tokenFor(t, KEY);
      t.clock.advance(31 * 60_000);
      const r = await submitThreatModel({ issueKey: KEY, threatModelJson: JSON.stringify(MODEL), submissionToken: tok, ...ctx('acc-1') }, t.deps);
      expect(r).toEqual({ saved: false, error: 'invalid_token' });
    });

    it('the token is never stored in plain form (KVS holds its hash)', async () => {
      const t = await ready();
      const tok = await tokenFor(t, KEY);
      expect(JSON.stringify([...t.kv.data.keys(), ...t.kv.data.values()])).not.toContain(tok);
    });
  });
});
