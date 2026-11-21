import { describe, expect, it } from 'vitest';
import { ok, type Requirement } from '@threatline/shared';
import { CI_STATIC_OUTPUTS, toStaticOutput } from '../../src/webtriggers/ci-static.js';
import { CI_REPORTS_PER_HOUR, ciVerify, MAX_BODY_BYTES, type CiVerifyResponse } from '../../src/webtriggers/ci-verify.js';
import { createCiToken } from '../../src/services/ci-tokens.js';
import { requirementsSetStatus } from '../../src/resolvers/requirements.js';
import { setRequirementStatus } from '../../src/services/requirements-service.js';
import { readVerdict } from '../../src/services/verdict-service.js';
import { coreDeps, jiraIssue } from '../support/core-deps.js';
import { ADMIN, DEV, ISSUE, reviewed } from '../support/reviewed.js';

const SHA = 'ab'.repeat(20);
const RUN = 'https://github.com/acme/payments/actions/runs/42';

async function setup(o: { projects?: string[]; allOpen?: boolean } = {}) {
  const r = await reviewed();
  const created = await createCiToken(r.t.deps, ADMIN, { projects: o.projects ?? [] });
  if (!created.ok) throw new Error('token');
  const post = (body: unknown, headers: Record<string, string[]> = { authorization: [`Bearer ${created.value.token}`] }, method = 'POST') =>
    ciVerify(r.t.deps, { method, headers: { 'content-type': ['application/json'], ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  const report = (results: Array<{ name: string; status: string }>, over: Record<string, unknown> = {}) => post({ issueKey: 'PAY-7', repo: 'acme/payments', commitSha: SHA, runUrl: RUN, results, ...over });
  return { ...r, token: created.value.token, tokenId: created.value.info.id, post, report };
}
const json = (res: { body: string }) => JSON.parse(res.body) as CiVerifyResponse & { error?: string; message?: string };
const current = async (t: Awaited<ReturnType<typeof setup>>['t'], id: string) => ((await t.deps.requirements.get(id)) as { ok: true; value: Requirement }).value;

describe('CI web trigger: verifies requirements whose tests passed (feature: verification from CI)', () => {
  it('a passing test named for the open requirement verifies it with the run as evidence, ledgered as CI, and the Done gate opens', async () => {
    const s = await setup();
    expect((await readVerdict(s.t.deps, ISSUE)) as unknown).toMatchObject({ ok: true, value: { state: 'block' } });
    const res = await s.report([
      { name: `PAY-7 Verify webhook signatures [${s.req.id}] > rejects a bad signature`, status: 'passed' },
      { name: `PAY-7 Verify webhook signatures [${s.req.id}] > rejects a replay`, status: 'passed' },
      { name: 'unrelated test', status: 'failed' },
    ]);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toEqual(['application/json']);
    const body = json(res);
    expect(body).toMatchObject({ issueKey: 'PAY-7', commitSha: SHA, verdict: 'pass', ignoredTests: 1, results: [{ requirementId: s.req.id, outcome: 'verified', passed: 2, failed: 0, skipped: 0 }] });
    const after = await current(s.t, s.req.id);
    expect(after).toMatchObject({ status: 'Verified', verifiedBy: `ci:${s.tokenId}`, evidence: { kind: 'ci', ref: RUN, commitSha: SHA, repo: 'acme/payments', attester: `ci:${s.tokenId}` } });
    const ledger = ((await s.t.deps.ledger.all()) as { ok: true; value: Array<{ eventType: string; actor: string; payload: Record<string, unknown> }> }).value;
    expect(ledger.at(-1)).toMatchObject({
      eventType: 'requirement.verified',
      actor: `ci:${s.tokenId}`,
      payload: { requirementId: s.req.id, issueId: ISSUE, from: 'Open', to: 'Verified', evidenceKind: 'ci', evidence: RUN, viaCi: true, ciTokenId: s.tokenId, commitSha: SHA, repo: 'acme/payments', viaAgent: false },
    });
    expect(JSON.stringify(ledger)).not.toContain(s.token.slice(22));
    expect(await readVerdict(s.t.deps, ISSUE)).toMatchObject({ ok: true, value: { state: 'pass' } });
  });

  it('a requirement with any failing test on the run is not verified; one verified earlier stays verified and is reported', async () => {
    const s = await setup();
    const res = await s.report([
      { name: `a [${s.req.id}]`, status: 'passed' },
      { name: `b [${s.req.id}]`, status: 'failed' },
    ]);
    expect(json(res).results).toEqual([{ requirementId: s.req.id, outcome: 'failed', passed: 1, failed: 1, skipped: 0, message: expect.stringMatching(/failed/) }]);
    expect((await current(s.t, s.req.id)).status).toBe('Open');
    expect(json(res).verdict).toBe('block');

    await s.report([{ name: `a [${s.req.id}]`, status: 'passed' }], { commitSha: 'cd'.repeat(20) });
    expect((await current(s.t, s.req.id)).status).toBe('Verified');
    const ledgerBefore = ((await s.t.deps.ledger.all()) as { ok: true; value: unknown[] }).value.length;
    const later = json(await s.report([{ name: `a [${s.req.id}]`, status: 'failed' }], { commitSha: 'ef'.repeat(20) }));
    expect(later.results[0]).toMatchObject({ outcome: 'failed', stillVerified: true, message: expect.stringMatching(/still Verified/) });
    expect((await current(s.t, s.req.id))).toMatchObject({ status: 'Verified', evidence: { commitSha: 'cd'.repeat(20) } });
    expect(((await s.t.deps.ledger.all()) as { ok: true; value: unknown[] }).value).toHaveLength(ledgerBefore);
  });

  it('reports already verified, only skipped, unknown ids, other work items, and requirements people closed, without changing them', async () => {
    const s = await setup();
    const all = await s.reqs();
    const other = all.find((r) => r.id !== s.req.id)!;
    const foreign: Requirement = { ...s.req, id: 'req_ffffffffffffffff', issueId: '99999', issueKey: 'PAY-99', threatId: 'thr_x' };
    await s.t.deps.requirements.upsert(foreign);
    const res = json(
      await s.report([
        { name: `x ${other.id}`, status: 'passed' },
        { name: `y ${s.req.id}`, status: 'skipped' },
        { name: 'z req_0123456789abcdef', status: 'passed' },
        { name: `w ${foreign.id}`, status: 'passed' },
      ]),
    );
    const by = Object.fromEntries(res.results.map((r) => [r.requirementId, r.outcome]));
    expect(by).toEqual({ [other.id]: 'already_verified', [s.req.id]: 'skipped', req_0123456789abcdef: 'unknown', [foreign.id]: 'not_this_issue' });
    expect((await current(s.t, s.req.id)).status).toBe('Open');
    expect((await current(s.t, foreign.id)).status).toBe('Open');
  });

  it('agents and CI never decide for people: an accepted risk or Not applicable stays as it is', async () => {
    const s = await setup();
    await s.t.deps.requirements.upsert({ ...s.req, status: 'AcceptedRisk' });
    const res = json(await s.report([{ name: `t ${s.req.id}`, status: 'passed' }]));
    expect(res.results[0]).toMatchObject({ outcome: 'not_open' });
    expect((await current(s.t, s.req.id)).status).toBe('AcceptedRisk');
  });

  it('race: a risk accepted after the report read the requirement is never overwritten (fresh read, then compare-and-set)', async () => {
    // A person accepts the risk just after the web trigger read the row: setRequirementStatus re-reads and refuses.
    const s = await setup();
    const get = s.t.deps.requirements.get.bind(s.t.deps.requirements);
    let reads = 0;
    s.t.deps.requirements.get = async (id) => {
      const r = await get(id);
      if (++reads === 1 && r.ok && r.value) await s.t.deps.requirements.upsert({ ...r.value, status: 'AcceptedRisk' });
      return r;
    };
    const before = ((await s.t.deps.ledger.all()) as { ok: true; value: unknown[] }).value.length;
    const first = json(await s.report([{ name: `t ${s.req.id}`, status: 'passed' }]));
    expect(first.results[0]).toMatchObject({ outcome: 'not_open' });
    expect((await current(s.t, s.req.id)).status).toBe('AcceptedRisk');
    expect(((await s.t.deps.ledger.all()) as { ok: true; value: unknown[] }).value).toHaveLength(before);

    // It changes between setRequirementStatus's own read and its write (while the ledger entry is written): the
    // conditional save refuses, and the ledger records that the change did not take effect.
    const u = await setup();
    const append = u.t.deps.ledger.append.bind(u.t.deps.ledger);
    u.t.deps.ledger.append = async (e) => {
      if (e.eventType === 'requirement.verified') await u.t.deps.requirements.upsert({ ...(await current(u.t, u.req.id)), status: 'NotApplicable' });
      return append(e);
    };
    const second = json(await u.report([{ name: `t ${u.req.id}`, status: 'passed' }]));
    expect(second.results[0]).toMatchObject({ outcome: 'not_open' });
    expect((await current(u.t, u.req.id)).status).toBe('NotApplicable');
    const rows = ((await u.t.deps.ledger.all()) as { ok: true; value: Array<{ eventType: string; payload: Record<string, unknown> }> }).value;
    expect(rows.slice(-2).map((r) => r.eventType)).toEqual(['requirement.verified', 'requirement.status_change_failed']);
    expect(rows.at(-1)!.payload).toMatchObject({ requirementId: u.req.id, code: 'conflict' });
  });

  it('a requirement’s own sub-task key names it too (branch PAY-101-…), and the parent’s verdict is reported', async () => {
    const s = await setup();
    await s.t.deps.requirements.upsert({ ...s.req, subtaskKey: 'PAY-101' });
    s.t.jira.issue = async (ref) => ok(ref === 'PAY-101' ? jiraIssue({ id: '20001', key: 'PAY-101', parent: { id: ISSUE, key: 'PAY-7' } }) : jiraIssue({ id: ISSUE, key: 'PAY-7' }));
    const res = json(await s.report([{ name: `t ${s.req.id}`, status: 'passed' }], { issueKey: 'PAY-101' }));
    expect(res).toMatchObject({ issueKey: 'PAY-101', verdict: 'pass', results: [{ outcome: 'verified' }] });
  });

  it('a requirement whose threat left the review is not verified (not_current)', async () => {
    const s = await setup();
    await s.t.deps.requirements.upsert({ ...s.req, threatId: 'thr_gone' });
    const res = json(await s.report([{ name: `t ${s.req.id}`, status: 'passed' }]));
    expect(res.results[0]).toMatchObject({ outcome: 'not_current' });
  });
});

describe('CI web trigger: security', () => {
  it('needs the bearer token: missing, wrong or revoked tokens are 401, and the body never echoes the token', async () => {
    const s = await setup();
    const body = { issueKey: 'PAY-7', repo: 'acme/payments', commitSha: SHA, runUrl: RUN, results: [{ name: s.req.id, status: 'passed' }] };
    for (const h of [{} as Record<string, string[]>, { authorization: ['Bearer nope'] }, { authorization: [`Basic ${s.token}`] }, { Authorization: [`Bearer ${s.token.slice(0, -2)}xx`] }]) {
      const res = await s.post(body, h);
      expect(res.statusCode).toBe(401);
      expect(res.headers['www-authenticate']).toEqual(['Bearer']);
      expect(res.body).not.toContain(s.token);
    }
    expect((await current(s.t, s.req.id)).status).toBe('Open');
    // Header names are case-insensitive.
    expect((await s.post(body, { Authorization: [`Bearer ${s.token}`] })).statusCode).toBe(200);
  });

  it('only POST with a JSON body of at most 256 KB that matches the format', async () => {
    const s = await setup();
    expect((await s.post({}, undefined, 'GET')).statusCode).toBe(405);
    expect((await s.post('x'.repeat(MAX_BODY_BYTES + 1))).statusCode).toBe(413);
    expect((await s.post('{not json')).statusCode).toBe(400);
    const base = { issueKey: 'PAY-7', repo: 'acme/payments', commitSha: SHA, runUrl: RUN, results: [] };
    for (const bad of [
      { ...base, commitSha: 'abc' },
      { ...base, runUrl: 'http://ci.example/run/1' },
      { ...base, runUrl: 'javascript:alert(1)' },
      { ...base, issueKey: 'pay 7' },
      { ...base, repo: '../x' },
      { ...base, results: [{ name: 'x', status: 'ok' }] },
      { ...base, extra: true },
    ]) {
      const res = await s.post(bad);
      expect(res.statusCode, JSON.stringify(bad)).toBe(400);
      expect(json(res).error).toBe('validation');
    }
  });

  it('rate-limits each token per hour', async () => {
    const s = await setup();
    for (let i = 0; i < CI_REPORTS_PER_HOUR; i++) expect((await s.report([])).statusCode).toBe(200);
    const res = await s.report([]);
    expect(res.statusCode).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
  });

  it('fails closed on storage errors: nothing is verified and the answer is 503', async () => {
    const s = await setup();
    const getSecret = s.t.deps.state.getSecret;
    s.t.deps.state.getSecret = async () => Promise.reject(new Error('kvs down'));
    expect((await s.report([{ name: s.req.id, status: 'passed' }])).statusCode).toBe(503);
    s.t.deps.state.getSecret = getSecret;
    s.t.deps.usage.takeSlot = async () => ({ ok: false, error: { code: 'upstream', message: 'sql down' } });
    expect((await s.report([{ name: s.req.id, status: 'passed' }])).statusCode).toBe(503);
    expect((await current(s.t, s.req.id)).status).toBe('Open');
  });

  it('a ledger failure verifies nothing and answers 503 with the per-requirement error', async () => {
    const s = await setup();
    s.t.deps.ledger.append = async () => ({ ok: false, error: { code: 'upstream', message: 'sql down' } });
    const res = await s.report([{ name: s.req.id, status: 'passed' }]);
    expect(res.statusCode).toBe(503);
    expect(json(res).results[0]).toMatchObject({ outcome: 'error' });
    expect((await current(s.t, s.req.id)).status).toBe('Open');
  });

  it('the work item must exist and be in a Threatline project; a token limited to projects refuses others', async () => {
    const s = await setup({ projects: ['SEC'] });
    const res = await s.report([{ name: s.req.id, status: 'passed' }]);
    expect(res.statusCode).toBe(403);
    expect(json(res).message).toMatch(/limited/);

    const u = await setup();
    expect((await u.report([], { issueKey: 'PAY-404' })).statusCode).toBe(404);
    u.t.jira.issue = async () => ok(jiraIssue({ id: ISSUE, key: 'OPS-7', project: { id: '1', key: 'OPS' } }));
    const off = await u.report([{ name: u.req.id, status: 'passed' }], { issueKey: 'OPS-7' });
    expect(off.statusCode).toBe(403);
    expect(json(off).message).toMatch(/not on/);
    expect((await current(u.t, u.req.id)).status).toBe('Open');
  });

  it('the panel and agents cannot forge CI evidence', async () => {
    const s = await setup();
    const panel = await requirementsSetStatus(s.t.deps, { accountId: DEV, issueId: ISSUE }, { requirementId: s.req.id, status: 'Verified', evidence: { kind: 'ci', ref: RUN } });
    expect(panel).toMatchObject({ error: 'validation' });
    const direct = await setRequirementStatus(s.t.deps, { accountId: DEV, issueId: ISSUE }, { requirementId: s.req.id, status: 'Verified', evidence: { kind: 'ci', ref: RUN } });
    expect(direct).toMatchObject({ ok: false, error: { code: 'validation' } });
    expect((await current(s.t, s.req.id)).status).toBe('Open');
  });
});

describe('manifest: the ci-verify web trigger (static, Runs on Atlassian)', () => {
  it('is static, its outputs are exactly the fixed answers in ci-static.ts, and index.ts exports the handler', async () => {
    const { readFileSync } = await import('node:fs');
    const { parse } = await import('yaml');
    const m = parse(readFileSync(new URL('../../manifest.yml', import.meta.url), 'utf8')) as { modules: Record<string, Array<Record<string, unknown>>> };
    const trigger = m.modules.webtrigger?.find((w) => w.key === 'ci-verify') as { function: string; response: { type: string; outputs: Array<Record<string, unknown>> } };
    expect(trigger).toMatchObject({ function: 'ciVerifyFn', response: { type: 'static' } });
    expect(trigger.response.outputs).toEqual(CI_STATIC_OUTPUTS.map((o) => ({ key: o.key, statusCode: o.statusCode, contentType: 'application/json', body: o.body })));
    for (const o of CI_STATIC_OUTPUTS) expect(() => JSON.parse(o.body)).not.toThrow();
    expect(m.modules.function!.find((f) => f.key === 'ciVerifyFn')?.handler).toBe('index.ciVerifyHandler');
    expect(readFileSync(new URL('../../src/index.ts', import.meta.url), 'utf8')).toMatch(/\bciVerifyHandler\b/);
  });
});

describe('static outputs: the full answer maps to a fixed one, never echoing request or work-item data', () => {
  const res = (statusCode: number, body: unknown) => ({ statusCode, headers: {}, body: typeof body === 'string' ? body : JSON.stringify(body) });
  it.each([
    [res(200, { verdict: 'pass', results: [] }), 'recorded-pass'],
    [res(200, { verdict: 'warn' }), 'recorded-warn'],
    [res(200, { verdict: 'block' }), 'recorded-block'],
    [res(200, 'not json'), 'unavailable'],
    [res(200, { verdict: 'other' }), 'unavailable'],
    [res(400, {}), 'bad-request'],
    [res(401, {}), 'unauthorized'],
    [res(403, {}), 'forbidden'],
    [res(404, {}), 'not-found'],
    [res(405, {}), 'method'],
    [res(413, {}), 'too-large'],
    [res(429, {}), 'rate-limited'],
    [res(503, {}), 'unavailable'],
    [res(500, {}), 'unavailable'],
  ])('%o → %s', (r, key) => {
    expect(toStaticOutput(r)).toEqual({ outputKey: key });
  });

  it('the handler answers with an outputKey only', async () => {
    const out = toStaticOutput(await ciVerify(coreDeps().deps, { method: 'GET', headers: {}, body: '' }));
    expect(out).toEqual({ outputKey: 'method' });
  });
});
