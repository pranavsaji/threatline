import { describe, expect, it } from 'vitest';
import type { FixCheckRecord, Requirement } from '@threatline/shared';
import { FakeLlm } from '../../../../packages/core/test/fakes/fake-llm.js';
import { toStaticOutput } from '../../src/webtriggers/ci-static.js';
import { ciVerify, type CiVerifyResponse } from '../../src/webtriggers/ci-verify.js';
import { createCiToken } from '../../src/services/ci-tokens.js';
import { handleJob } from '../../src/consumers/review-consumer.js';
import { readFixCheck } from '../../src/services/fix-check-store.js';
import { readVerdict } from '../../src/services/verdict-service.js';
import { fixCheckConfirm } from '../../src/resolvers/requirements.js';
import { panelGet } from '../../src/resolvers/panel.js';
import { ADMIN, CHAMP, DEV, ISSUE, reviewed } from '../support/reviewed.js';

const SHA = 'ab'.repeat(20);
const SHA2 = 'cd'.repeat(20);
const RUN = 'https://bitbucket.org/acme/payments/pipelines/results/42';
const PR = 'https://bitbucket.org/acme/payments/pull-requests/7';
const DIFF = `diff --git a/src/webhooks/refund.ts b/src/webhooks/refund.ts
--- a/src/webhooks/refund.ts
+++ b/src/webhooks/refund.ts
@@ -10,2 +10,4 @@ export async function onRefund(req, res) {
   const raw = await readRaw(req);
+  if (!verifySignature(raw, req.headers['x-signature'], env.WEBHOOK_SECRET)) return res.status(401).end();
+  const event = JSON.parse(raw);
   await payout(event);
`;

/** A fix-check reply giving every requirement in the prompt the same verdict (quoting the signature check). */
const reply = (verdict: 'fixed' | 'not_addressed') => (req: { user: string }) =>
  JSON.stringify({
    results: [...req.user.matchAll(/^(R\d+) \[/gm)].map((m) => ({
      id: m[1],
      verdict,
      reason: verdict === 'fixed' ? 'verifySignature guards onRefund' : 'nothing checks the signature',
      quotes: verdict === 'fixed' ? [{ path: 'src/webhooks/refund.ts', line: 11, text: "if (!verifySignature(raw, req.headers['x-signature'], env.WEBHOOK_SECRET))" }] : [],
      ...(verdict === 'fixed' ? {} : { missing: 'a signature check', suggestion: { summary: 'check it', code: 'verifySignature(raw, sig, secret)' } }),
    })),
  });

async function setup(verdict: 'fixed' | 'not_addressed' | 'down' = 'not_addressed') {
  const r = await reviewed();
  r.t.deps.llm = new FakeLlm(verdict === 'down' ? {} : { fix_check: reply(verdict) });
  const created = await createCiToken(r.t.deps, ADMIN, { projects: [] });
  if (!created.ok) throw new Error('token');
  const report = (over: Record<string, unknown> = {}) =>
    ciVerify(r.t.deps, {
      method: 'POST',
      headers: { authorization: [`Bearer ${created.value.token}`] },
      body: JSON.stringify({ issueKey: 'PAY-7', repo: 'acme/payments', commitSha: SHA, runUrl: RUN, prUrl: PR, diff: DIFF, results: [{ name: `t [${r.req.id}]`, status: 'passed' }], ...over }),
    });
  const run = async () => {
    const jobs = r.t.pushed.splice(0);
    for (const j of jobs) await handleJob(r.t.deps, j);
  };
  const verdict$ = async () => ((await readVerdict(r.t.deps, ISSUE)) as { ok: true; value: { state: string; reasons: Array<{ code: string }> } }).value;
  return { ...r, report, run, verdict: verdict$, tokenId: created.value.info.id };
}
const body = (res: { body: string }) => JSON.parse(res.body) as CiVerifyResponse;

describe('fix check (docs/FIX_CHECK.md): CI sends the change, Threatline Engine checks it fixes the requirement', () => {
  it('a report with a diff verifies the requirement but holds it while the check runs, then holds it for a champion when the change does not fix it', async () => {
    const s = await setup('not_addressed');
    const res = await s.report();
    expect(body(res)).toMatchObject({ verdict: 'block', fixCheck: 'checking', verified: 1 });
    expect(toStaticOutput(res)).toEqual({ outputKey: 'recorded-checking' });
    expect((await s.verdict()).reasons.map((x) => x.code)).toEqual(['fix_check_pending']);
    expect(s.t.pushed).toContainEqual({ kind: 'fix_check', issueId: ISSUE, commitSha: SHA });

    await s.run();
    const v = await s.verdict();
    expect(v.state).toBe('block');
    expect(v.reasons.map((x) => x.code)).toEqual(['fix_unconfirmed']);
    const rec = ((await readFixCheck(s.t.deps, ISSUE)) as { ok: true; value: FixCheckRecord }).value;
    expect(rec).toMatchObject({ status: 'done', commitSha: SHA, prUrl: PR, promptVersion: 'fix-v1.0.0' });
    expect(rec.findings.find((f) => f.requirementId === s.req.id)).toMatchObject({ verdict: 'not_addressed', testsNamed: 0, suggestion: { code: 'verifySignature(raw, sig, secret)' } });
    // The change is not kept after the check.
    expect([...s.t.kv.data.keys()].some((k) => k.startsWith('fixcheck-diff:'))).toBe(false);
    const ledger = ((await s.t.deps.ledger.all()) as { ok: true; value: Array<{ eventType: string; actor: string; payload: Record<string, unknown> }> }).value;
    expect(ledger.find((e) => e.eventType === 'fix_check.completed')).toMatchObject({ actor: `ci:${s.tokenId}`, payload: { commitSha: SHA, status: 'done' } });
  });

  it('a security champion (only) can confirm it is fixed; the confirmation is ledgered and Done opens', async () => {
    const s = await setup('not_addressed');
    await s.report();
    await s.run();
    expect(await fixCheckConfirm(s.t.deps, { accountId: DEV, issueId: ISSUE }, { requirementId: s.req.id })).toMatchObject({ error: 'forbidden' });
    expect(await fixCheckConfirm(s.t.deps, { accountId: CHAMP, issueId: ISSUE }, { requirementId: s.req.id })).toEqual({ ok: true });
    expect((await s.verdict()).state).toBe('pass');
    const ledger = ((await s.t.deps.ledger.all()) as { ok: true; value: Array<{ eventType: string; actor: string }> }).value;
    expect(ledger.at(-1)).toMatchObject({ eventType: 'fix_check.confirmed', actor: CHAMP });
    // Nothing left to confirm.
    expect(await fixCheckConfirm(s.t.deps, { accountId: CHAMP, issueId: ISSUE }, { requirementId: s.req.id })).toMatchObject({ error: 'validation' });
  });

  it('a change that fixes it, with a quote code can find, lets Done open with no champion', async () => {
    const s = await setup('fixed');
    await s.report();
    await s.run();
    expect((await s.verdict()).state).toBe('pass');
    const p = await panelGet(s.t.deps, { accountId: DEV, issueId: ISSUE });
    if ('error' in p) throw new Error('panel');
    expect(p.fixCheck?.findings.find((f) => f.requirementId === s.req.id)).toMatchObject({ verdict: 'fixed', quotes: [{ path: 'src/webhooks/refund.ts', line: 11 }] });
    expect(p.fixCheck?.holds).toEqual({});
    expect(p.fixCheck).not.toHaveProperty('by');
  });

  it('fails closed: a check that cannot run holds the verified requirement for a champion', async () => {
    const s = await setup('down');
    await s.report();
    await s.run();
    expect((await s.verdict()).reasons.map((x) => x.code)).toEqual(['fix_unconfirmed']);
    expect(((await readFixCheck(s.t.deps, ISSUE)) as { ok: true; value: { status: string } }).value.status).toBe('failed');
  });

  it('the same commit is checked once; a newer commit replaces the check and its old job does nothing', async () => {
    const s = await setup('fixed');
    await s.report();
    await s.run();
    s.t.pushed.length = 0;
    const again = await s.report();
    expect(body(again).fixCheck).toBe('already_checked');
    expect(s.t.pushed).toEqual([]);
    await s.report({ commitSha: SHA2, results: [] });
    expect(s.t.pushed).toEqual([{ kind: 'fix_check', issueId: ISSUE, commitSha: SHA2 }]);
    s.t.pushed.length = 0;
    await handleJob(s.t.deps, { kind: 'fix_check', issueId: ISSUE, commitSha: SHA });
    expect(((await readFixCheck(s.t.deps, ISSUE)) as { ok: true; value: { commitSha: string; status: string } }).value).toMatchObject({ commitSha: SHA2, status: 'pending' });
  });

  it('only a requirement verified for this change is held: one verified by other evidence is left alone', async () => {
    const s = await setup('not_addressed');
    await s.t.deps.requirements.upsert({ ...(s.req as Requirement), status: 'Verified', verifiedBy: 'x', evidence: { kind: 'confluence', ref: 'https://wiki/page', attester: 'x' } });
    await s.report({ results: [] });
    await s.run();
    expect((await s.verdict()).state).toBe('pass');
  });

  it('refuses a change over the size limit, and a pull request link that is not https', async () => {
    const s = await setup();
    expect((await s.report({ diff: 'x'.repeat(200_001) })).statusCode).toBe(400);
    expect((await s.report({ diff: 'x'.repeat(190_000) })).statusCode).toBe(200);
    expect((await s.report({ prUrl: 'http://bitbucket.org/x' })).statusCode).toBe(400);
  });
});
