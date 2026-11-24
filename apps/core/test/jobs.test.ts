import { describe, expect, it, vi } from 'vitest';
import { MIGRATIONS } from '@threatline/db';
import { migrate } from '@threatline/db';
import { sqliteExecutor } from '../../../packages/db/test/sqlite-executor.js';
import { sqlRetention } from '@threatline/db';
import { handleJob } from '../src/consumers/review-consumer.js';
import { sweep } from '../src/jobs/sweeper.js';
import { hourly } from '../src/jobs/hourly.js';
import { daily } from '../src/jobs/daily.js';
import { appendLedger } from '@threatline/core';
import { checkRerunLimit } from '../src/services/rate-limit.js';
import { coreDeps, drain, POLICY } from './support/core-deps.js';

describe('sweeper', () => {
  it('turns a 20-minute-old awaiting_agent review into agent_timeout and the verdict reason agent_missing', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    t.clock.set('2026-11-15T12:20:00Z');
    await sweep(t.deps);
    const l = await t.deps.reviews.latest('10042');
    expect(l.ok && l.value?.status).toBe('agent_timeout');
    const v = t.verdicts._written.get('10042') as { reasons: Array<{ code: string; message: string }> };
    const missing = v.reasons.find((r) => r.code === 'agent_missing');
    expect(missing?.message).toMatch(/did not arrive in time/);
  });

  it('M5: a timed-out review with some agent runs in is assembled from what arrived, instead of staying blocked', async () => {
    const t = coreDeps();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    const rev = (await t.deps.reviews.latest('10042')) as { ok: true; value: { id: string } };
    const model = { schema: 'threatline.threatmodel.v1' as const, issueKey: 'PAY-7', threats: [{ stride: 'Spoofing' as const, title: 'Forged refund webhooks', scenario: 'An attacker posts a fake refund event.', component: 'webhook endpoint', likelihood: 4, impact: 4, evidence: [{ quote: 'Public webhook that receives refund events' }] }] };
    for (const n of [1, 2]) await t.deps.reviews.saveSample(rev.value.id, n, model);
    t.clock.set('2026-11-15T12:20:00Z');
    t.pushed.length = 0;
    await sweep(t.deps);
    expect(t.pushed).toContainEqual({ kind: 'assemble', reviewId: rev.value.id });
    await drain((job) => handleJob(t.deps, job), t.pushed);
    const l = (await t.deps.reviews.latest('10042')) as { ok: true; value: { status: string } };
    expect(l.value.status).not.toBe('awaiting_agent');
    const threats = (await t.deps.reviews.threats(rev.value.id)) as { ok: true; value: Array<{ title: string; origin: string }> };
    expect(threats.value.some((x) => x.origin === 'agent' && /Forged refund/.test(x.title))).toBe(true);
  });

  it('the timeout counts from when the review started, not from its last run (live: 2 of 3 runs, settled 23 minutes in)', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    const rev = (await t.deps.reviews.latest('10042')) as { ok: true; value: { id: string } };
    const model = { schema: 'threatline.threatmodel.v1' as const, issueKey: 'PAY-7', threats: [{ stride: 'Spoofing' as const, title: 'Forged refund webhooks', scenario: 'An attacker posts a fake refund event.', component: 'webhook endpoint', likelihood: 4, impact: 4, evidence: [{ quote: 'Public webhook that receives refund events' }] }] };
    // Two runs arrive 10 minutes in and are assembled (the review's updatedAt moves to 12:10); the third never comes.
    t.clock.set('2026-11-15T12:10:00Z');
    for (const n of [1, 2]) await t.deps.reviews.saveSample(rev.value.id, n, model);
    await handleJob(t.deps, { kind: 'assemble', reviewId: rev.value.id });
    t.clock.set('2026-11-15T12:16:00Z');
    t.pushed.length = 0;
    await sweep(t.deps);
    expect(t.pushed).toContainEqual({ kind: 'assemble', reviewId: rev.value.id });
    await drain((job) => handleJob(t.deps, job), t.pushed);
    const l = (await t.deps.reviews.latest('10042')) as { ok: true; value: { status: string; samplesReceived: number } };
    expect(l.value).toMatchObject({ status: 'ready', samplesReceived: 2 });
  });

  it('a timed-out review whose assembly could not be queued is put back, so the next sweep queues it again', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    const rev = (await t.deps.reviews.latest('10042')) as { ok: true; value: { id: string } };
    const model = { schema: 'threatline.threatmodel.v1' as const, issueKey: 'PAY-7', threats: [{ stride: 'Spoofing' as const, title: 'Forged refund webhooks', scenario: 'An attacker posts a fake refund event.', component: 'webhook endpoint', likelihood: 4, impact: 4, evidence: [{ quote: 'Public webhook that receives refund events' }] }] };
    for (const n of [1, 2]) await t.deps.reviews.saveSample(rev.value.id, n, model);
    t.clock.set('2026-11-15T12:20:00Z');
    const push = t.deps.queue.push;
    t.deps.queue.push = async () => ({ ok: false, error: { code: 'upstream', message: 'queue down' } });
    await sweep(t.deps);
    expect(((await t.deps.reviews.latest('10042')) as { ok: true; value: { status: string } }).value.status).toBe('awaiting_agent');
    t.deps.queue.push = push;
    t.pushed.length = 0;
    await sweep(t.deps);
    expect(t.pushed).toContainEqual({ kind: 'assemble', reviewId: rev.value.id });
  });

  it('leaves a 10-minute-old review alone', async () => {
    const t = coreDeps();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    t.clock.set('2026-11-15T12:10:00Z');
    await sweep(t.deps);
    const l = await t.deps.reviews.latest('10042');
    expect(l.ok && l.value?.status).toBe('awaiting_agent');
  });

  it('queues a migration when the stored schema version is behind', async () => {
    const t = coreDeps();
    await sweep(t.deps);
    expect(t.pushed).toContainEqual({ kind: 'migrate' });
    t.pushed.length = 0;
    t.kv.data.set('schema:version', Math.max(...MIGRATIONS.map((m) => m.version)));
    await sweep(t.deps);
    expect(t.pushed).not.toContainEqual({ kind: 'migrate' });
  });
});

describe('hourly', () => {
  it('feature: when timed-out reviews got no agent run at all, the alert says Automation did not run the agent and how to fix it', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    t.kv.data.set('config:ops', { issueKey: 'OPS-1', accountIds: ['acc-admin'] });
    for (const id of ['1', '2']) {
      await t.deps.reviews.create({
        id: `rev_${id}`, issueId: id, issueKey: `PAY-${id}`, revision: 1, status: 'agent_timeout', contextHash: 'h', riskScore: 0, partial: false,
        promptVersion: 'v', modelIds: [], samplesExpected: 3, samplesReceived: 0, tokensIn: 0, tokensOut: 0, createdAt: '2026-11-15T11:30:00.000Z', updatedAt: '2026-11-15T11:50:00.000Z',
      });
    }
    await hourly(t.deps);
    const text = JSON.stringify(t.jira.commented[0]!.adf);
    expect(text).toContain('2 of them got no agent run at all');
    expect(text).toMatch(/Audit log/);
    expect(text).toMatch(/re-select Threatline in each Use agent step/);
    expect(text).toMatch(/Rule-based checks only/);
  });

  it('security: the alert says when agent runs were refused because their account is not a review author', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    t.kv.data.set('config:ops', { issueKey: 'OPS-1', accountIds: ['acc-admin'] });
    await t.deps.reviews.create({
      id: 'rev_1', issueId: '1', issueKey: 'PAY-1', revision: 1, status: 'agent_timeout', contextHash: 'h', riskScore: 0, partial: false,
      promptVersion: 'v', modelIds: [], samplesExpected: 3, samplesReceived: 0, tokensIn: 0, tokensOut: 0, createdAt: '2026-11-15T11:30:00.000Z', updatedAt: '2026-11-15T11:50:00.000Z',
    });
    t.clock.set('2026-11-15T11:40:00Z');
    await appendLedger(t.deps.ledger, t.deps.clock, 'review.sample_rejected', { issueId: '1', issueKey: 'PAY-1', reason: 'not_review_author' }, 'acc-other');
    t.clock.set('2026-11-15T12:00:00Z');
    await hourly(t.deps);
    expect(JSON.stringify(t.jira.commented[0]!.adf)).toMatch(/1 agent run was refused because the account is not a review author/);
  });


  it('alerts once on the ops issue when more than 20% of the last hour’s reviews failed or timed out', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    t.kv.data.set('config:ops', { issueKey: 'OPS-1', accountIds: ['acc-admin'] });
    for (const id of ['1', '2', '3', '4']) {
      await t.deps.reviews.create({
        id: `rev_${id}`, issueId: id, issueKey: `PAY-${id}`, revision: 1, status: id === '1' ? 'failed' : 'ready', contextHash: 'h', riskScore: 0, partial: false,
        promptVersion: 'v', modelIds: [], samplesExpected: 3, samplesReceived: 3, tokensIn: 0, tokensOut: 0, createdAt: '2026-11-15T11:30:00.000Z', updatedAt: '2026-11-15T11:30:00.000Z',
      });
    }
    await hourly(t.deps);
    await hourly(t.deps);
    expect(t.jira.commented).toHaveLength(1);
    expect(t.jira.commented[0]!.issueId).toBe('OPS-1');
    expect(JSON.stringify(t.jira.commented[0]!.adf)).toContain('acc-admin');
    expect(JSON.stringify(t.jira.commented[0]!.adf)).toContain('1 of 4');
  });

  it('expires overdue acceptances (RL-5) even when no ops issue is configured', async () => {
    const t = coreDeps();
    await appendLedger(t.deps.ledger, t.clock, 'acceptance.requested', { acceptanceId: 'acc_1', requirementId: 'req_1', issueId: '10042', severity: 'High', expiresAt: '2026-11-15T11:00:00.000Z', needsApprover: 'none' }, 'acc-dev');
    await hourly(t.deps);
    const rows = await t.deps.ledger.all();
    expect(rows.ok && rows.value.map((r) => r.eventType)).toEqual(['acceptance.requested', 'acceptance.expired']);
  });

  it('counts reviews settled on only some of their runs (the rest timed out) toward the alert, and says so', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    t.kv.data.set('config:ops', { issueKey: 'OPS-1', accountIds: ['acc-admin'] });
    for (const id of ['1', '2', '3', '4']) {
      await t.deps.reviews.create({
        id: `rev_${id}`, issueId: id, issueKey: `PAY-${id}`, revision: 1, status: 'ready', contextHash: 'h', riskScore: 0, partial: false,
        promptVersion: 'v', modelIds: [], samplesExpected: 3, samplesReceived: id === '1' ? 2 : 3, tokensIn: 0, tokensOut: 0, createdAt: '2026-11-15T11:30:00.000Z', updatedAt: '2026-11-15T11:50:00.000Z',
      });
    }
    await hourly(t.deps);
    const text = JSON.stringify(t.jira.commented[0]!.adf);
    expect(text).toContain('0 of 4 security reviews in the last hour failed or timed out, and 1 more was settled on only some of its runs after the 15-minute agent timeout');
  });

  it('logs the fail-rate alert even when no ops work item is configured (forge logs is the developer\'s only view)', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    await t.deps.reviews.create({
      id: 'rev_1', issueId: '1', issueKey: 'PAY-1', revision: 1, status: 'agent_timeout', contextHash: 'h', riskScore: 0, partial: false,
      promptVersion: 'v', modelIds: [], samplesExpected: 3, samplesReceived: 0, tokensIn: 0, tokensOut: 0, createdAt: '2026-11-15T11:30:00.000Z', updatedAt: '2026-11-15T11:50:00.000Z',
    });
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      await hourly(t.deps);
      const events = spy.mock.calls.map((c) => JSON.parse(String(c[0])) as Record<string, unknown>);
      expect(events).toContainEqual(expect.objectContaining({ event: 'alert.failrate', bad: 1, total: 1, silent: 1, notified: false }));
    } finally {
      spy.mockRestore();
    }
    expect(t.jira.commented).toHaveLength(0);
  });

  it('warns once at 80% of the month\'s review budget, and once more when it is used up and reviews pause', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z', policy: { ...POLICY, budget: { ...POLICY.budget, reviewsPerMonth: 10 } } });
    t.kv.data.set('config:ops', { issueKey: 'OPS-1', accountIds: ['acc-admin'] });
    await t.deps.usage.add('2026-11', { tokensIn: 0, tokensOut: 0, reviews: 7 });
    await hourly(t.deps);
    expect(t.jira.commented).toHaveLength(0);
    await t.deps.usage.add('2026-11', { tokensIn: 0, tokensOut: 0, reviews: 1 });
    await hourly(t.deps);
    await hourly(t.deps);
    expect(t.jira.commented).toHaveLength(1);
    expect(JSON.stringify(t.jira.commented[0]!.adf)).toContain('used 8 of its 10 AI security reviews for 2026-11');
    await t.deps.usage.add('2026-11', { tokensIn: 0, tokensOut: 0, reviews: 2 });
    await hourly(t.deps);
    await hourly(t.deps);
    expect(t.jira.commented).toHaveLength(2);
    expect(JSON.stringify(t.jira.commented[1]!.adf)).toMatch(/used its 10 AI security reviews for 2026-11\. New reviews are paused/);
  });

  it('alerts when Rovo agent reviews are paused because the site looks out of Rovo credits', async () => {
    const t = coreDeps({ now: '2026-11-15T12:00:00Z' });
    t.kv.data.set('config:ops', { issueKey: 'OPS-1', accountIds: ['acc-admin'] });
    t.kv.data.set('ingest:recent', [false, false, false]);
    t.kv.data.set('ingest:recent:at', '2026-11-15T11:00:00.000Z');
    await hourly(t.deps);
    expect(JSON.stringify(t.jira.commented[0]!.adf)).toMatch(/looks out of Rovo credits/);
  });

  it('stays quiet at or below 20%, and without an ops issue', async () => {
    const t = coreDeps();
    await hourly(t.deps);
    expect(t.jira.commented).toHaveLength(0);
  });
});

describe('daily', () => {
  it('purges data older than 400 days and snapshots posture', async () => {
    const t = coreDeps({ now: '2026-11-15T03:00:00Z' });
    await daily(t.deps);
    expect(t.purged).toEqual(['2025-10-11T03:00:00.000Z']);
  });

  it('the SQL purge never touches the ledger and keeps each issue’s latest revision', async () => {
    const x = sqliteExecutor();
    expect((await migrate(x, MIGRATIONS)).ok).toBe(true);
    await x.exec("INSERT INTO ledger (seq, event_type, payload_json, actor, prev_hash, entry_hash, created_at) VALUES (1, 'key.rotated', '{}', 'a', 'p', 'e', '2020-01-01T00:00:00Z')", []);
    await x.exec(
      "INSERT INTO reviews (id, issue_id, issue_key, revision, status, context_hash, risk_score, partial_bundle, prompt_version, model_ids, samples_expected, samples_received, tokens_in, tokens_out, created_at, updated_at) VALUES ('rev_old', '1', 'PAY-1', 1, 'ready', 'h', 0, 0, 'v', '[]', 0, 0, 0, 0, '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')",
      [],
    );
    await x.exec(
      "INSERT INTO reviews (id, issue_id, issue_key, revision, status, context_hash, risk_score, partial_bundle, prompt_version, model_ids, samples_expected, samples_received, tokens_in, tokens_out, created_at, updated_at) VALUES ('rev_latest', '1', 'PAY-1', 2, 'ready', 'h', 0, 0, 'v', '[]', 0, 0, 0, 0, '2020-02-01T00:00:00Z', '2020-02-01T00:00:00Z')",
      [],
    );
    await x.exec("INSERT INTO context_facts (review_id, id, position, source_ari, trust_level, injection_suspected, fact_json) VALUES ('rev_old', 'f', 0, 'a', 'trusted', 0, '{}')", []);
    const r = await sqlRetention(x).purgeBefore('2025-10-11T00:00:00.000Z');
    expect(r).toEqual({ ok: true, value: { reviews: 1 } });
    expect(await x.query('SELECT COUNT(*) AS n FROM ledger', [])).toEqual({ ok: true, value: [{ n: 1 }] });
    expect(await x.query('SELECT COUNT(*) AS n FROM context_facts', [])).toEqual({ ok: true, value: [{ n: 0 }] });
    expect(await x.query('SELECT id FROM reviews', [])).toEqual({ ok: true, value: [{ id: 'rev_latest' }] });
  });
});

describe('purge one project (admin, privacy)', () => {
  const review = (id: string, issueId: string, key: string) =>
    `INSERT INTO reviews (id, issue_id, issue_key, revision, status, context_hash, risk_score, partial_bundle, prompt_version, model_ids, samples_expected, samples_received, tokens_in, tokens_out, created_at, updated_at) VALUES ('${id}', '${issueId}', '${key}', 1, 'ready', 'h', 0, 0, 'v', '[]', 0, 0, 0, 0, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`;
  it('deletes every review, its facts, threats, samples and stages, and the requirements of that project only; keeps the ledger and attestations', async () => {
    const x = sqliteExecutor();
    expect((await migrate(x, MIGRATIONS)).ok).toBe(true);
    await x.exec("INSERT INTO ledger (seq, event_type, payload_json, actor, prev_hash, entry_hash, created_at) VALUES (1, 'key.rotated', '{}', 'a', 'p', 'e', '2020-01-01T00:00:00Z')", []);
    await x.exec("INSERT INTO attestations (id, issue_key, repo, commit_sha, kid, expires_at, nonce) VALUES ('att1', 'OLD-1', 'a/b', 'c', 'k', 'x', 'n')", []);
    for (const [id, issue, key] of [['rev_a', '1', 'OLD-1'], ['rev_b', '2', 'OLD-2'], ['rev_keep', '3', 'PAY-1'], ['rev_lookalike', '4', 'OLDER-1']] as const) await x.exec(review(id, issue, key), []);
    await x.exec("INSERT INTO issues (issue_id, issue_key, project_key) VALUES ('5', 'OLD-5', 'OLD')", []);
    await x.exec("INSERT INTO context_facts (review_id, id, position, source_ari, trust_level, injection_suspected, fact_json) VALUES ('rev_a', 'f', 0, 'a', 'trusted', 0, '{}'), ('rev_keep', 'f', 0, 'a', 'trusted', 0, '{}')", []);
    await x.exec("INSERT INTO threats (id, review_id, position, state, severity, threat_json) VALUES ('t1', 'rev_b', 0, 'accepted', 'High', '{}')", []);
    await x.exec("INSERT INTO requirements (id, issue_id, status, severity, requirement_json) VALUES ('r1', '1', 'Open', 'High', '{}'), ('r5', '5', 'Open', 'High', '{}'), ('r3', '3', 'Open', 'High', '{}')", []);
    const r = await sqlRetention(x).purgeProject('OLD');
    expect(r).toEqual({ ok: true, value: { reviews: 2, requirements: 2 } });
    expect(await x.query('SELECT id FROM reviews ORDER BY id', [])).toEqual({ ok: true, value: [{ id: 'rev_keep' }, { id: 'rev_lookalike' }] });
    expect(await x.query('SELECT review_id FROM context_facts', [])).toEqual({ ok: true, value: [{ review_id: 'rev_keep' }] });
    expect(await x.query('SELECT COUNT(*) AS n FROM threats', [])).toEqual({ ok: true, value: [{ n: 0 }] });
    expect(await x.query('SELECT id FROM requirements', [])).toEqual({ ok: true, value: [{ id: 'r3' }] });
    expect(await x.query('SELECT COUNT(*) AS n FROM ledger', [])).toEqual({ ok: true, value: [{ n: 1 }] });
    expect(await x.query('SELECT COUNT(*) AS n FROM attestations', [])).toEqual({ ok: true, value: [{ n: 1 }] });
  });
});

describe('posture trend (daily snapshots)', () => {
  it('reads open Critical and High per day from the snapshots since a day, oldest first, skipping unreadable rows', async () => {
    const x = sqliteExecutor();
    expect((await migrate(x, MIGRATIONS)).ok).toBe(true);
    await x.exec("INSERT INTO requirements (id, issue_id, status, severity, requirement_json) VALUES ('r1', '1', 'Open', 'Critical', '{}'), ('r2', '1', 'InProgress', 'High', '{}'), ('r3', '1', 'Verified', 'High', '{}'), ('r4', '1', 'Open', 'High', '{}')", []);
    const store = sqlRetention(x);
    expect((await store.snapshotPosture('2026-11-14')).ok).toBe(true);
    await x.exec("INSERT INTO posture_snapshots (day, snapshot_json) VALUES ('2026-11-13', 'not json'), ('2026-10-01', '{}')", []);
    expect(await store.postureTrend('2026-10-16')).toEqual({ ok: true, value: [{ day: '2026-11-14', openCritical: 1, openHigh: 2 }] });
  });
});

describe('rerun rate limit', () => {
  it('allows 10 reruns per account per hour, then refuses', async () => {
    const t = coreDeps();
    for (let i = 0; i < 10; i++) expect((await checkRerunLimit(t.deps, 'acc-1')).ok).toBe(true);
    const eleventh = await checkRerunLimit(t.deps, 'acc-1');
    expect(!eleventh.ok && eleventh.error.code).toBe('budget');
    expect((await checkRerunLimit(t.deps, 'acc-2')).ok).toBe(true);
    t.clock.set('2026-11-15T13:00:00Z');
    expect((await checkRerunLimit(t.deps, 'acc-1')).ok).toBe(true);
  });

  it('is atomic: parallel re-runs cannot all pass the check', async () => {
    const t = coreDeps();
    const got = await Promise.all(Array.from({ length: 25 }, () => checkRerunLimit(t.deps, 'acc-1')));
    expect(got.filter((r) => r.ok).length).toBe(10);
  });
});
