import { describe, expect, it } from 'vitest';
import { suppressionContract } from '../../core/test/contracts/suppressions.contract.js';
import { MIGRATIONS, migrate, sqlFeedbackRepo, sqlSuppressionRepo } from '../src/index.js';
import { sqliteExecutor } from './sqlite-executor.js';

const fresh = async () => {
  const x = sqliteExecutor();
  const m = await migrate(x, MIGRATIONS);
  if (!m.ok) throw new Error(JSON.stringify(m.error));
  return x;
};

suppressionContract('sql', { suppressions: async () => sqlSuppressionRepo(await fresh()), feedback: async () => sqlFeedbackRepo(await fresh()) });

describe('migration v7 (suppression rules)', () => {
  it('upgrades a database at v5 in place: feedback rows written before it keep working and feed no suggestion', async () => {
    const x = sqliteExecutor();
    expect((await migrate(x, MIGRATIONS.filter((m) => m.version <= 5))).ok).toBe(true);
    await x.exec("INSERT INTO feedback (threat_id, component, title, stride, actor, action, reason) VALUES ('t0', 'c', 'Old', 'Spoofing', 'a', 'dismiss', 'false_positive')", []);
    const up = await migrate(x, MIGRATIONS);
    expect(up.ok && up.value).toEqual({ from: 5, to: 7 });
    const fb = sqlFeedbackRepo(x);
    expect(await fb.dismissedFor('c')).toEqual({ ok: true, value: [{ title: 'Old', stride: 'Spoofing', reason: 'false_positive' }] });
    expect(await fb.dismissalsSince('2000-01-01T00:00:00.000Z', 10)).toEqual({ ok: true, value: [] });
  });

  it('a stored rule with an unknown status is an error, never a silently wrong rule', async () => {
    const x = await fresh();
    const s = sqlSuppressionRepo(x);
    await x.exec("INSERT INTO suppression_rules (id, project_key, status, created_at, expires_at, rule_json) VALUES ('sup_x', 'PAY', 'weird', 'a', 'b', '{}')", []);
    const r = await s.get('sup_x');
    expect(r.ok).toBe(false);
  });
});
