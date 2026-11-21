import { appError, err, ok, SuppressionRuleSchema, SuppressionStatusSchema, type Result, type SuppressionRule } from '@threatline/shared';
import type { SuppressionRepo } from '@threatline/core';
import type { SqlExecutor } from '../executor.js';
import { parseJson } from '../json.js';

/** The fields a rule is created with; status and who ended it live in their own columns. */
const ImmutableSchema = SuppressionRuleSchema.omit({ status: true, endedBy: true, endedAt: true, endReason: true });
type Row = { status: string; ended_by: string | null; ended_at: string | null; end_reason: string | null; rule_json: string };
const COLS = 'status, ended_by, ended_at, end_reason, rule_json';

function toRule(row: Row): Result<SuppressionRule> {
  const base = parseJson(ImmutableSchema, row.rule_json, 'suppression_rules');
  if (!base.ok) return base;
  const status = SuppressionStatusSchema.safeParse(row.status);
  if (!status.success) return err(appError('internal', 'suppression_rules: stored row failed validation'));
  return ok({
    ...base.value,
    status: status.data,
    ...(row.ended_by ? { endedBy: row.ended_by } : {}),
    ...(row.ended_at ? { endedAt: row.ended_at } : {}),
    ...(row.end_reason ? { endReason: row.end_reason } : {}),
  });
}

function many(rows: Row[]): Result<SuppressionRule[]> {
  const out: SuppressionRule[] = [];
  for (const row of rows) {
    const r = toRule(row);
    if (!r.ok) return r;
    out.push(r.value);
  }
  return ok(out);
}

const marks = (n: number) => Array.from({ length: n }, () => '?').join(', ');

export function sqlSuppressionRepo(x: SqlExecutor): SuppressionRepo {
  return {
    async create(rule) {
      const { status, endedBy: _b, endedAt: _a, endReason: _r, ...immutable } = rule;
      const r = await x.exec('INSERT INTO suppression_rules (id, project_key, status, created_at, expires_at, rule_json) VALUES (?, ?, ?, ?, ?, ?)', [
        rule.id, rule.projectKey, status, rule.createdAt, rule.expiresAt, JSON.stringify(immutable),
      ]);
      return r.ok ? ok(undefined) : r;
    },
    async get(id) {
      const r = await x.query<Row>(`SELECT ${COLS} FROM suppression_rules WHERE id = ?`, [id]);
      if (!r.ok) return r;
      return r.value[0] ? toRule(r.value[0]) : ok(null);
    },
    async list(statuses, limit) {
      if (statuses.length === 0) return ok([]);
      const n = Math.max(0, Math.min(500, Math.floor(limit)));
      const r = await x.query<Row>(`SELECT ${COLS} FROM suppression_rules WHERE status IN (${marks(statuses.length)}) ORDER BY created_at DESC, id DESC LIMIT ${n}`, [...statuses]);
      return r.ok ? many(r.value) : r;
    },
    async activeFor(projectKey, nowIso) {
      const r = await x.query<Row>(`SELECT ${COLS} FROM suppression_rules WHERE project_key = ? AND status = 'active' AND expires_at > ? ORDER BY created_at ASC, id ASC LIMIT 100`, [projectKey, nowIso]);
      return r.ok ? many(r.value) : r;
    },
    async transition(id, from, to, end) {
      const r = await x.exec('UPDATE suppression_rules SET status = ?, ended_by = ?, ended_at = ?, end_reason = ? WHERE id = ? AND status = ?', [
        to, end?.by ?? null, end?.at ?? null, end?.reason?.slice(0, 300) ?? null, id, from,
      ]);
      return r.ok ? ok(r.value.affectedRows > 0) : r;
    },
    async recordMatch(ruleId, issueId, issueKey, at) {
      const r = await x.exec('INSERT INTO suppression_matches (rule_id, issue_id, issue_key, matched_at) VALUES (?, ?, ?, ?)', [ruleId, issueId, issueKey, at]);
      return r.ok || r.error.code === 'conflict' ? ok(undefined) : r;
    },
    async matchCounts(ruleIds) {
      if (ruleIds.length === 0) return ok({});
      const r = await x.query<{ rule_id: string; n: number | string }>(`SELECT rule_id, COUNT(*) AS n FROM suppression_matches WHERE rule_id IN (${marks(ruleIds.length)}) GROUP BY rule_id`, [...ruleIds]);
      if (!r.ok) return r;
      return ok(Object.fromEntries(r.value.map((v) => [v.rule_id, Number(v.n)])));
    },
    async unhide(ruleId, issueId, issueKey, by, at) {
      const u = await x.exec('UPDATE suppression_matches SET unhidden_by = ?, unhidden_at = ? WHERE rule_id = ? AND issue_id = ? AND unhidden_at IS NULL', [by, at, ruleId, issueId]);
      if (!u.ok) return u;
      if (u.value.affectedRows > 0) return ok(undefined);
      const i = await x.exec('INSERT INTO suppression_matches (rule_id, issue_id, issue_key, matched_at, unhidden_by, unhidden_at) VALUES (?, ?, ?, ?, ?, ?)', [ruleId, issueId, issueKey, at, by, at]);
      // A conflict: the row exists (already unhidden, or written in between); unhide it once more to be sure.
      if (i.ok) return ok(undefined);
      if (i.error.code !== 'conflict') return i;
      const again = await x.exec('UPDATE suppression_matches SET unhidden_by = ?, unhidden_at = ? WHERE rule_id = ? AND issue_id = ? AND unhidden_at IS NULL', [by, at, ruleId, issueId]);
      return again.ok ? ok(undefined) : again;
    },
    async unhiddenOn(issueId) {
      const r = await x.query<{ rule_id: string }>('SELECT rule_id FROM suppression_matches WHERE issue_id = ? AND unhidden_at IS NOT NULL ORDER BY rule_id ASC', [issueId]);
      return r.ok ? ok(r.value.map((v) => v.rule_id)) : r;
    },
  };
}
