import { ok, RequirementSchema } from '@threatline/shared';
import type { RequirementRepo } from '@threatline/core';
import type { SqlExecutor } from '../executor.js';
import { collect, parseJson } from '../json.js';

export function sqlRequirementRepo(x: SqlExecutor): RequirementRepo {
  return {
    async forIssue(issueId) {
      const r = await x.query<{ requirement_json: string }>('SELECT requirement_json FROM requirements WHERE issue_id = ? ORDER BY id ASC', [issueId]);
      return r.ok ? collect(r.value.map((row) => parseJson(RequirementSchema, row.requirement_json, 'requirements'))) : r;
    },
    async forIssues(issueIds) {
      const ids = [...new Set(issueIds)].slice(0, 100);
      if (ids.length === 0) return ok([]);
      const r = await x.query<{ requirement_json: string }>(`SELECT requirement_json FROM requirements WHERE issue_id IN (${ids.map(() => '?').join(', ')}) ORDER BY issue_id ASC, id ASC`, ids);
      return r.ok ? collect(r.value.map((row) => parseJson(RequirementSchema, row.requirement_json, 'requirements'))) : r;
    },
    async get(id) {
      const r = await x.query<{ requirement_json: string }>('SELECT requirement_json FROM requirements WHERE id = ?', [id]);
      if (!r.ok) return r;
      return r.value[0] ? parseJson(RequirementSchema, r.value[0].requirement_json, 'requirements') : ok(null);
    },
    async upsert(req) {
      const r = await x.exec('REPLACE INTO requirements (id, issue_id, status, severity, requirement_json) VALUES (?, ?, ?, ?, ?)', [req.id, req.issueId, req.status, req.severity, JSON.stringify(req)]);
      return r.ok ? ok(undefined) : r;
    },
    async upsertIf(req, expected) {
      if (expected.length === 0) return ok(false);
      const sql = `UPDATE requirements SET issue_id = ?, status = ?, severity = ?, requirement_json = ? WHERE id = ? AND status IN (${expected.map(() => '?').join(', ')})`;
      const r = await x.exec(sql, [req.issueId, req.status, req.severity, JSON.stringify(req), req.id, ...expected]);
      return r.ok ? ok(r.value.affectedRows > 0) : r;
    },
    async remove(id) {
      const r = await x.exec('DELETE FROM requirements WHERE id = ?', [id]);
      return r.ok ? ok(undefined) : r;
    },
  };
}
