import { appError, err, ok, type SuppressionRule } from '@threatline/shared';
import type { SuppressionRepo } from '../../src/suppressions.js';

const clone = <T>(v: T): T => structuredClone(v);

export function memorySuppressionRepo(): SuppressionRepo & { _rules: Map<string, SuppressionRule> } {
  const rules = new Map<string, SuppressionRule>();
  const matches = new Map<string, { ruleId: string; issueId: string; unhiddenAt?: string }>();
  const key = (ruleId: string, issueId: string) => `${ruleId}|${issueId}`;
  return {
    _rules: rules,
    async create(r) {
      if (rules.has(r.id)) return err(appError('conflict', `suppression ${r.id} exists`));
      rules.set(r.id, clone(r));
      return ok(undefined);
    },
    async get(id) {
      const r = rules.get(id);
      return ok(r ? clone(r) : null);
    },
    async list(statuses, limit) {
      const n = Math.max(0, Math.min(500, Math.floor(limit)));
      return ok([...rules.values()].filter((r) => statuses.includes(r.status)).sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id)).slice(0, n).map(clone));
    },
    async activeFor(projectKey, nowIso) {
      return ok(
        [...rules.values()]
          .filter((r) => r.projectKey === projectKey && r.status === 'active' && r.expiresAt > nowIso)
          .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id))
          .slice(0, 100)
          .map(clone),
      );
    },
    async transition(id, from, to, end) {
      const r = rules.get(id);
      if (!r || r.status !== from) return ok(false);
      rules.set(id, { ...r, status: to, ...(end ? { endedBy: end.by, endedAt: end.at, ...(end.reason ? { endReason: end.reason } : {}) } : {}) });
      return ok(true);
    },
    async recordMatch(ruleId, issueId) {
      if (!matches.has(key(ruleId, issueId))) matches.set(key(ruleId, issueId), { ruleId, issueId });
      return ok(undefined);
    },
    async matchCounts(ruleIds) {
      const out: Record<string, number> = {};
      for (const m of matches.values()) if (ruleIds.includes(m.ruleId)) out[m.ruleId] = (out[m.ruleId] ?? 0) + 1;
      return ok(out);
    },
    async unhide(ruleId, issueId, _issueKey, _by, at) {
      const m = matches.get(key(ruleId, issueId));
      matches.set(key(ruleId, issueId), { ruleId, issueId, unhiddenAt: m?.unhiddenAt ?? at });
      return ok(undefined);
    },
    async unhiddenOn(issueId) {
      return ok([...matches.values()].filter((m) => m.issueId === issueId && m.unhiddenAt).map((m) => m.ruleId).sort());
    },
  };
}
