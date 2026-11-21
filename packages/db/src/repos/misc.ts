import { appError, DismissReasonSchema, err, ok, StrideSchema, type DismissReason, type Stride } from '@threatline/shared';
import type { AttestationRepo, DismissalRow, FeedbackRepo, IssueRepo, TreeHead, TreeHeadRepo, UsageRepo } from '@threatline/core';
import type { SqlExecutor } from '../executor.js';

export function sqlFeedbackRepo(x: SqlExecutor): FeedbackRepo {
  return {
    async dismissedFor(component) {
      const r = await x.query<{ title: string; stride: string; reason: string | null }>(
        "SELECT title, stride, reason FROM feedback WHERE component = ? AND action = 'dismiss' AND reason IS NOT NULL ORDER BY id ASC",
        [component],
      );
      if (!r.ok) return r;
      const out: Array<{ title: string; stride: Stride; reason: DismissReason }> = [];
      for (const row of r.value) {
        const s = StrideSchema.safeParse(row.stride);
        const d = DismissReasonSchema.safeParse(row.reason);
        if (s.success && d.success) out.push({ title: row.title, stride: s.data, reason: d.data });
      }
      return ok(out);
    },
    async record(f) {
      const r = await x.exec('INSERT INTO feedback (threat_id, component, title, stride, actor, action, reason, note, issue_id, issue_key, project_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
        f.threatId, f.component.slice(0, 255), f.title.slice(0, 255), f.stride, f.actor, f.action, f.reason ?? null, f.note?.slice(0, 2000) ?? null,
        f.issueId ?? null, f.issueKey ?? null, f.projectKey ?? null, f.at ?? null,
      ]);
      return r.ok ? ok(undefined) : r;
    },
    async dismissalsSince(sinceIso, limit) {
      type Row = { threat_id: string; component: string; title: string; stride: string; actor: string; reason: string; issue_id: string; issue_key: string; project_key: string; created_at: string };
      const n = Math.max(0, Math.min(2000, Math.floor(limit)));
      const r = await x.query<Row>(
        `SELECT threat_id, component, title, stride, actor, reason, issue_id, issue_key, project_key, created_at FROM feedback
         WHERE action = 'dismiss' AND created_at >= ? AND reason IS NOT NULL AND issue_id IS NOT NULL AND issue_key IS NOT NULL AND project_key IS NOT NULL
         ORDER BY created_at DESC, id DESC LIMIT ${n}`,
        [sinceIso],
      );
      if (!r.ok) return r;
      const out: DismissalRow[] = [];
      for (const row of r.value) {
        const s = StrideSchema.safeParse(row.stride);
        const d = DismissReasonSchema.safeParse(row.reason);
        if (s.success && d.success)
          out.push({ threatId: row.threat_id, component: row.component, title: row.title, stride: s.data, actor: row.actor, reason: d.data, issueId: row.issue_id, issueKey: row.issue_key, projectKey: row.project_key, at: row.created_at });
      }
      return ok(out);
    },
  };
}

export function sqlIssueRepo(x: SqlExecutor): IssueRepo {
  type Row = { issue_id: string; issue_key: string; project_key: string; parent_id: string | null };
  const map = (r: Row) => ({ issueId: r.issue_id, issueKey: r.issue_key, projectKey: r.project_key, ...(r.parent_id ? { parentId: r.parent_id } : {}) });
  return {
    async upsert(i) {
      const r = await x.exec('REPLACE INTO issues (issue_id, issue_key, project_key, parent_id) VALUES (?, ?, ?, ?)', [i.issueId, i.issueKey, i.projectKey, i.parentId ?? null]);
      return r.ok ? ok(undefined) : r;
    },
    async get(issueId) {
      const r = await x.query<Row>('SELECT issue_id, issue_key, project_key, parent_id FROM issues WHERE issue_id = ?', [issueId]);
      return r.ok ? ok(r.value[0] ? map(r.value[0]) : null) : r;
    },
    async byKey(issueKey) {
      const r = await x.query<Row>('SELECT issue_id, issue_key, project_key, parent_id FROM issues WHERE issue_key = ?', [issueKey]);
      return r.ok ? ok(r.value[0] ? map(r.value[0]) : null) : r;
    },
    async children(issueId) {
      const r = await x.query<Row>('SELECT issue_id, issue_key, project_key, parent_id FROM issues WHERE parent_id = ? ORDER BY issue_key ASC', [issueId]);
      return r.ok ? ok(r.value.map(map)) : r;
    },
    async linkPage(issueId, pageId) {
      const r = await x.exec('REPLACE INTO issue_pages (page_id, issue_id) VALUES (?, ?)', [pageId, issueId]);
      return r.ok ? ok(undefined) : r;
    },
    async issuesForPage(pageId) {
      const r = await x.query<{ issue_id: string }>('SELECT issue_id FROM issue_pages WHERE page_id = ?', [pageId]);
      return r.ok ? ok(r.value.map((v) => v.issue_id)) : r;
    },
  };
}

export function sqlAttestationRepo(x: SqlExecutor): AttestationRepo {
  return {
    async record(a) {
      const r = await x.exec('INSERT INTO attestations (id, issue_key, repo, commit_sha, kid, expires_at, nonce) VALUES (?, ?, ?, ?, ?, ?, ?)', [a.id, a.issueKey, a.repo, a.commitSha, a.kid, a.expiresAt, a.nonce]);
      return r.ok ? ok(undefined) : r;
    },
    async forIssue(issueKey) {
      const r = await x.query<{ id: string; issue_key: string; repo: string; commit_sha: string; kid: string; expires_at: string; nonce: string }>(
        'SELECT id, issue_key, repo, commit_sha, kid, expires_at, nonce FROM attestations WHERE issue_key = ? ORDER BY expires_at DESC',
        [issueKey],
      );
      return r.ok ? ok(r.value.map((v) => ({ id: v.id, issueKey: v.issue_key, repo: v.repo, commitSha: v.commit_sha, kid: v.kid, expiresAt: v.expires_at, nonce: v.nonce }))) : r;
    },
  };
}

export function sqlUsageRepo(x: SqlExecutor): UsageRepo {
  return {
    async add(month, d) {
      for (let attempt = 0; attempt < 3; attempt++) {
        const u = await x.exec('UPDATE usage_monthly SET tokens_in = tokens_in + ?, tokens_out = tokens_out + ?, reviews = reviews + ? WHERE month = ?', [d.tokensIn, d.tokensOut, d.reviews, month]);
        if (!u.ok) return u;
        if (u.value.affectedRows > 0) return ok(undefined);
        const i = await x.exec('INSERT INTO usage_monthly (month, tokens_in, tokens_out, reviews) VALUES (?, ?, ?, ?)', [month, d.tokensIn, d.tokensOut, d.reviews]);
        if (i.ok) return ok(undefined);
        if (i.error.code !== 'conflict') return i;
      }
      return ok(undefined);
    },
    async get(month) {
      const r = await x.query<{ tokens_in: number; tokens_out: number; reviews: number }>('SELECT tokens_in, tokens_out, reviews FROM usage_monthly WHERE month = ?', [month]);
      if (!r.ok) return r;
      const v = r.value[0];
      return ok(v ? { tokensIn: Number(v.tokens_in), tokensOut: Number(v.tokens_out), reviews: Number(v.reviews) } : { tokensIn: 0, tokensOut: 0, reviews: 0 });
    },
    async takeSlot(bucket, window, limit) {
      // One row per bucket. The conditional UPDATE is the check and the increment in one statement, so parallel callers
      // cannot all pass; `used` is assigned before `win`, so it sees the old window under MySQL and SQLite alike.
      const take = () =>
        x.exec('UPDATE rate_limits SET used = CASE WHEN win = ? THEN used + 1 ELSE 1 END, win = ? WHERE bucket = ? AND (win <> ? OR used < ?)', [window, window, bucket, window, limit]);
      const used = async () => {
        const r = await x.query<{ used: number }>('SELECT used FROM rate_limits WHERE bucket = ?', [bucket]);
        return r.ok ? ok(Math.min(limit, Number(r.value[0]?.used ?? 1))) : r;
      };
      if (limit <= 0) return ok(null);
      const u = await take();
      if (!u.ok) return u;
      if (u.value.affectedRows > 0) return used();
      const i = await x.exec('INSERT INTO rate_limits (bucket, win, used) VALUES (?, ?, 1)', [bucket, window]);
      if (i.ok) return ok(1);
      if (i.error.code !== 'conflict') return i;
      // Someone else created the row first: take from it, or it is already full.
      const again = await take();
      if (!again.ok) return again;
      return again.value.affectedRows > 0 ? used() : ok(null);
    },
    async reserveReview(month, cap) {
      // Increment-then-check in one conditional UPDATE, so parallel gathers at cap - 1 cannot all pass.
      for (let attempt = 0; attempt < 3; attempt++) {
        const u = await x.exec('UPDATE usage_monthly SET reviews = reviews + 1 WHERE month = ? AND reviews + 1 <= ?', [month, cap]);
        if (!u.ok) return u;
        if (u.value.affectedRows > 0) return ok(true);
        const g = await x.query<{ reviews: number }>('SELECT reviews FROM usage_monthly WHERE month = ?', [month]);
        if (!g.ok) return g;
        if (g.value[0] || cap < 1) return ok(false);
        const i = await x.exec('INSERT INTO usage_monthly (month, tokens_in, tokens_out, reviews) VALUES (?, 0, 0, 1)', [month]);
        if (i.ok) return ok(true);
        if (i.error.code !== 'conflict') return i;
      }
      return ok(false);
    },
  };
}

type HeadRow = { tree_size: number; root_hash: string; kid: string; signature: string; published_page_id: string | null; created_at: string };
const HEAD_COLS = 'tree_size, root_hash, kid, signature, published_page_id, created_at';
const toHead = (v: HeadRow): TreeHead => ({
  treeSize: Number(v.tree_size), rootHash: v.root_hash, timestamp: v.created_at, kid: v.kid, signature: v.signature, ...(v.published_page_id ? { publishedPageId: v.published_page_id } : {}),
});

export function sqlTreeHeadRepo(x: SqlExecutor): TreeHeadRepo {
  const many = async (sql: string, params: unknown[]) => {
    const r = await x.query<HeadRow>(sql, params);
    return r.ok ? ok(r.value.map(toHead)) : r;
  };
  return {
    async add(h) {
      const r = await x.exec(`INSERT INTO merkle_heads (${HEAD_COLS}) VALUES (?, ?, ?, ?, ?, ?)`, [h.treeSize, h.rootHash, h.kid, h.signature, h.publishedPageId ?? null, h.timestamp]);
      return r.ok ? ok(undefined) : r;
    },
    async latest() {
      const r = await many(`SELECT ${HEAD_COLS} FROM merkle_heads ORDER BY tree_size DESC LIMIT 1`, []);
      return r.ok ? ok(r.value[0] ?? null) : r;
    },
    async lastPublished() {
      const r = await many(`SELECT ${HEAD_COLS} FROM merkle_heads WHERE published_page_id IS NOT NULL ORDER BY tree_size DESC LIMIT 1`, []);
      return r.ok ? ok(r.value[0] ?? null) : r;
    },
    list: (limit) => many(`SELECT ${HEAD_COLS} FROM merkle_heads ORDER BY tree_size DESC LIMIT ${Math.max(0, Math.min(1000, Math.floor(limit)))}`, []),
    async markPublished(treeSize, pageId) {
      const r = await x.exec('UPDATE merkle_heads SET published_page_id = ? WHERE tree_size = ?', [pageId, treeSize]);
      if (!r.ok) return r;
      return r.value.affectedRows > 0 ? ok(undefined) : err(appError('not_found', `tree head ${treeSize}`));
    },
  };
}
