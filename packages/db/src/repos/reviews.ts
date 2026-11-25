import { z } from 'zod';
import { appError, AgentThreatModelSchema, ContextFactSchema, err, ok, ReviewSchema, ThreatSchema, type Result, type Review, type Threat } from '@threatline/shared';
import type { DiscardedThreat, ReviewRepo, ReviewThreatRow, Sample } from '@threatline/core';
import type { SqlExecutor } from '../executor.js';
import { collect, parseJson } from '../json.js';

type Row = Record<string, unknown>;
const COLS = 'id, issue_id, issue_key, revision, status, context_hash, risk_score, partial_bundle, prompt_version, model_ids, samples_expected, samples_received, tokens_in, tokens_out, failure_reason, created_at, updated_at';

const toReview = (r: Row) => {
  let modelIds: unknown = [];
  try {
    modelIds = JSON.parse(String(r.model_ids));
  } catch {
    /* validated below */
  }
  const parsed = ReviewSchema.safeParse({
    id: r.id, issueId: r.issue_id, issueKey: r.issue_key, revision: Number(r.revision), status: r.status, contextHash: r.context_hash,
    riskScore: Number(r.risk_score), partial: Number(r.partial_bundle) === 1, promptVersion: r.prompt_version, modelIds,
    samplesExpected: Number(r.samples_expected), samplesReceived: Number(r.samples_received), tokensIn: Number(r.tokens_in), tokensOut: Number(r.tokens_out),
    ...(r.failure_reason ? { failureReason: r.failure_reason } : {}), createdAt: r.created_at, updatedAt: r.updated_at,
  });
  return parsed.success ? ok(parsed.data) : err(appError('internal', 'reviews: stored row failed validation'));
};

const values = (v: Review) => [
  v.id, v.issueId, v.issueKey, v.revision, v.status, v.contextHash, Math.round(v.riskScore), v.partial ? 1 : 0, v.promptVersion, JSON.stringify(v.modelIds),
  v.samplesExpected, v.samplesReceived, v.tokensIn, v.tokensOut, v.failureReason ?? null, v.createdAt, v.updatedAt,
];

const DiscardedSchema = z.array(
  z.object({ title: z.string(), stride: z.string().optional(), reason: z.enum(['low_votes', 'unsupported_citation', 'duplicate_of_dismissed', 'schema']) }).strict(),
) as unknown as z.ZodType<DiscardedThreat[]>;
const THREAT_BATCH = 20;
/** Work items per latestThreats query (a review holds up to a few dozen threats). */
const LATEST_THREATS_BATCH = 25;
const THREATS_FOR_BATCH = 50;
const SampleSchema = z.union([AgentThreatModelSchema, z.object({ failed: z.string() }).strict()]) as z.ZodType<Sample>;

export function sqlReviewRepo(x: SqlExecutor): ReviewRepo {
  const one = async (sql: string, params: unknown[]) => {
    const r = await x.query<Row>(sql, params);
    if (!r.ok) return r;
    return r.value[0] ? toReview(r.value[0]) : ok(null);
  };
  const many = async (sql: string, params: unknown[]) => {
    const r = await x.query<Row>(sql, params);
    return r.ok ? collect(r.value.map(toReview)) : r;
  };
  /** The SET clause for the fields in the patch, validated against the stored row. Null when the patch writes nothing. */
  const patchWrite = async (id: string, patch: Partial<Review>): Promise<Result<{ set: string; params: unknown[] } | null>> => {
    const cur = await one(`SELECT ${COLS} FROM reviews WHERE id = ?`, [id]);
    if (!cur.ok) return cur;
    if (!cur.value) return err(appError('not_found', `review ${id}`));
    const next = ReviewSchema.safeParse({ ...cur.value, ...patch });
    if (!next.success) return err(appError('validation', 'invalid review update'));
    const v = values(next.data);
    // Only the fields in the patch are written, so a concurrent addUsage increment is never overwritten by a stale read.
    const cols: Array<[keyof Review, string, unknown]> = [
      ['status', 'status', v[4]], ['contextHash', 'context_hash', v[5]], ['riskScore', 'risk_score', v[6]], ['partial', 'partial_bundle', v[7]],
      ['promptVersion', 'prompt_version', v[8]], ['modelIds', 'model_ids', v[9]], ['samplesExpected', 'samples_expected', v[10]],
      ['samplesReceived', 'samples_received', v[11]], ['tokensIn', 'tokens_in', v[12]], ['tokensOut', 'tokens_out', v[13]],
      ['failureReason', 'failure_reason', v[14]], ['updatedAt', 'updated_at', v[16]],
    ];
    const set = cols.filter(([k]) => k in patch);
    return ok(set.length === 0 ? null : { set: set.map(([, c]) => `${c} = ?`).join(', '), params: set.map(([, , val]) => val) });
  };
  return {
    latest: (issueId) => one(`SELECT ${COLS} FROM reviews WHERE issue_id = ? ORDER BY revision DESC LIMIT 1`, [issueId]),
    get: (id) => one(`SELECT ${COLS} FROM reviews WHERE id = ?`, [id]),
    history: (issueId) => many(`SELECT ${COLS} FROM reviews WHERE issue_id = ? ORDER BY revision ASC`, [issueId]),
    byStatus: (status, createdBefore) =>
      createdBefore
        ? many(`SELECT ${COLS} FROM reviews WHERE status = ? AND created_at < ? ORDER BY created_at ASC LIMIT 200`, [status, createdBefore])
        : many(`SELECT ${COLS} FROM reviews WHERE status = ? ORDER BY updated_at ASC LIMIT 200`, [status]),
    async create(v) {
      const r = await x.exec(`INSERT INTO reviews (${COLS}) VALUES (${COLS.split(',').map(() => '?').join(', ')})`, values(v));
      return r.ok ? ok(v) : r;
    },
    async update(id, patch) {
      const w = await patchWrite(id, patch);
      if (!w.ok) return w;
      if (!w.value) return ok(undefined);
      const r = await x.exec(`UPDATE reviews SET ${w.value.set} WHERE id = ?`, [...w.value.params, id]);
      return r.ok ? ok(undefined) : r;
    },
    async updateWhere(id, expect, patch) {
      const w = await patchWrite(id, patch);
      if (!w.ok) return w.error.code === 'not_found' ? ok(false) : w;
      const cond: Array<[string, unknown]> = [];
      if (expect.status !== undefined) cond.push(['status = ?', expect.status]);
      if (expect.samplesReceivedAtMost !== undefined) cond.push(['samples_received <= ?', expect.samplesReceivedAtMost]);
      const where = `WHERE id = ?${cond.map(([c]) => ` AND ${c}`).join('')}`;
      const params = [id, ...cond.map(([, v]) => v)];
      if (!w.value) {
        const m = await x.query<Row>(`SELECT id FROM reviews ${where}`, params);
        return m.ok ? ok(m.value.length > 0) : m;
      }
      const r = await x.exec(`UPDATE reviews SET ${w.value.set} ${where}`, [...w.value.params, ...params]);
      return r.ok ? ok(r.value.affectedRows > 0) : r;
    },
    updatedSince: (status, since, limit) =>
      many(`SELECT ${COLS} FROM reviews WHERE status = ? AND updated_at >= ? ORDER BY updated_at DESC LIMIT ${Math.max(1, Math.min(500, Math.floor(limit)))}`, [status, since]),
    async reserveUsage(id, est, cap) {
      const i = Math.max(0, Math.round(est.tokensIn));
      const o = Math.max(0, Math.round(est.tokensOut));
      const r = await x.exec('UPDATE reviews SET tokens_in = tokens_in + ?, tokens_out = tokens_out + ? WHERE id = ? AND tokens_in + ? <= ? AND tokens_out + ? <= ?', [i, o, id, i, cap.tokensIn, o, cap.tokensOut]);
      return r.ok ? ok(r.value.affectedRows > 0) : r;
    },
    async addUsage(id, delta) {
      const r = await x.exec('UPDATE reviews SET tokens_in = tokens_in + ?, tokens_out = tokens_out + ? WHERE id = ?', [Math.round(delta.tokensIn), Math.round(delta.tokensOut), id]);
      if (!r.ok) return r;
      if (delta.modelIds.length === 0) return ok(undefined);
      const cur = await one(`SELECT ${COLS} FROM reviews WHERE id = ?`, [id]);
      if (!cur.ok) return cur;
      if (!cur.value) return err(appError('not_found', `review ${id}`));
      const merged = [...new Set([...cur.value.modelIds, ...delta.modelIds])];
      if (merged.length === cur.value.modelIds.length) return ok(undefined);
      const m = await x.exec('UPDATE reviews SET model_ids = ? WHERE id = ?', [JSON.stringify(merged), id]);
      return m.ok ? ok(undefined) : m;
    },
    async saveFacts(reviewId, facts) {
      const d = await x.exec('DELETE FROM context_facts WHERE review_id = ?', [reviewId]);
      if (!d.ok) return d;
      for (const [i, f] of facts.entries()) {
        const r = await x.exec(
          'INSERT INTO context_facts (review_id, id, position, source_ari, trust_level, injection_suspected, fact_json) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [reviewId, f.id, i, f.sourceAri.slice(0, 255), f.trustLevel, f.injectionSuspected ? 1 : 0, JSON.stringify(f)],
        );
        if (!r.ok) return r;
      }
      return ok(undefined);
    },
    async facts(reviewId) {
      const r = await x.query<Row>('SELECT fact_json FROM context_facts WHERE review_id = ? ORDER BY position ASC', [reviewId]);
      return r.ok ? collect(r.value.map((row) => parseJson(ContextFactSchema, row.fact_json, 'context_facts'))) : r;
    },
    async saveThreats(reviewId, threats, discarded) {
      if (new Set(threats.map((t) => t.id)).size !== threats.length) return err(appError('conflict', 'duplicate threat id'));
      // Forge SQL has no multi-statement transactions. Upsert the new set first (one statement per batch), then remove
      // the rows it no longer has: a failure part-way leaves the old set plus some new rows, never a partial set.
      for (let i = 0; i < threats.length; i += THREAT_BATCH) {
        const batch = threats.slice(i, i + THREAT_BATCH);
        const r = await x.exec(
          `REPLACE INTO threats (id, review_id, position, state, severity, threat_json) VALUES ${batch.map(() => '(?, ?, ?, ?, ?, ?)').join(', ')}`,
          batch.flatMap((t, n) => [t.id, reviewId, i + n, t.state, t.severity, JSON.stringify(t)]),
        );
        if (!r.ok) return r;
      }
      const ids = threats.map((t) => t.id);
      const d = await x.exec(`DELETE FROM threats WHERE review_id = ?${ids.length ? ` AND id NOT IN (${ids.map(() => '?').join(', ')})` : ''}`, [reviewId, ...ids]);
      if (!d.ok) return d;
      const r = await x.exec('REPLACE INTO review_discarded (review_id, discarded_json) VALUES (?, ?)', [reviewId, JSON.stringify(discarded)]);
      return r.ok ? ok(undefined) : r;
    },
    async threats(reviewId) {
      const r = await x.query<Row>('SELECT threat_json FROM threats WHERE review_id = ? ORDER BY position ASC', [reviewId]);
      return r.ok ? collect(r.value.map((row) => parseJson(ThreatSchema, row.threat_json, 'threats'))) : r;
    },
    async discarded(reviewId) {
      const r = await x.query<Row>('SELECT discarded_json FROM review_discarded WHERE review_id = ?', [reviewId]);
      if (!r.ok) return r;
      return r.value[0] ? parseJson(DiscardedSchema, r.value[0].discarded_json, 'review_discarded') : ok([]);
    },
    async updateThreat(id, patch) {
      const r = await x.query<Row>('SELECT threat_json FROM threats WHERE id = ?', [id]);
      if (!r.ok) return r;
      if (!r.value[0]) return err(appError('not_found', `threat ${id}`));
      const cur = parseJson(ThreatSchema, r.value[0].threat_json, 'threats');
      if (!cur.ok) return cur;
      const next = ThreatSchema.safeParse({ ...cur.value, ...patch });
      if (!next.success) return err(appError('validation', 'invalid threat update'));
      const u = await x.exec('UPDATE threats SET state = ?, severity = ?, threat_json = ? WHERE id = ?', [next.data.state, next.data.severity, JSON.stringify(next.data), id]);
      return u.ok ? ok(undefined) : u;
    },
    async saveSample(reviewId, n, sample) {
      // INSERT, not REPLACE: a run number is taken once, so two runs saved at the same moment cannot overwrite each other.
      const r = await x.exec('INSERT INTO agent_samples (review_id, n, sample_json) VALUES (?, ?, ?)', [reviewId, n, JSON.stringify(sample)]);
      return r.ok ? ok(undefined) : r;
    },
    async samples(reviewId) {
      const r = await x.query<Row>('SELECT sample_json FROM agent_samples WHERE review_id = ? ORDER BY n ASC', [reviewId]);
      return r.ok ? collect(r.value.map((row) => parseJson(SampleSchema, row.sample_json, 'agent_samples'))) : r;
    },
    async saveStage(reviewId, stage, status, checkpoint, error, at) {
      const r = await x.exec('REPLACE INTO review_stages (review_id, stage, status, checkpoint_json, error, updated_at) VALUES (?, ?, ?, ?, ?, ?)', [
        reviewId, stage, status, checkpoint === undefined ? null : JSON.stringify(checkpoint), error ?? null, at ?? new Date().toISOString(),
      ]);
      return r.ok ? ok(undefined) : r;
    },
    async stage(reviewId, stage) {
      const r = await x.query<Row>('SELECT status, checkpoint_json FROM review_stages WHERE review_id = ? AND stage = ?', [reviewId, stage]);
      if (!r.ok) return r;
      const row = r.value[0];
      if (!row) return ok(null);
      let checkpoint: unknown;
      try {
        checkpoint = row.checkpoint_json == null ? undefined : JSON.parse(String(row.checkpoint_json));
      } catch {
        return err(appError('internal', 'review_stages: checkpoint is not JSON'));
      }
      return ok({ status: String(row.status), ...(checkpoint === undefined ? {} : { checkpoint }) });
    },
    recent: (limit, since) => {
      const n = Math.max(1, Math.min(500, Math.floor(limit)));
      return since
        ? many(`SELECT ${COLS} FROM reviews WHERE created_at >= ? ORDER BY created_at DESC LIMIT ${n}`, [since])
        : many(`SELECT ${COLS} FROM reviews ORDER BY created_at DESC LIMIT ${n}`, []);
    },
    async needsHuman(limit) {
      // Indexed on threats (state, severity); the latest-revision check uses the (issue_id, revision) unique index.
      const n = Math.max(1, Math.min(500, Math.floor(limit)));
      const r = await x.query<Row>(
        `SELECT t.threat_json, ${COLS.split(', ').map((c) => `r.${c}`).join(', ')} FROM threats t JOIN reviews r ON r.id = t.review_id
         WHERE t.state = 'needs_human' AND r.revision = (SELECT MAX(r2.revision) FROM reviews r2 WHERE r2.issue_id = r.issue_id)
         ORDER BY CASE t.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END ASC, r.created_at ASC, t.id ASC
         LIMIT ${n}`,
        [],
      );
      if (!r.ok) return r;
      const out: ReviewThreatRow[] = [];
      for (const row of r.value) {
        const threat = parseJson(ThreatSchema, row.threat_json, 'threats');
        if (!threat.ok) return threat;
        const review = toReview(row);
        if (!review.ok) return review;
        out.push({ threat: threat.value, review: review.value });
      }
      return ok(out);
    },
    async latestThreats(issueIds) {
      // Bounded: a few work items per query, so no single result carries hundreds of threats' JSON.
      const ids = [...new Set(issueIds)];
      const out: ReviewThreatRow[] = [];
      for (let i = 0; i < ids.length; i += LATEST_THREATS_BATCH) {
        const chunk = ids.slice(i, i + LATEST_THREATS_BATCH);
        const r = await x.query<Row>(
          `SELECT t.threat_json, ${COLS.split(', ').map((c) => `r.${c}`).join(', ')} FROM reviews r JOIN threats t ON t.review_id = r.id
           WHERE r.issue_id IN (${chunk.map(() => '?').join(', ')}) AND r.revision = (SELECT MAX(r2.revision) FROM reviews r2 WHERE r2.issue_id = r.issue_id)
           ORDER BY t.position ASC`,
          chunk,
        );
        if (!r.ok) return r;
        const byIssue = new Map<string, ReviewThreatRow[]>();
        for (const row of r.value) {
          const threat = parseJson(ThreatSchema, row.threat_json, 'threats');
          if (!threat.ok) return threat;
          const review = toReview(row);
          if (!review.ok) return review;
          const list = byIssue.get(review.value.issueId) ?? [];
          list.push({ threat: threat.value, review: review.value });
          byIssue.set(review.value.issueId, list);
        }
        for (const id of chunk) out.push(...(byIssue.get(id) ?? []));
      }
      return ok(out);
    },
    async threatsFor(reviewIds, states, limit) {
      const n = Math.max(1, Math.min(2000, Math.floor(limit)));
      const ids = [...new Set(reviewIds)].slice(0, 200);
      const wanted = [...new Set(states)];
      if (ids.length === 0 || wanted.length === 0) return ok([]);
      const out: Threat[] = [];
      // Batches in the given order (most recent review first), so the cap keeps the newest reviews' threats.
      for (let i = 0; i < ids.length && out.length < n; i += THREATS_FOR_BATCH) {
        const batch = ids.slice(i, i + THREATS_FOR_BATCH);
        // Portable "in the order given" (no FIELD() in SQLite): a CASE over the batch's ids.
        const order = `CASE review_id ${batch.map((_, k) => `WHEN ? THEN ${k}`).join(' ')} END`;
        const r = await x.query<Row>(
          `SELECT threat_json FROM threats WHERE review_id IN (${batch.map(() => '?').join(', ')}) AND state IN (${wanted.map(() => '?').join(', ')}) ORDER BY ${order} ASC, position ASC LIMIT ${n - out.length}`,
          [...batch, ...wanted, ...batch],
        );
        if (!r.ok) return r;
        for (const row of r.value) {
          const t = parseJson(ThreatSchema, row.threat_json, 'threats');
          if (!t.ok) return t;
          out.push(t.value);
        }
      }
      return ok(out.slice(0, n));
    },
    async stages(reviewId) {
      const r = await x.query<Row>('SELECT stage, status, error, updated_at FROM review_stages WHERE review_id = ? ORDER BY updated_at ASC, stage ASC', [reviewId]);
      if (!r.ok) return r;
      return ok(r.value.map((row) => ({ stage: String(row.stage), status: String(row.status), ...(row.error ? { error: String(row.error) } : {}), at: String(row.updated_at) })));
    },
  };
}
