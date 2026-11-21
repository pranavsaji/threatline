import { appError, err, ok, severityRank, type ContextFact, type Requirement, type Review, type Threat } from '@threatline/shared';
import type {
  AttestationRepo,
  AttestationRow,
  DiscardedThreat,
  DismissalRow,
  FeedbackRepo,
  FeedbackRow,
  IssueRepo,
  IssueRow,
  LedgerRepo,
  LedgerRow,
  RequirementRepo,
  ReviewRepo,
  TreeHead,
  TreeHeadRepo,
  Sample,
  UsageRepo,
  VerdictSink,
} from '../../src/ports.js';

const clone = <T>(v: T): T => structuredClone(v);

export function memoryReviewRepo(): ReviewRepo & { _reviews: Map<string, Review> } {
  const reviews = new Map<string, Review>();
  const facts = new Map<string, ContextFact[]>();
  const threats = new Map<string, Threat[]>();
  const discarded = new Map<string, DiscardedThreat[]>();
  const samples = new Map<string, Map<number, Sample>>();
  const stages = new Map<string, { status: string; checkpoint?: unknown; error?: string; at: string }>();
  return {
    _reviews: reviews,
    async latest(issueId) {
      const list = [...reviews.values()].filter((r) => r.issueId === issueId).sort((a, b) => b.revision - a.revision);
      return ok(list[0] ? clone(list[0]) : null);
    },
    async get(id) {
      const r = reviews.get(id);
      return ok(r ? clone(r) : null);
    },
    async history(issueId) {
      return ok([...reviews.values()].filter((r) => r.issueId === issueId).sort((a, b) => a.revision - b.revision).map(clone));
    },
    async byStatus(status, olderThan) {
      // Like SQL: oldest first, at most 200.
      const list = [...reviews.values()].filter((r) => r.status === status && (!olderThan || r.updatedAt < olderThan)).sort((a, b) => a.updatedAt.localeCompare(b.updatedAt));
      return ok(list.slice(0, 200).map(clone));
    },
    async create(r) {
      if (reviews.has(r.id)) return err(appError('conflict', `review ${r.id} exists`));
      reviews.set(r.id, clone(r));
      return ok(clone(r));
    },
    async update(id, patch) {
      const r = reviews.get(id);
      if (!r) return err(appError('not_found', `review ${id}`));
      reviews.set(id, { ...r, ...clone(patch) });
      return ok(undefined);
    },
    async updateWhere(id, expect, patch) {
      const r = reviews.get(id);
      if (!r) return ok(false);
      if (expect.status !== undefined && r.status !== expect.status) return ok(false);
      if (expect.samplesReceivedAtMost !== undefined && r.samplesReceived > expect.samplesReceivedAtMost) return ok(false);
      reviews.set(id, { ...r, ...clone(patch) });
      return ok(true);
    },
    async updatedSince(status, since, limit) {
      const n = Math.max(1, Math.min(500, Math.floor(limit)));
      const list = [...reviews.values()].filter((r) => r.status === status && r.updatedAt >= since).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
      return ok(list.slice(0, n).map(clone));
    },
    async reserveUsage(id, est, cap) {
      const r = reviews.get(id);
      if (!r) return err(appError('not_found', `review ${id}`));
      if (r.tokensIn + est.tokensIn > cap.tokensIn || r.tokensOut + est.tokensOut > cap.tokensOut) return ok(false);
      reviews.set(id, { ...r, tokensIn: r.tokensIn + est.tokensIn, tokensOut: r.tokensOut + est.tokensOut });
      return ok(true);
    },
    async addUsage(id, delta) {
      const r = reviews.get(id);
      if (!r) return err(appError('not_found', `review ${id}`));
      reviews.set(id, { ...r, tokensIn: r.tokensIn + delta.tokensIn, tokensOut: r.tokensOut + delta.tokensOut, modelIds: [...new Set([...r.modelIds, ...delta.modelIds])] });
      return ok(undefined);
    },
    async saveFacts(reviewId, f) {
      facts.set(reviewId, clone(f));
      return ok(undefined);
    },
    async facts(reviewId) {
      return ok(clone(facts.get(reviewId) ?? []));
    },
    async saveThreats(reviewId, t, d) {
      // Like the SQL primary key: threat ids are unique, and a refused save writes nothing.
      if (new Set(t.map((x) => x.id)).size !== t.length) return err(appError('conflict', 'duplicate threat id'));
      threats.set(reviewId, clone(t));
      discarded.set(reviewId, clone(d));
      return ok(undefined);
    },
    async threats(reviewId) {
      return ok(clone(threats.get(reviewId) ?? []));
    },
    async discarded(reviewId) {
      return ok(clone(discarded.get(reviewId) ?? []));
    },
    async updateThreat(id, patch) {
      for (const [rid, list] of threats) {
        const i = list.findIndex((t) => t.id === id);
        if (i >= 0) {
          list[i] = { ...list[i]!, ...clone(patch) };
          threats.set(rid, list);
          return ok(undefined);
        }
      }
      return err(appError('not_found', `threat ${id}`));
    },
    async saveSample(reviewId, n, sample) {
      const m = samples.get(reviewId) ?? new Map<number, Sample>();
      if (m.has(n)) return err(appError('conflict', `sample ${n} already saved`));
      m.set(n, clone(sample));
      samples.set(reviewId, m);
      return ok(undefined);
    },
    async samples(reviewId) {
      const m = samples.get(reviewId);
      return ok(m ? [...m.entries()].sort((a, b) => a[0] - b[0]).map(([, s]) => clone(s)) : []);
    },
    async saveStage(reviewId, stage, status, checkpoint, error, at) {
      stages.set(`${reviewId}:${stage}`, { status, checkpoint: clone(checkpoint), ...(error ? { error } : {}), at: at ?? new Date().toISOString() });
      return ok(undefined);
    },
    async stage(reviewId, stage) {
      const s = stages.get(`${reviewId}:${stage}`);
      if (!s) return ok(null);
      const { at: _at, ...rest } = clone(s);
      return ok(rest);
    },
    async recent(limit, since) {
      const n = Math.max(1, Math.min(500, Math.floor(limit)));
      const list = [...reviews.values()].filter((r) => !since || r.createdAt >= since).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return ok(list.slice(0, n).map(clone));
    },
    async stages(reviewId) {
      const list = [...stages.entries()]
        .filter(([k]) => k.startsWith(`${reviewId}:`))
        .map(([k, v]) => ({ stage: k.slice(reviewId.length + 1), status: v.status, ...(v.error ? { error: v.error } : {}), at: v.at }))
        .sort((a, b) => a.at.localeCompare(b.at) || a.stage.localeCompare(b.stage));
      return ok(list);
    },
    async needsHuman(limit) {
      // Like SQL: latest revision per work item only, most severe first, then oldest review, then threat id.
      const n = Math.max(1, Math.min(500, Math.floor(limit)));
      const latest = new Map<string, Review>();
      for (const r of reviews.values()) if ((latest.get(r.issueId)?.revision ?? -1) < r.revision) latest.set(r.issueId, r);
      const rows = [...latest.values()].flatMap((r) => (threats.get(r.id) ?? []).filter((t) => t.state === 'needs_human').map((t) => ({ threat: clone(t), review: clone(r) })));
      rows.sort((a, b) => severityRank(b.threat.severity) - severityRank(a.threat.severity) || a.review.createdAt.localeCompare(b.review.createdAt) || a.threat.id.localeCompare(b.threat.id));
      return ok(rows.slice(0, n));
    },
  };
}

export function memoryRequirementRepo(): RequirementRepo {
  const reqs = new Map<string, Requirement>();
  return {
    async forIssue(issueId) {
      return ok([...reqs.values()].filter((r) => r.issueId === issueId).map(clone));
    },
    async get(id) {
      const r = reqs.get(id);
      return ok(r ? clone(r) : null);
    },
    async upsert(r) {
      reqs.set(r.id, clone(r));
      return ok(undefined);
    },
    async upsertIf(r, expected) {
      const cur = reqs.get(r.id);
      if (!cur || !expected.includes(cur.status)) return ok(false);
      reqs.set(r.id, clone(r));
      return ok(true);
    },
    async remove(id) {
      reqs.delete(id);
      return ok(undefined);
    },
  };
}

export function memoryLedgerRepo(): LedgerRepo & { _rows: LedgerRow[] } {
  const rows: LedgerRow[] = [];
  return {
    _rows: rows,
    async head() {
      const last = rows.at(-1);
      return ok(last ? { seq: last.seq, entryHash: last.entryHash } : null);
    },
    async append(e) {
      if (rows.some((r) => r.prevHash === e.prevHash || r.seq === e.seq)) return err(appError('conflict', 'ledger head moved'));
      rows.push(clone(e));
      return ok(clone(e));
    },
    async range(fromSeq, toSeq) {
      return ok(rows.filter((r) => r.seq >= fromSeq && r.seq <= toSeq).map(clone));
    },
    async all() {
      return ok(rows.map(clone));
    },
    async ofTypes(types) {
      return ok(rows.filter((r) => types.includes(r.eventType)).map(clone));
    },
    async forIssues(types, issueIds) {
      if (types.length === 0 || issueIds.length === 0) return ok([]);
      return ok(
        rows.filter((r) => types.includes(r.eventType) && (typeof r.payload.issueId !== 'string' || issueIds.includes(r.payload.issueId))).map((r) => ({ ...r, payload: { ...r.payload } })),
      );
    },
    async latestOfTypes(types, limit) {
      return ok(rows.filter((r) => types.includes(r.eventType)).slice(-Math.max(0, limit)).map((r) => ({ ...r, payload: { ...r.payload } })));
    },
    async ofTypesSince(types, sinceIso) {
      return ok(rows.filter((r) => types.includes(r.eventType) && r.createdAt >= sinceIso).map(clone));
    },
    async entryHashes(afterSeq, limit) {
      const n = Math.max(0, Math.min(5000, Math.floor(limit)));
      return ok(rows.filter((r) => r.seq > afterSeq).sort((a, b) => a.seq - b.seq).slice(0, n).map((r) => ({ seq: r.seq, entryHash: r.entryHash })));
    },
  };
}

export function memoryFeedbackRepo(): FeedbackRepo & { _rows: FeedbackRow[] } {
  const rows: FeedbackRow[] = [];
  return {
    _rows: rows,
    async dismissedFor(component) {
      return ok(
        rows
          .filter((r) => r.action === 'dismiss' && r.component === component && r.reason)
          .map((r) => ({ title: r.title, stride: r.stride, reason: r.reason! })),
      );
    },
    async record(f) {
      rows.push(clone(f));
      return ok(undefined);
    },
    async dismissalsSince(sinceIso, limit) {
      const n = Math.max(0, Math.min(2000, Math.floor(limit)));
      const out: DismissalRow[] = [];
      for (const r of [...rows].reverse()) {
        if (r.action !== 'dismiss' || !r.reason || !r.issueId || !r.issueKey || !r.projectKey || !r.at || r.at < sinceIso) continue;
        out.push({ threatId: r.threatId, component: r.component, title: r.title, stride: r.stride, actor: r.actor, reason: r.reason, issueId: r.issueId, issueKey: r.issueKey, projectKey: r.projectKey, at: r.at });
      }
      return ok(out.sort((a, b) => b.at.localeCompare(a.at)).slice(0, n));
    },
  };
}

export function memoryIssueRepo(): IssueRepo {
  const issues = new Map<string, IssueRow>();
  const pages = new Map<string, Set<string>>();
  return {
    async upsert(i) {
      issues.set(i.issueId, clone(i));
      return ok(undefined);
    },
    async get(issueId) {
      const i = issues.get(issueId);
      return ok(i ? clone(i) : null);
    },
    async byKey(issueKey) {
      const i = [...issues.values()].find((x) => x.issueKey === issueKey);
      return ok(i ? clone(i) : null);
    },
    async children(issueId) {
      return ok([...issues.values()].filter((i) => i.parentId === issueId).map(clone));
    },
    async linkPage(issueId, pageId) {
      const s = pages.get(pageId) ?? new Set<string>();
      s.add(issueId);
      pages.set(pageId, s);
      return ok(undefined);
    },
    async issuesForPage(pageId) {
      return ok([...(pages.get(pageId) ?? [])]);
    },
  };
}

export function memoryAttestationRepo(): AttestationRepo {
  const rows: AttestationRow[] = [];
  return {
    async record(a) {
      rows.push(clone(a));
      return ok(undefined);
    },
    async forIssue(issueKey) {
      return ok(rows.filter((r) => r.issueKey === issueKey).map(clone));
    },
  };
}

export function memoryUsageRepo(): UsageRepo {
  const m = new Map<string, { tokensIn: number; tokensOut: number; reviews: number }>();
  const slots = new Map<string, { window: string; used: number }>();
  return {
    async add(month, d) {
      const cur = m.get(month) ?? { tokensIn: 0, tokensOut: 0, reviews: 0 };
      m.set(month, { tokensIn: cur.tokensIn + d.tokensIn, tokensOut: cur.tokensOut + d.tokensOut, reviews: cur.reviews + d.reviews });
      return ok(undefined);
    },
    async get(month) {
      return ok(m.get(month) ?? { tokensIn: 0, tokensOut: 0, reviews: 0 });
    },
    async takeSlot(bucket, window, limit) {
      const cur = slots.get(bucket);
      const used = cur && cur.window === window ? cur.used : 0;
      if (used >= limit) return ok(null);
      slots.set(bucket, { window, used: used + 1 });
      return ok(used + 1);
    },
    async reserveReview(month, cap) {
      const cur = m.get(month) ?? { tokensIn: 0, tokensOut: 0, reviews: 0 };
      if (cur.reviews + 1 > cap) return ok(false);
      m.set(month, { ...cur, reviews: cur.reviews + 1 });
      return ok(true);
    },
  };
}

export function memoryVerdictSink(): VerdictSink & { _written: Map<string, unknown> } {
  const written = new Map<string, unknown>();
  return {
    _written: written,
    async write(issueId, v) {
      written.set(issueId, clone(v));
      return ok(undefined);
    },
  };
}

export function memoryTreeHeadRepo(): TreeHeadRepo {
  const heads = new Map<number, TreeHead>();
  const sorted = () => [...heads.values()].sort((a, b) => b.treeSize - a.treeSize).map(clone);
  return {
    async add(h) {
      if (heads.has(h.treeSize)) return err(appError('conflict', `tree head ${h.treeSize} exists`));
      heads.set(h.treeSize, clone(h));
      return ok(undefined);
    },
    latest: async () => ok(sorted()[0] ?? null),
    lastPublished: async () => ok(sorted().find((h) => h.publishedPageId) ?? null),
    list: async (limit) => ok(sorted().slice(0, Math.max(0, limit))),
    async markPublished(treeSize, pageId) {
      const h = heads.get(treeSize);
      if (!h) return err(appError('not_found', `tree head ${treeSize}`));
      heads.set(treeSize, { ...h, publishedPageId: pageId });
      return ok(undefined);
    },
  };
}
