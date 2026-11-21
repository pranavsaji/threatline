import { verifyChain } from '@threatline/crypto';
import { controlsCell, csvCell, requirementControls, type LedgerRow } from '@threatline/core';
import { COMPLIANCE_DISCLAIMER, type ControlRef } from '@threatline/frameworks';
import { ok, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';

const DAY = 86_400_000;
const COLUMNS = ['seq', 'created_at', 'event_type', 'actor', 'issue_key', 'requirement_id', 'acceptance_id', 'reason', 'payload_json', 'prev_hash', 'entry_hash', 'controls'] as const;

const str = (v: unknown) => (typeof v === 'string' ? v : '');

/**
 * RL-7: one project's ledger entries in a date range (UTC, inclusive), as CSV and JSON. Every entry carries its
 * prev/entry hashes; the JSON adds the whole chain's verification result and head at export time, so an auditor can
 * recompute each entry hash (sha256(prevHash + canonicalJson({seq, eventType, payload, actor, createdAt}))) and match
 * the head against the admin page. Site-wide entries (no work item, e.g. key rotation) are included in every project.
 * An entry about a requirement also names the compliance controls its ASVS ids map to (indicative, not an audit
 * opinion; docs/COMPLIANCE.md). They are looked up at export time and are not part of the hashed entry.
 */
export async function evidencePack(deps: CoreDeps, q: { projectKey: string; from: string; to: string }): Promise<Result<{ csv: string; json: string }>> {
  const rows = await deps.ledger.all();
  if (!rows.ok) return rows;
  const start = new Date(`${q.from}T00:00:00.000Z`).getTime();
  const end = new Date(`${q.to}T00:00:00.000Z`).getTime() + DAY;

  const projectOf = new Map<string, { project: string | null; key: string }>();
  const lookup = async (row: LedgerRow): Promise<{ project: string | null; key: string } | 'site'> => {
    const issueId = str(row.payload.issueId);
    const issueKey = str(row.payload.issueKey);
    if (!issueId && !issueKey) return str(row.payload.projectKey) ? { project: str(row.payload.projectKey), key: '' } : 'site';
    const cacheKey = issueId || issueKey;
    const cached = projectOf.get(cacheKey);
    if (cached) return cached;
    const known = issueId ? await deps.issues.get(issueId) : await deps.issues.byKey(issueKey);
    const found = known.ok && known.value ? { project: known.value.projectKey, key: known.value.issueKey } : { project: issueKey ? issueKey.split('-')[0]! : null, key: issueKey };
    projectOf.set(cacheKey, found);
    return found;
  };

  const picked: Array<{ row: LedgerRow; issueKey: string }> = [];
  for (const row of rows.value) {
    const t = new Date(row.createdAt).getTime();
    if (t < start || t >= end) continue;
    const where = await lookup(row);
    if (where === 'site') picked.push({ row, issueKey: '' });
    else if (where.project === q.projectKey) picked.push({ row, issueKey: where.key });
  }

  // A requirement that is gone (its project purged) still names its id; it just maps to no control.
  const controlsOf = new Map<string, ControlRef[]>();
  for (const { row } of picked) {
    const id = str(row.payload.requirementId);
    if (!id || controlsOf.has(id)) continue;
    const req = await deps.requirements.get(id);
    controlsOf.set(id, req.ok && req.value ? requirementControls(req.value) : []);
  }
  const controls = (row: LedgerRow) => controlsOf.get(str(row.payload.requirementId));

  const lines = [COLUMNS.join(',')];
  for (const { row, issueKey } of picked) {
    const p = row.payload;
    lines.push(
      [String(row.seq), row.createdAt, row.eventType, row.actor, issueKey, str(p.requirementId), str(p.acceptanceId), str(p.reason), JSON.stringify(p), row.prevHash, row.entryHash, controlsCell(controls(row) ?? [])].map(csvCell).join(','),
    );
  }
  const head = rows.value.at(-1);
  const json = {
    projectKey: q.projectKey,
    from: q.from,
    to: q.to,
    generatedAt: deps.clock.now().toISOString(),
    chain: verifyChain(rows.value),
    head: head ? { seq: head.seq, entryHash: head.entryHash } : null,
    hashRule: 'entryHash = sha256_hex(prevHash + canonicalJson({seq, eventType, payload, actor, createdAt})); the first entry chains from 64 zeros',
    controlsNote: `${COMPLIANCE_DISCLAIMER} "controls" is added at export time from the requirement's ASVS ids and is not part of the hashed entry.`,
    entries: picked.map(({ row, issueKey }) => {
      const c = controls(row);
      return { seq: row.seq, createdAt: row.createdAt, eventType: row.eventType, actor: row.actor, issueKey, payload: row.payload, prevHash: row.prevHash, entryHash: row.entryHash, ...(c ? { controls: c } : {}) };
    }),
  };
  return ok({ csv: `${lines.join('\n')}\n`, json: JSON.stringify(json, null, 2) });
}
