import { z } from 'zod';
import { checkTreeHeads, type TreeHeadCheck } from '@threatline/core';
import { verifyChain, type ChainVerdict } from '@threatline/crypto';
import type { CoreDeps } from '../deps.js';
import { evidencePack } from '../services/evidence-pack.js';
import { currentTreeHead, ledgerProofFor } from '../services/transparency.js';
import { requireAdmin, type Admin } from './admin.js';
import { apiError, type ApiError } from './errors.js';

const DATE = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'use YYYY-MM-DD').refine((d) => !Number.isNaN(new Date(`${d}T00:00:00Z`).getTime()), 'not a date');
export const ExportSchema = z
  .object({ projectKey: z.string().regex(/^[A-Z][A-Z0-9_]{0,254}$/, 'a Jira project key like PAY'), from: DATE, to: DATE })
  .refine((q) => q.from <= q.to, { message: 'the start date must be on or before the end date', path: ['from'] });

/** How many stored signed tree heads "Verify the ledger" checks (newest first; one per ledger size that was signed). */
const VERIFY_HEADS = 200;
export type LedgerVerdict = (ChainVerdict & { treeHeads?: number }) | Extract<TreeHeadCheck, { ok: false }>;

/**
 * `ledger.verify` (RL-4): Jira administrators only. The hash chain, then the chain against the signed tree heads: the
 * chain alone reads "intact" after the newest entries are dropped, or after an entry is changed and every later hash
 * recomputed.
 */
export async function ledgerVerify(deps: CoreDeps, a: Admin): Promise<LedgerVerdict | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const rows = await deps.ledger.all();
  if (!rows.ok) return apiError(rows.error);
  const chain = verifyChain(rows.value);
  if (!chain.ok) return chain;
  const [heads, keys] = await Promise.all([deps.treeHeads.list(VERIFY_HEADS), deps.keys.publicKeys()]);
  if (!heads.ok) return apiError(heads.error);
  if (!keys.ok) return apiError(keys.error);
  const checked = checkTreeHeads(rows.value, heads.value, keys.value);
  if (!checked.ok) return checked;
  return checked.checked > 0 ? { ...chain, treeHeads: checked.checked } : chain;
}

/** `ledger.export` (RL-7): the evidence pack. Jira administrators only. */
export async function ledgerExport(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ csv: string; json: string } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = ExportSchema.safeParse(payload);
  if (!p.success) return { error: 'validation', message: p.error.issues.slice(0, 2).map((i) => `${i.path.join('.') || 'request'}: ${i.message}`).join('; ') };
  const r = await evidencePack(deps, p.data);
  return r.ok ? r.value : apiError(r.error);
}

/** `ledger.proof` (R5): a downloadable inclusion proof for one entry. Jira administrators only. */
export async function ledgerProof(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ json: string; seq: number; treeSize: number } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = z.object({ seq: z.number().int().min(1) }).safeParse(payload);
  if (!p.success) return { error: 'validation', message: 'Give a ledger entry number (1 or more).' };
  const r = await ledgerProofFor(deps, p.data.seq);
  if (!r.ok) return apiError(r.error);
  return { json: JSON.stringify(r.value, null, 2), seq: p.data.seq, treeSize: r.value.treeHead.treeSize };
}

/** `ledger.treeHead` (R5): the current signed head and the key to check it with. Jira administrators only. */
export async function ledgerTreeHead(deps: CoreDeps, a: Admin): Promise<{ treeHead: { treeSize: number; rootHash: string; timestamp: string; kid: string }; publicKey: string | null; publishedPageId: string | null } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const [head, keys] = await Promise.all([currentTreeHead(deps), deps.keys.publicKeys()]);
  if (!head.ok) return apiError(head.error);
  const { treeSize, rootHash, timestamp, kid } = head.value;
  return { treeHead: { treeSize, rootHash, timestamp, kid }, publicKey: keys.ok ? (keys.value[kid] ?? null) : null, publishedPageId: head.value.publishedPageId ?? null };
}
