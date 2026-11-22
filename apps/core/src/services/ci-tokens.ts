import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { appendLedger } from '@threatline/core';
import { appError, err, ok, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';

/**
 * Per-site CI tokens for verification from CI (docs/CI_VERIFICATION.md). A token is `tlci_<id>_<secret>`: the id is
 * public (it names the token in the admin page and the ledger), the secret is 256 random bits. Threatline keeps only
 * SHA-256 of the whole token, in Forge secret storage; the plain store lists the tokens for the admin page. A token
 * works only while it is in both, so a half-finished create or revoke fails closed.
 */
export const CI_TOKENS_KEY = 'config:ci-tokens';
const secretKey = (id: string) => `secret:ci-token:${id}`;
export const MAX_CI_TOKENS = 10;
const MAX_PROJECTS = 50;
const ID = /^[0-9a-f]{16}$/;
const TOKEN = /^tlci_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;
const BEARER = /^Bearer +(\S+)$/i;
const PROJECT_KEY = /^[A-Z][A-Z0-9_]{0,254}$/;

const InfoSchema = z.object({ id: z.string().regex(ID), createdAt: z.string(), createdBy: z.string(), projects: z.array(z.string()) }).strict();
export type CiTokenInfo = z.infer<typeof InfoSchema>;
const SecretSchema = z.object({ hash: z.string().regex(/^[0-9a-f]{64}$/), projects: z.array(z.string().regex(PROJECT_KEY)) }).strict();

const upstream = (e: unknown): Result<never> => err(appError('upstream', `kvs: ${e instanceof Error ? e.message : String(e)}`));
const hashOf = (token: string) => createHash('sha256').update(token, 'utf8').digest('hex');

async function readList(deps: CoreDeps): Promise<Result<CiTokenInfo[]>> {
  try {
    const raw = await deps.state.get<unknown>(CI_TOKENS_KEY);
    if (raw === undefined) return ok([]);
    const p = z.array(InfoSchema).safeParse(raw);
    return p.success ? ok(p.data) : err(appError('schema', 'stored CI token list is invalid'));
  } catch (e) {
    return upstream(e);
  }
}

export const listCiTokens = (deps: CoreDeps): Promise<Result<CiTokenInfo[]>> => readList(deps);

/** Creates a token and returns it once. Ledgered (id and projects, never the token) before anything is stored. */
export async function createCiToken(deps: CoreDeps, actor: string, input: { projects: readonly string[] }): Promise<Result<{ token: string; info: CiTokenInfo }>> {
  const projects = [...new Set(input.projects.map((p) => p.trim().toUpperCase()).filter(Boolean))].sort();
  const bad = projects.find((p) => !PROJECT_KEY.test(p));
  if (bad !== undefined) return err(appError('validation', `"${bad.slice(0, 40)}" is not a Jira project key (like PAY).`));
  if (projects.length > MAX_PROJECTS) return err(appError('validation', `Limit a token to at most ${MAX_PROJECTS} projects.`));
  const list = await readList(deps);
  if (!list.ok) return list;
  if (list.value.length >= MAX_CI_TOKENS) return err(appError('validation', `A site can have at most ${MAX_CI_TOKENS} CI tokens. Revoke one first.`));

  const id = randomBytes(8).toString('hex');
  const token = `tlci_${id}_${randomBytes(32).toString('base64url')}`;
  const info: CiTokenInfo = { id, createdAt: deps.clock.now().toISOString(), createdBy: actor, projects };
  const row = await appendLedger(deps.ledger, deps.clock, 'ci_token.created', { tokenId: id, projects }, actor);
  if (!row.ok) return row;
  try {
    await deps.state.setSecret(secretKey(id), { hash: hashOf(token), projects });
    await deps.state.set(CI_TOKENS_KEY, [...list.value, info]);
  } catch (e) {
    return upstream(e);
  }
  return ok({ token, info });
}

/**
 * Revokes a token: it leaves the list (refused from then on), then its hash is deleted. Ledgered first.
 * Security: KVS reads can lag a write, so a list read just after a create may not show the token yet. Its hash is what
 * authenticates it, so revoke deletes the hash whenever it exists, listed or not; not_found only when neither exists.
 */
export async function revokeCiToken(deps: CoreDeps, actor: string, id: string): Promise<Result<{ id: string }>> {
  if (!ID.test(id)) return err(appError('validation', 'That is not a CI token id.'));
  const list = await readList(deps);
  if (!list.ok) return list;
  const listed = list.value.some((t) => t.id === id);
  if (!listed) {
    let secret: unknown;
    try {
      secret = await deps.state.getSecret<unknown>(secretKey(id));
    } catch (e) {
      return upstream(e);
    }
    if (secret === undefined) return err(appError('not_found', 'CI token not found'));
  }
  const row = await appendLedger(deps.ledger, deps.clock, 'ci_token.revoked', { tokenId: id }, actor);
  if (!row.ok) return row;
  try {
    if (listed) await deps.state.set(CI_TOKENS_KEY, list.value.filter((t) => t.id !== id));
    await deps.state.deleteSecret(secretKey(id));
  } catch (e) {
    return upstream(e);
  }
  return ok({ id });
}

export type CiAuth = { ok: true; value: { id: string; projects: string[] } } | { ok: false; error: 'unauthorized' | 'unavailable' };

/**
 * Security: checks an `Authorization: Bearer tlci_…` header. The hash is compared in constant time; the token must
 * still be listed and its secret record valid. A storage error is `unavailable` (the caller refuses the request), never
 * a pass. Nothing about the presented token is logged or returned.
 */
export async function authenticateCi(deps: CoreDeps, authorization: string | undefined): Promise<CiAuth> {
  const bearer = BEARER.exec(authorization?.trim() ?? '');
  const m = bearer ? TOKEN.exec(bearer[1]!) : null;
  if (!m) return { ok: false, error: 'unauthorized' };
  const id = m[1]!;
  let raw: unknown;
  const list = await readList(deps);
  if (!list.ok) return { ok: false, error: 'unavailable' };
  try {
    raw = await deps.state.getSecret<unknown>(secretKey(id));
  } catch {
    return { ok: false, error: 'unavailable' };
  }
  const stored = SecretSchema.safeParse(raw);
  // Hash even when the token is unknown, so an unknown id and a wrong secret take the same work.
  const presented = Buffer.from(hashOf(bearer![1]!), 'utf8');
  const expected = Buffer.from(stored.success ? stored.data.hash : '0'.repeat(64), 'utf8');
  const match = timingSafeEqual(presented, expected);
  if (!stored.success || !match || !list.value.some((t) => t.id === id)) return { ok: false, error: 'unauthorized' };
  return { ok: true, value: { id, projects: stored.data.projects } };
}
