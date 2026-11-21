import { z } from 'zod';
import type { CoreDeps } from '../deps.js';
import { createCiToken, listCiTokens, revokeCiToken, type CiTokenInfo } from '../services/ci-tokens.js';
import { requireAdmin, type Admin } from './admin.js';
import { apiError, type ApiError } from './errors.js';

export type { CiTokenInfo };
export interface CiTokensDto {
  /** The `ci-verify` web trigger's URL for this site, or null when Forge could not give it. */
  url: string | null;
  tokens: CiTokenInfo[];
}

const CreateSchema = z.object({ projects: z.array(z.string().max(255)).max(50).optional() });
const RevokeSchema = z.object({ id: z.string().max(64) });

/** `ci.tokens`: the web trigger URL and the site's CI tokens (ids and limits only). Jira administrators only. */
export async function ciTokens(deps: CoreDeps, a: Admin, env: { triggerUrl: () => Promise<string> }): Promise<CiTokensDto | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const tokens = await listCiTokens(deps);
  if (!tokens.ok) return apiError(tokens.error);
  const url = await env.triggerUrl().then(
    (u) => (typeof u === 'string' && u.startsWith('https://') ? u : null),
    () => null,
  );
  return { url, tokens: tokens.value };
}

/** `ci.createToken`: a new CI token, returned once (only its hash is kept). Ledgered. Jira administrators only. */
export async function ciCreateToken(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ token: string; info: CiTokenInfo } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = CreateSchema.safeParse(payload);
  if (!p.success) return { error: 'validation', message: 'projects: a list of Jira project keys (like PAY), or none for every Threatline project.' };
  const r = await createCiToken(deps, a.accountId, { projects: p.data.projects ?? [] });
  return r.ok ? r.value : apiError(r.error);
}

/** `ci.revokeToken`: the token stops working at once. Ledgered. Jira administrators only. */
export async function ciRevokeToken(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ id: string } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = RevokeSchema.safeParse(payload);
  if (!p.success) return { error: 'validation', message: 'id: the CI token to revoke.' };
  const r = await revokeCiToken(deps, a.accountId, p.data.id);
  return r.ok ? r.value : apiError(r.error);
}
