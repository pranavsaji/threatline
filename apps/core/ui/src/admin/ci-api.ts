import type { Invoke } from '../bridge.js';
import type { ApiError, CiTokenInfo, CiTokensDto } from '../types.js';

/** The admin page's CI verification calls (Jira administrators only; the server checks). */
export interface CiApi {
  tokens(): Promise<CiTokensDto | ApiError>;
  /** A new token, returned once. An empty list means every Threatline project. */
  create(projects: string[]): Promise<{ token: string; info: CiTokenInfo } | ApiError>;
  revoke(id: string): Promise<{ id: string } | ApiError>;
}

export function ciApiOver(invoke: Invoke): CiApi {
  return {
    tokens: () => invoke('ci.tokens'),
    create: (projects) => invoke('ci.createToken', { projects }),
    revoke: (id) => invoke('ci.revokeToken', { id }),
  };
}

/** Local preview (`?view=admin`): one token, and a create that returns a sample token. */
export function mockCiApi(): CiApi {
  let tokens: CiTokenInfo[] = [{ id: '0123456789abcdef', createdAt: '2026-11-20T10:00:00.000Z', createdBy: 'acc-admin', projects: [] }];
  return {
    tokens: async () => ({ url: 'https://example.hello.atlassian-dev.net/x1/ci-verify', tokens: structuredClone(tokens) }),
    create: async (projects) => {
      const info = { id: 'fedcba9876543210', createdAt: new Date().toISOString(), createdBy: 'acc-admin', projects };
      tokens = [...tokens, info];
      return { token: `tlci_${info.id}_${'x'.repeat(43)}`, info };
    },
    revoke: async (id) => ((tokens = tokens.filter((t) => t.id !== id)), { id }),
  };
}
