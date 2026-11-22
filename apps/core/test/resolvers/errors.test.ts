import { afterEach, describe, expect, it, vi } from 'vitest';
import { appError, type AppError } from '@threatline/shared';
import { httpJson } from '../../src/adapters/http.js';
import { apiError } from '../../src/resolvers/errors.js';
import { actionError } from '../../src/actions/schemas.js';

const upstream = async (path: string, status: number, body: string): Promise<AppError> => {
  const call = httpJson(async () => ({ status, text: async () => body }), { maxRetries: 0 });
  const r = await call(path, { method: 'POST', body: '{}' });
  if (r.ok) throw new Error('expected an error');
  return r.error;
};

afterEach(() => vi.restoreAllMocks());

describe('upstream refusals are shown as plain messages, with the detail kept in the logs', () => {
  it.each([
    ['/rest/api/3/issue', 403, 'forbidden', /Jira refused.*permission/i],
    ['/rest/api/3/issue', 400, 'validation', /Jira did not accept/i],
    ['/rest/api/3/issue/1', 409, 'conflict', /changed in Jira/i],
    ['/wiki/api/v2/pages', 403, 'forbidden', /Confluence refused.*permission/i],
  ] as const)('%s %d', async (path, status, code, shown) => {
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((s: string) => void logs.push(s));
    const e = await upstream(path, status, '{"errorMessages":["You do not have permission to create issues in project SEC (internal-id 42)"]}');
    for (const out of [apiError(e), actionError(e)]) {
      expect(out).toMatchObject({ message: expect.stringMatching(shown) });
      const message = (out as { message: string }).message;
      expect(message).not.toMatch(/→|\/rest\/|\/wiki\/|internal-id|POST/);
    }
    expect((apiError(e) as { error: string }).error).toBe(code);
    expect(logs.join('\n')).toContain('internal-id 42');
  });

  it('messages Threatline writes itself still pass through unchanged', () => {
    const mine = appError('forbidden', 'Only a security champion can mark a requirement Not applicable.');
    expect(apiError(mine)).toEqual({ error: 'forbidden', message: mine.message });
    expect(actionError(mine)).toEqual({ error: 'refused', message: mine.message });
    const v = appError('validation', 'A PR or Confluence link must start with https://.', { field: 'ref' });
    expect(apiError(v)).toEqual({ error: 'validation', message: v.message });
  });
});

describe('other failures say what kind they are (audit: every fault used to read as "still finishing its install")', () => {
  it('tells a slow or busy Jira from an internal fault, and keeps the detail in the logs', () => {
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((s: string) => void logs.push(s));
    expect(apiError(appError('timeout', 'gather timed out'))).toEqual({ error: 'unavailable', message: expect.stringMatching(/took too long/) });
    expect(apiError(appError('upstream', 'GET /rest/api/3/issue/1 → 503', { upstream: 'Jira', status: 503 }))).toEqual({ error: 'unavailable', message: 'Jira did not answer just now. Try again in a minute.' });
    const internal = apiError(appError('internal', 'sql: relation reviews does not exist (table secret_x)'));
    expect(internal).toMatchObject({ error: 'unavailable', message: expect.stringMatching(/\(internal\).*app logs/) });
    expect((internal as { message: string }).message).not.toContain('secret_x');
    expect(logs.join('\n')).toContain('secret_x');
  });
});
