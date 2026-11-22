import { describe, expect, it } from 'vitest';
import { retryDecision } from '../src/consumers/retry.js';

const failed = (code: string) => ({ ok: false as const, error: { code } });

describe('queue retry decision', () => {
  it('retries transient failures with serialisable retryData (Forge measures it and throws on undefined)', () => {
    const r = retryDecision(failed('upstream'), 0) as unknown as { _retry: boolean; retryOptions: { retryData?: unknown } };
    expect(r._retry).toBe(true);
    expect(r.retryOptions.retryData).toEqual({ code: 'upstream', attempt: 1 });
    expect(Buffer.byteLength(JSON.stringify(r.retryOptions.retryData))).toBeLessThan(4096);
    expect(retryDecision(failed('timeout'), 2)).toBeDefined();
  });
  it('does not retry success, permanent failures, or after three attempts', () => {
    expect(retryDecision({ ok: true }, 0)).toBeUndefined();
    expect(retryDecision(failed('validation'), 0)).toBeUndefined();
    expect(retryDecision(failed('upstream'), 3)).toBeUndefined();
  });
});
