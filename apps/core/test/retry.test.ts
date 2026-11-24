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
  it('backs off: a longer delay each attempt, with jitter so jobs that failed together do not retry together', () => {
    const after = (count: number, rand: number) => (retryDecision(failed('upstream'), count, () => rand) as unknown as { retryOptions: { retryAfter: number } }).retryOptions.retryAfter;
    expect([after(0, 0), after(1, 0), after(2, 0)]).toEqual([60, 120, 180]);
    expect(after(0, 0.999)).toBe(89);
    expect(after(2, 0.999)).toBeLessThan(900); // Forge's maximum delay
  });
  it('does not retry success, permanent failures, or after three attempts', () => {
    expect(retryDecision({ ok: true }, 0)).toBeUndefined();
    expect(retryDecision(failed('validation'), 0)).toBeUndefined();
    expect(retryDecision(failed('upstream'), 3)).toBeUndefined();
  });
});
