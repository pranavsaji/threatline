import { describe, expect, it } from 'vitest';
import { forgeLlm } from '../../src/adapters/forge-llm.js';

const req = { system: 'sys', user: 'usr', tier: 'deep' as const, maxOutputTokens: 100, purpose: 'propose' as const };
const reply = (text: string, usage = { input_tokens: 12, output_tokens: 34 }) => ({ choices: [{ finish_reason: 'stop', message: { role: 'assistant' as const, content: text } }], usage });
const apiError = (status: number) => Object.assign(new Error('x'), { name: 'ForgeLlmAPIError', status, code: 'MODEL_UNAVAILABLE' });

describe('forgeLlm (Threatline Engine on Forge LLMs)', () => {
  it('sends the system prompt as a system message, caps output, and reports the model and token counts', async () => {
    const calls: unknown[] = [];
    const llm = forgeLlm({ fast: ['f'], balanced: ['b'], deep: ['opus-x'] }, async (p) => (calls.push(p), reply('{"threats":[]}')));
    const r = await llm.complete(req);
    expect(r).toEqual({ ok: true, value: { text: '{"threats":[]}', modelId: 'opus-x', tokensIn: 12, tokensOut: 34 } });
    expect(calls[0]).toMatchObject({ model: 'opus-x', messages: [{ role: 'system', content: 'sys' }, { role: 'user', content: 'usr' }], max_completion_tokens: 100 });
  });

  it('falls through to the next model when the platform refuses one', async () => {
    const tried: string[] = [];
    const llm = forgeLlm({ fast: [], balanced: [], deep: ['new', 'older'] }, async (p) => {
      tried.push(p.model);
      if (p.model === 'new') throw apiError(404);
      return reply('ok');
    });
    const r = await llm.complete(req);
    expect(tried).toEqual(['new', 'older']);
    expect(r.ok && r.value.modelId).toBe('older');
  });

  it('retries a model once without temperature on a 400, remembers that, and skips models refused outright', async () => {
    const seen: Array<{ model: string; temperature?: number }> = [];
    const llm = forgeLlm({ fast: [], balanced: [], deep: ['gone', 'fixed'] }, async (p) => {
      seen.push({ model: p.model, ...(p.temperature !== undefined ? { temperature: p.temperature } : {}) });
      if (p.model === 'gone') throw apiError(400);
      if (p.temperature !== undefined) throw apiError(400);
      return reply('ok');
    });
    expect((await llm.complete(req)).ok).toBe(true);
    expect(seen).toEqual([{ model: 'gone', temperature: 0.7 }, { model: 'gone' }, { model: 'fixed', temperature: 0.7 }, { model: 'fixed' }]);
    seen.length = 0;
    expect((await llm.complete(req)).ok).toBe(true);
    expect(seen).toEqual([{ model: 'fixed' }]);
  });

  it('stops at a prompt validation error (our bug fails on every model) and reports every failure as an error, never a throw', async () => {
    const tried: string[] = [];
    const bad = Object.assign(new Error('x'), { name: 'PromptValidationError' });
    const llm = forgeLlm({ fast: [], balanced: [], deep: ['a', 'b'] }, async (p) => (tried.push(p.model), Promise.reject(bad)));
    const r = await llm.complete(req);
    expect(tried).toEqual(['a']);
    // Not worth a queue retry: the same request fails the same way.
    expect(!r.ok && r.error.code).toBe('validation');
    const all = forgeLlm({ fast: [], balanced: [], deep: ['a'] }, async () => Promise.reject(apiError(504)), { sleep: async () => {} });
    expect(await all.complete(req)).toMatchObject({ ok: false, error: { code: 'timeout' } });
  });

  it('retries a rate-limited or overloaded model with exponential backoff and full jitter before falling through', async () => {
    const tried: string[] = [];
    const slept: number[] = [];
    let n = 0;
    const llm = forgeLlm(
      { fast: [], balanced: [], deep: ['opus', 'older'] },
      async (p) => {
        tried.push(p.model);
        if (n++ < 2) throw apiError(n === 1 ? 429 : 503);
        return reply('ok');
      },
      { sleep: async (ms) => void slept.push(ms), random: () => 0.5, baseDelayMs: 1000, maxDelayMs: 10_000 },
    );
    const r = await llm.complete(req);
    // The same (best) model answered on its third try: the rate limit did not push the review onto an older model.
    expect(tried).toEqual(['opus', 'opus', 'opus']);
    expect(r.ok && r.value.modelId).toBe('opus');
    expect(slept).toEqual([500, 1000]);
  });

  it('a network error (no HTTP status) is transient too; after the retries the next model is tried', async () => {
    const tried: string[] = [];
    const llm = forgeLlm(
      { fast: [], balanced: [], deep: ['a', 'b'] },
      async (p) => {
        tried.push(p.model);
        if (p.model === 'a') throw Object.assign(new Error('socket hang up'), { name: 'FetchError' });
        return reply('ok');
      },
      { sleep: async () => {}, retries: 1 },
    );
    const r = await llm.complete(req);
    expect(tried).toEqual(['a', 'a', 'b']);
    expect(r.ok && r.value.modelId).toBe('b');
  });

  it('never retries past the deadline (the queue function has 300 s), and reports a transient failure as upstream for a later job retry', async () => {
    let clock = 0;
    const tried: string[] = [];
    const llm = forgeLlm(
      { fast: [], balanced: [], deep: ['a', 'b'] },
      async (p) => {
        tried.push(p.model);
        clock += 100_000; // each call takes 100 s, then the platform says it is overloaded
        throw apiError(529);
      },
      { sleep: async (ms) => void (clock += ms), now: () => clock, random: () => 1, deadlineMs: 120_000 },
    );
    const r = await llm.complete(req);
    // 100 s in, a retry that may take another 100 s would end past 120 s: no retry. The next model is still tried once
    // (as before retries existed); 200 s in, nothing more is.
    expect(tried).toEqual(['a', 'b']);
    expect(!r.ok && r.error.code).toBe('upstream');
  });

  it('a tier whose every model the platform refused is reported as forbidden (no queue retry), not as an outage', async () => {
    const slept: number[] = [];
    const llm = forgeLlm({ fast: [], balanced: [], deep: ['a', 'b'] }, async () => Promise.reject(apiError(404)), { sleep: async (ms) => void slept.push(ms) });
    const r = await llm.complete(req);
    expect(!r.ok && r.error.code).toBe('forbidden');
    expect(slept).toEqual([]);
  });

  it('joins text parts, and an empty reply is an error', async () => {
    const parts = forgeLlm({ fast: [], balanced: [], deep: ['m'] }, async () => ({ choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }] } }] }));
    expect((await parts.complete(req)).ok && ((await parts.complete(req)) as { ok: true; value: { text: string } }).value.text).toBe('ab');
    const empty = forgeLlm({ fast: [], balanced: [], deep: ['m'] }, async () => reply('  '));
    expect((await empty.complete(req)).ok).toBe(false);
  });
});
