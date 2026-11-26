import { existsSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { FIX_CASES } from '../fixtures/fix-cases.js';
import { FIX_RECORD_DIR, runFixEval } from './fix-eval.js';
import { parseUnifiedDiff } from '@threatline/core';

/**
 * CI gate for the fix check (docs/FIX_CHECK.md): replays the recorded `claude -p` replies through today's code
 * (validation, quote check, settlement). No false fix is allowed: a change that does not fix its requirement must never
 * be called fixed. Re-record with `pnpm threatline fix-eval --llm claude-code --model claude-opus-5`.
 */
describe('fix-check eval set', () => {
  it('every case diff parses, and every case has a real added line', () => {
    for (const c of FIX_CASES) {
      const files = parseUnifiedDiff(c.diff);
      expect(files.length, c.id).toBeGreaterThan(0);
      expect(files.reduce((n, f) => n + f.added, 0), c.id).toBeGreaterThan(0);
    }
  });
  it('acceptable alternatives never include fixed', () => {
    for (const c of FIX_CASES) expect(c.acceptable ?? [], c.id).not.toContain('fixed');
  });
});

const recorded = existsSync(FIX_RECORD_DIR) ? readdirSync(FIX_RECORD_DIR).filter((f) => f.endsWith('.json')).length : 0;

describe.skipIf(recorded < FIX_CASES.length)('fix-check eval gate (recorded replies)', () => {
  it('no false fixes, at most one real fix held, and at least 90% of verdicts a reviewer would accept', async () => {
    const r = await runFixEval({ mode: 'recorded', model: 'recorded' });
    expect(r.errors).toBe(0);
    expect(r.results.filter((x) => x.falseFix).map((x) => x.id)).toEqual([]);
    expect(r.missedFixes).toBeLessThanOrEqual(1);
    expect(r.acceptable / r.cases).toBeGreaterThanOrEqual(0.9);
  });
  it('the change that talks to the AI is flagged, and still not called fixed', async () => {
    const r = await runFixEval({ mode: 'recorded', model: 'recorded', only: ['ts-webhook-comment-injection'] });
    expect(r.results[0]).toMatchObject({ injectionFlagged: true, falseFix: false });
  });
});
