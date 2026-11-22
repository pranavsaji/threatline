import { describe, expect, it } from 'vitest';
import { FIXTURES } from '../src/fixtures.js';
import { pollMs, viewOf } from '../src/panel/states.js';

describe('viewOf', () => {
  it.each([
    ['not_reviewed', 'not_reviewed'],
    ['in_progress', 'in_progress'],
    ['ready', 'ready'],
    ['partial', 'ready'],
    ['failed', 'failed'],
    ['timeout', 'timeout'],
    ['budget', 'budget'],
  ])('%s fixture → state %s', (fixture, state) => {
    expect(viewOf(FIXTURES[fixture]!).state).toBe(state);
  });

  it('a review that failed at the budget is shown as failed (with a re-run) once the gate says reviews resumed', () => {
    const b = FIXTURES.budget!;
    const resumed = { ...b, verdict: { ...b.verdict!, reasons: [{ code: 'review_failed' as const, message: 'This work item’s review failed while reviews were paused at the AI budget. Reviews have resumed, so run it again.' }] } };
    expect(viewOf(resumed).state).toBe('failed');
  });

  it('flags partial, stale and injection', () => {
    expect(viewOf(FIXTURES.partial!).partial).toBe(true);
    expect(viewOf(FIXTURES.stale!).stale).toBe(true);
    expect(viewOf(FIXTURES.injection!).injection).toBe(true);
    expect(viewOf(FIXTURES.ready!)).toMatchObject({ partial: false, stale: false, injection: false });
  });

  it('builds the live step list and marks the current step; polls every 3 s only while running', () => {
    const v = viewOf(FIXTURES.in_progress!);
    expect(v.steps.map((s) => [s.label, s.done, s.current])).toEqual([
      ['Context gathered', true, false],
      ['Agent run 1 of 3', true, false],
      ['Agent run 2 of 3', false, true],
      ['Agent run 3 of 3', false, false],
      ['Scored', false, false],
    ]);
    expect(pollMs(v)).toBe(3000);
    expect(pollMs(viewOf(FIXTURES.ready!))).toBeNull();
  });
});

describe('polling while the Engine verifier runs', () => {
  it('keeps polling a ready review until panel.get stops reporting verification as pending', () => {
    const ready = FIXTURES.ready!;
    const verifying = viewOf({ ...ready, verifying: true } as typeof ready);
    expect(verifying).toMatchObject({ state: 'ready', verifying: true });
    expect(pollMs(verifying)).toBe(3000);
    expect(pollMs(viewOf({ ...ready, verifying: false } as typeof ready))).toBeNull();
  });

  it('a failed review never counts as verifying', () => {
    const failed = FIXTURES.failed!;
    expect(viewOf({ ...failed, verifying: true } as typeof failed).verifying).toBe(false);
  });
});
