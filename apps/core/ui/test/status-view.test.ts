import { describe, expect, it } from 'vitest';
import { FIXTURES } from '../src/fixtures.js';
import { statusOf, statusPollMs } from '../src/status/status-view.js';
import type { StatusDto } from '../src/types.js';

const ready = FIXTURES.ready!;
const block: StatusDto = { issueKey: 'PAY-6', verdict: ready.verdict, review: { status: 'ready' }, inScope: true };
const withVerdict = (v: Partial<NonNullable<StatusDto['verdict']>>): StatusDto => ({ ...block, verdict: { ...block.verdict!, ...v } });

describe('statusOf: the context column', () => {
  it('blocks: ✕ Blocks Done, the open count and the top reason', () => {
    expect(statusOf(block)).toEqual({ kind: 'block', icon: '✕', label: 'Blocks Done', appearance: 'removed', open: '2 open', line: '2 open security requirements at High or above.' });
  });

  it('a block with nothing open (a failed review) shows no count, only why', () => {
    const v = statusOf({ ...FIXTURES.failed!, verdict: { ...FIXTURES.failed!.verdict!, blockingCount: 0 } });
    expect(v).toMatchObject({ kind: 'block', open: null, line: 'The security review failed.' });
  });

  it('passes: ✓ Ready for Done and nothing else', () => {
    expect(statusOf(FIXTURES.pass!)).toEqual({ kind: 'pass', icon: '✓', label: 'Ready for Done', appearance: 'success', open: null, line: null });
  });

  it('warn only: ! Warn only with the count and reason', () => {
    expect(statusOf(withVerdict({ state: 'warn' }))).toMatchObject({ kind: 'warn', icon: '!', label: 'Warn only', appearance: 'moved', open: '2 open', line: '2 open security requirements at High or above.' });
    expect(statusOf(withVerdict({ state: 'warn', reasons: [], validUntil: '2026-12-01T10:00:00.000Z' })).line).toBe('Until 2026-12-01 10:00 UTC');
  });

  it('break-glass: the gate passes but says it is overridden, and until when', () => {
    const v = statusOf(withVerdict({ state: 'pass', overridden: true, validUntil: '2026-11-25T08:30:00.000Z' }));
    expect(v).toEqual({ kind: 'overridden', icon: '!', label: 'Gate overridden (break-glass)', appearance: 'moved', open: null, line: 'Until 2026-11-25 08:30 UTC' });
  });

  it('a running review shows Reviewing… with its progress, and polls; nothing else does', () => {
    const v = statusOf(FIXTURES.in_progress!);
    expect(v).toMatchObject({ kind: 'reviewing', label: 'Reviewing…', appearance: 'inprogress', open: null, line: 'Review in progress (1 of 3 agent runs received).' });
    expect(statusPollMs(v)).toBe(5000);
    for (const s of ['queued', 'gathering', 'modeling'] as const) expect(statusOf({ ...block, review: { status: s } }).kind).toBe('reviewing');
    for (const f of ['ready', 'pass', 'failed', 'timeout', 'not_reviewed']) expect(statusPollMs(statusOf(FIXTURES[f]!)), f).toBeNull();
  });

  it('not reviewed: says Done is blocked until it is, when the gate blocks', () => {
    expect(statusOf(FIXTURES.not_reviewed!)).toEqual({ kind: 'not_reviewed', icon: '✕', label: 'Not reviewed', appearance: 'removed', open: null, line: 'Blocks Done until Threatline reviews it.' });
  });

  it('not reviewed, inherited block: the parent’s reason is the line', () => {
    const v = statusOf({ ...block, review: null, verdict: { ...block.verdict!, reasons: [{ code: 'open_requirement', message: 'PAY-1: 1 open security requirement at High or above.' }] } });
    expect(v).toMatchObject({ kind: 'not_reviewed', icon: '✕', line: 'PAY-1: 1 open security requirement at High or above.' });
  });

  it('not reviewed and no verdict: a plain Not reviewed, with why when Threatline does not review it', () => {
    expect(statusOf({ issueKey: 'PAY-6', verdict: null, review: null, inScope: true })).toEqual({ kind: 'not_reviewed', icon: null, label: 'Not reviewed', appearance: 'default', open: null, line: null });
    expect(statusOf({ issueKey: 'OPS-1', verdict: null, review: null, inScope: false, scopeMessage: 'Threatline is not turned on for project OPS.' }).line).toBe('Threatline is not turned on for project OPS.');
    // A review with no verdict yet reads as the panel header does.
    expect(statusOf({ ...block, verdict: null }).label).toBe('Not reviewed');
  });

  it('an inactive license: the gate does not block, so no verdict is shown', () => {
    expect(statusOf({ ...block, licenseInactive: true })).toEqual({ kind: 'license', icon: '!', label: 'License inactive', appearance: 'moved', open: null, line: 'The Done gate does not block until Threatline is renewed.' });
  });

  it('the panel DTO maps the same as panel.status (the fallback when an API has no status call)', () => {
    for (const f of Object.keys(FIXTURES)) expect(statusOf(FIXTURES[f]!).label, f).toBeTruthy();
    expect(statusOf(ready)).toEqual(statusOf(block));
  });
  it('a second reason shows under the first while the gate blocks or warns, never otherwise', () => {
    const reasons = [
      { code: 'open_requirements', message: '10 open security requirements at High or above.' },
      { code: 'needs_human', message: '1 threat needs a security champion to confirm it.' },
    ];
    expect(statusOf(withVerdict({ reasons } as never))).toMatchObject({ kind: 'block', line: reasons[0]!.message, next: reasons[1]!.message });
    expect(statusOf(withVerdict({ state: 'warn', reasons } as never)).next).toBe(reasons[1]!.message);
    expect(statusOf(withVerdict({ state: 'pass', reasons } as never)).next).toBeUndefined();
  });
});
