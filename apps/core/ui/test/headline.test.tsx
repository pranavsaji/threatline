// @vitest-environment jsdom
import './setup-dom.js';
import { describe, expect, it } from 'vitest';
import { headlineOf } from '../src/panel/Header.js';
import type { PanelDto } from '../src/types.js';

type V = NonNullable<PanelDto['verdict']>;
const reason = (message: string): V['reasons'][number] => ({ code: 'open_requirement', message }) as V['reasons'][number];
const verdict = (over: Partial<V>): V => ({ state: 'block', reasons: [], blockingCount: 0, inheritedFrom: [], updatedAt: '2026-11-24T00:00:00.000Z', ...over }) as V;

describe('panel headline: what stands between this work item and Done', () => {
  it('counts the reasons when Done is blocked, and says when only the first three are listed', () => {
    expect(headlineOf(verdict({ reasons: [reason('a'), reason('b')] }))).toBe('2 things stand between this work item and Done:');
    expect(headlineOf(verdict({ reasons: [reason('a')] }))).toBe('1 thing stands between this work item and Done:');
    expect(headlineOf(verdict({ reasons: ['a', 'b', 'c', 'd'].map(reason) }))).toBe('4 things stand between this work item and Done (the first three below):');
  });

  it('a pass says nothing stands in the way; warn-only and break-glass still name what is open', () => {
    expect(headlineOf(verdict({ state: 'pass' }))).toBe('Nothing stands between this work item and Done or merge.');
    expect(headlineOf(verdict({ state: 'warn', reasons: [reason('a')] }))).toBe('Warn only: Done and merge go through for now, but 1 thing stands in the way.');
    expect(headlineOf(verdict({ state: 'pass', overridden: true, reasons: [reason('a'), reason('b')] }))).toBe('Done and merge are let through by a break-glass override, but 2 things stand in the way.');
  });

  it('no verdict yet, no headline', () => {
    expect(headlineOf(null)).toBeNull();
  });
});
