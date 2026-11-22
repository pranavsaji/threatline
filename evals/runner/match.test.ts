import { describe, expect, it } from 'vitest';
import type { LlmPort } from '@threatline/core';
import { ok } from '@threatline/shared';
import { addMatch, emptyTotals, matchCase, parseMatch, type MatchItem } from './match.js';
import { CLEAN_CASES } from '../fixtures/cases.js';

const reply = (text: string): LlmPort => ({ complete: async () => ok({ text, modelId: 'test', tokensIn: 1, tokensOut: 1 }) });
const t = (id: string, severity: MatchItem['severity'] = 'High'): MatchItem => ({ id, stride: 'Spoofing', severity, title: `threat ${id}`, scenario: 's' });

describe('parseMatch', () => {
  it('reads one entry per expected threat, null meaning not found', () => {
    const r = parseMatch('```json\n{"matches":[{"expected":"E1","reported":"T2","reason":"same"},{"expected":"E2","reported":null,"reason":"absent"}]}\n```', ['E1', 'E2'], ['T1', 'T2']);
    expect(r.ok && r.value).toEqual([{ expected: 'E1', reported: 'T2', reason: 'same' }, { expected: 'E2', reported: null, reason: 'absent' }]);
  });
  it('rejects a missing entry, an unknown threat id and a repeated expected id', () => {
    expect(parseMatch('{"matches":[{"expected":"E1","reported":"T1"}]}', ['E1', 'E2'], ['T1']).ok).toBe(false);
    expect(parseMatch('{"matches":[{"expected":"E1","reported":"T9"}]}', ['E1'], ['T1']).ok).toBe(false);
    expect(parseMatch('{"matches":[{"expected":"E1","reported":null},{"expected":"E1","reported":null}]}', ['E1'], ['T1']).ok).toBe(false);
    expect(parseMatch('not json', ['E1'], ['T1']).ok).toBe(false);
  });
  it('lets a reported threat find only one expected threat', () => {
    const r = parseMatch('{"matches":[{"expected":"E1","reported":"T1"},{"expected":"E2","reported":"T1"}]}', ['E1', 'E2'], ['T1']);
    expect(r.ok && r.value.map((m) => m.reported)).toEqual(['T1', null]);
  });
});

describe('matchCase and totals', () => {
  const c = CLEAN_CASES[0]!; // web-01: High, Medium, Medium
  it('nothing reported means nothing found, without a model call', async () => {
    const r = await matchCase({ complete: async () => { throw new Error('must not be called'); } }, c, []);
    expect(r.ok && r.value.every((m) => m.reported === null)).toBe(true);
  });
  it('counts recall, high-severity recall and severity drift', async () => {
    const reported = [t('T1', 'Critical'), t('T2', 'Medium')];
    const r = await matchCase(reply('{"matches":[{"expected":"E1","reported":"T1"},{"expected":"E2","reported":"T2"},{"expected":"E3","reported":null}]}'), c, reported);
    const totals = emptyTotals();
    if (r.ok) addMatch(totals, c, r.value, reported);
    expect(totals).toEqual({ found: 2, expected: 3, highFound: 1, highExpected: 1, severity: { higher: 1, same: 1, lower: 0 } });
  });
});

describe('one retry after a malformed grader reply', () => {
  it('asks again naming the problem, and uses the second reply', async () => {
    const c = CLEAN_CASES[0]!;
    const asked: string[] = [];
    const replies = ['{"matches":[{"expected":"E1","reported":"T1"}]}', `{"matches":[${c.expected.map((_, k) => `{"expected":"E${k + 1}","reported":${k === 0 ? '"T1"' : 'null'},"reason":"r"}`).join(',')}]}`];
    const llm: LlmPort = { complete: async (req) => (asked.push(req.user), ok({ text: replies.shift()!, modelId: 'test', tokensIn: 1, tokensOut: 1 })) };
    const r = await matchCase(llm, c, [t('T1')]);
    expect(r.ok && r.value.map((v) => v.reported)).toEqual(c.expected.map((_, k) => (k === 0 ? 'T1' : null)));
    expect(asked).toHaveLength(2);
    expect(asked[1]).toMatch(/previous reply could not be used .*exactly one entry for each of: E1, E2, E3/);
  });
});
