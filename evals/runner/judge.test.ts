import { describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appError, err, ok } from '@threatline/shared';
import type { LlmPort, LlmRequest } from '@threatline/core';
import { judgeExtras, judgeSystemPrompt, judgeUserPrompt, parseJudge, type JudgeItem } from './judge.js';
import { loadRecording, replayLlm } from './recorded.js';
import { scoreCase, summarize } from './metrics.js';
import { reportMarkdown, runEval } from './run.js';

const item = (id: string, title: string): JudgeItem => ({ id, stride: 'Tampering', severity: 'High', title, scenario: `An attacker ${title.toLowerCase()}.` });
const theCase = { summary: 'Password reset by email link', design: 'Users request a reset link by email.' };

describe('LLM judge for threats outside the must-find list (offline eval only, Task 33)', () => {
  it('the rubric asks for a strict, per-threat verdict and JSON only', () => {
    const s = judgeSystemPrompt();
    expect(s).toMatch(/follows from the design/i);
    expect(s).toMatch(/duplicate/i);
    expect(s).toMatch(/generic/i);
    expect(s).toMatch(/JSON only/i);
  });

  it('the user prompt shows the design, the threats already counted, and the extras by id only', () => {
    const u = judgeUserPrompt(theCase, [item('c1', 'Reset token reuse')], [item('x1', 'CSRF on the reset form')]);
    expect(u).toContain('Users request a reset link by email.');
    expect(u).toContain('Reset token reuse');
    expect(u).toMatch(/x1.*CSRF on the reset form/);
    expect(u).not.toMatch(/must-find|Threatline|model/i);
  });

  it('parseJudge needs exactly one verdict per extra id, and tolerates a fenced reply', () => {
    const good = '```json\n{"verdicts":[{"id":"x1","valid":true,"reason":"specific"},{"id":"x2","valid":false,"reason":"generic"}]}\n```';
    const r = parseJudge(good, ['x1', 'x2']);
    expect(r.ok && r.value.map((v) => v.valid)).toEqual([true, false]);
    expect(parseJudge('{"verdicts":[{"id":"x1","valid":true,"reason":"r"}]}', ['x1', 'x2']).ok).toBe(false);
    expect(parseJudge('{"verdicts":[{"id":"x1","valid":"yes","reason":"r"}]}', ['x1']).ok).toBe(false);
    expect(parseJudge('not json', ['x1']).ok).toBe(false);
  });

  it('judgeExtras makes no call when every reported threat was on the must-find list', async () => {
    let calls = 0;
    const llm: LlmPort = { complete: async () => (calls++, err(appError('upstream', 'x'))) };
    const r = await judgeExtras(llm, theCase, [item('c1', 'a')], []);
    expect(r.ok && r.value).toEqual([]);
    expect(calls).toBe(0);
  });

  it('judgeExtras sends the rubric as the system prompt and returns the verdicts', async () => {
    let seen: LlmRequest | undefined;
    const llm: LlmPort = { complete: async (req) => ((seen = req), ok({ text: '{"verdicts":[{"id":"x1","valid":false,"reason":"duplicate of c1"}]}', modelId: 'm', tokensIn: 1, tokensOut: 1 })) };
    const r = await judgeExtras(llm, theCase, [item('c1', 'a')], [item('x1', 'b')]);
    expect(r.ok && r.value).toEqual([{ id: 'x1', valid: false, reason: 'duplicate of c1' }]);
    expect(seen?.system).toBe(judgeSystemPrompt());
  });

  it('scoreCase reports which predicted threats matched and which are extras', () => {
    const s = scoreCase(
      [{ stride: 'Tampering', title: 'Refund abuse', scenario: '', severity: 'High' }, { stride: 'Repudiation', title: 'No audit log', scenario: '', severity: 'Low' }],
      [{ stride: 'Tampering', title: 'Refund abuse', severity: 'High', keywords: ['refund'] }],
    );
    expect(s.matchedIdx).toEqual([0]);
    expect(s.extraIdx).toEqual([1]);
  });

  it('summarize adds judged precision over judged cases only: (matched + extras judged valid) / reported', () => {
    const base = { highTp: 0, highTotal: 0, perStride: {}, citationValid: 0, citationTotal: 0 };
    const s = summarize([
      { ...base, tp: 2, fp: 8, fn: 0, judgedValid: 6 },
      { ...base, tp: 1, fp: 1, fn: 1 },
    ]);
    expect(s.precision).toBeCloseTo(3 / 12);
    expect(s.judgedPrecision).toBeCloseTo(8 / 10);
    expect(s.judgedCases).toBe(1);
    expect(summarize([{ ...base, tp: 1, fp: 1, fn: 0 }]).judgedPrecision).toBeUndefined();
  });

  it('summarize splits judged precision by origin: model-proposed threats vs the rule-based floor', () => {
    const base = { highTp: 0, highTotal: 0, perStride: {}, citationValid: 0, citationTotal: 0 };
    const s = summarize([
      { ...base, tp: 2, fp: 8, fn: 0, judgedValid: 6, judgedByOrigin: { agent: { tp: 2, extra: 3, valid: 3 }, baseline: { tp: 0, extra: 5, valid: 3 } } },
      { ...base, tp: 1, fp: 1, fn: 0, judgedValid: 0, judgedByOrigin: { agent: { tp: 0, extra: 1, valid: 0 }, baseline: { tp: 1, extra: 0, valid: 0 } } },
    ]);
    expect(s.judgedByOrigin?.agent.precision).toBeCloseTo(5 / 6);
    expect(s.judgedByOrigin?.baseline.precision).toBeCloseTo(4 / 6);
    expect(s.judgedByOrigin?.baseline.extras).toBe(5);
  });

  it('runEval with a judge records its replies, replays them offline, and reports judged precision next to strict', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'threatline-judge-'));
    const proposer: LlmPort = { complete: async (r) => ok({ text: JSON.stringify({ schema: 'threatline.threatmodel.v1', issueKey: /EVAL-\d+/.exec(r.user)![0], threats: [] }), modelId: 'm', tokensIn: 1, tokensOut: 1 }) };
    let judgeCalls = 0;
    const judge: LlmPort = {
      complete: async (r) => {
        judgeCalls++;
        const ids = [...r.user.matchAll(/^- (x\d+)/gm)].map((m) => m[1]!);
        return ok({ text: JSON.stringify({ verdicts: ids.map((id, i) => ({ id, valid: i % 2 === 0, reason: 'r' })) }), modelId: 'j', tokensIn: 1, tokensOut: 1 });
      },
    };
    const live = await runEval({ llm: proposer, llmName: 'claude-code', subset: 5, samples: 1, path: 'agent', judge: { llmFor: () => judge, recordDir: dir } });
    expect(live.ok).toBe(true);
    if (!live.ok) return;
    const replay = await runEval({ llm: proposer, llmName: 'claude-code', subset: 5, samples: 1, path: 'agent', judge: { llmFor: (id) => { const rec = loadRecording(dir, id); return rec ? replayLlm(rec) : null; } } });
    expect(replay.ok && replay.value.summary.judgedPrecision).toBe(live.value.summary.judgedPrecision);
    expect(judgeCalls).toBeGreaterThan(0);
    expect(live.value.summary.judgedPrecision).toBeGreaterThan(live.value.summary.precision);
    expect(reportMarkdown(live.value)).toMatch(/\| Precision, judged \|/);
    expect(reportMarkdown(live.value)).toMatch(/\| Precision, judged: rule-based floor \| \d+\.\d%/);
    expect(live.value.failures).toEqual([]);
  });

  it('a judge failure is reported by case and leaves that case out of judged precision, never counted as valid', async () => {
    const proposer: LlmPort = { complete: async (r) => ok({ text: JSON.stringify({ schema: 'threatline.threatmodel.v1', issueKey: /EVAL-\d+/.exec(r.user)![0], threats: [] }), modelId: 'm', tokensIn: 1, tokensOut: 1 }) };
    const down: LlmPort = { complete: async () => err(appError('upstream', 'claude -p exited with 1')) };
    const r = await runEval({ llm: proposer, llmName: 'claude-code', subset: 5, samples: 1, path: 'agent', judge: { llmFor: () => down } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.failures[0]).toMatch(/^judge web-01: upstream \(/);
    const withExtras = r.value.perCase.filter((c) => c.fp > 0 && c.injectionHeld === undefined);
    expect(r.value.failures).toHaveLength(withExtras.length);
    expect(withExtras.every((c) => c.judgedValid === undefined)).toBe(true);
    // Only cases with nothing to grade count as judged; a failed judge never inflates judged precision.
    expect(r.value.summary.judgedCases ?? 0).toBe(r.value.perCase.filter((c) => c.fp === 0 && c.injectionHeld === undefined).length);
    expect(reportMarkdown(r.value)).toMatch(new RegExp(`incomplete: ${withExtras.length} not judged`));
  });
});

describe('one retry after a malformed judge reply', () => {
  it('asks again naming the ids, and uses the second reply', async () => {
    const asked: string[] = [];
    const replies = ['{"verdicts":[{"id":"x1","valid":true}]}', '{"verdicts":[{"id":"x1","valid":true,"reason":"r"},{"id":"x2","valid":false,"reason":"r"}]}'];
    const llm: LlmPort = { complete: async (req: LlmRequest) => (asked.push(req.user), ok({ text: replies.shift()!, modelId: 'test', tokensIn: 1, tokensOut: 1 })) };
    const r = await judgeExtras(llm, theCase, [], [item('x1', 'Forges a token'), item('x2', 'Replays a link')]);
    expect(r.ok && r.value.map((v) => v.valid)).toEqual([true, false]);
    expect(asked[1]).toMatch(/exactly one entry for each of: x1, x2/);
  });
  it('does not retry an error that is not about the reply format', async () => {
    let calls = 0;
    const llm: LlmPort = { complete: async () => (calls++, err(appError('timeout', 'slow'))) };
    expect((await judgeExtras(llm, theCase, [], [item('x1', 'Forges a token')])).ok).toBe(false);
    expect(calls).toBe(1);
  });
});
