import { runFixCheck, type LlmPort, type Usage } from '@threatline/core';
import { FIX_CHECK_PROMPT_VERSION } from '@threatline/prompts';
import type { FixVerdict, Requirement } from '@threatline/shared';
import { FIX_CASES, type FixCase, type FixLabel } from '../fixtures/fix-cases.js';
import { loadRecording, recordingLlm, replayLlm, saveRecording } from './recorded.js';

/**
 * Fix-check eval (docs/FIX_CHECK.md): every case through the product's own runFixCheck (prompt, validation, quote check,
 * settlement), live through `claude -p` (recorded) or replayed from the recordings. The number that matters most is
 * false fixes: a change that does not fix the requirement called fixed. The product treats every other mistake as a
 * hold a champion can clear, so it is safe; a false fix lets a fake fix through, so the gate allows none.
 */
export const FIX_RECORD_DIR = 'evals/results/fix-check';
const REQ_ID = 'req_1a2b3c4d5e6f7a8b';

export interface FixCaseResult {
  id: string;
  language: string;
  expected: FixLabel;
  got: FixVerdict | 'error';
  ok: boolean;
  exact: boolean;
  falseFix: boolean;
  missedFix: boolean;
  quotes: number;
  injectionFlagged: boolean;
  reason: string;
  why: string;
}
export interface FixEvalReport {
  promptVersion: string;
  model: string;
  cases: number;
  acceptable: number;
  exact: number;
  falseFixes: number;
  missedFixes: number;
  errors: number;
  results: FixCaseResult[];
}

export const toRequirement = (c: FixCase): Requirement => ({
  id: REQ_ID, threatId: 'thr_1', issueId: '1', issueKey: 'PAY-7', title: c.requirement.title, severity: c.requirement.severity, status: 'Verified',
  criteria: [{ given: c.requirement.given, when: c.requirement.when, then: c.requirement.then }], asvsIds: [], ...(c.requirement.fileHints ? { fileHints: c.requirement.fileHints } : {}),
});

const POLICY_BUDGET = { budget: { tokensInPerReview: 400_000, tokensOutPerReview: 60_000 } };

export async function runFixEval(o: { live?: LlmPort; mode: 'live' | 'recorded' | 'resume'; model: string; only?: string[]; dir?: string }): Promise<FixEvalReport> {
  const dir = o.dir ?? FIX_RECORD_DIR;
  const results: FixCaseResult[] = [];
  for (const c of FIX_CASES.filter((x) => !o.only || o.only.includes(x.id))) {
    const rec = o.mode !== 'live' ? loadRecording(dir, c.id) : null;
    const recorder = !rec && o.live ? recordingLlm(o.live) : null;
    const llm = rec ? replayLlm(rec) : recorder?.llm;
    const usage: Usage = { tokensIn: 0, tokensOut: 0, modelIds: new Set() };
    const threat = { id: 'thr_1', title: c.requirement.threat, scenario: '' } as unknown as Parameters<typeof runFixCheck>[1]['threats'][number];
    const r = llm
      ? await runFixCheck({ llm, policy: POLICY_BUDGET as never }, { requirements: [toRequirement(c)], threats: [threat], diff: c.diff }, usage, 'evalnonce01')
      : null;
    if (recorder && r?.ok) saveRecording(dir, { caseId: c.id, promptVersion: FIX_CHECK_PROMPT_VERSION, replies: recorder.replies() });
    const f = r?.ok ? r.value.findings[0] : undefined;
    const got: FixVerdict | 'error' = f ? f.verdict : 'error';
    const notFixed = got !== 'fixed';
    results.push({
      id: c.id, language: c.language, expected: c.expected, got,
      exact: got === c.expected,
      // `unclear` is a hold, like not_addressed: acceptable wherever the reviewer says it is not fixed.
      ok: got === c.expected || (got !== 'error' && (c.acceptable ?? []).includes(got as FixLabel)) || (got === 'unclear' && c.expected !== 'fixed'),
      falseFix: c.expected !== 'fixed' && got === 'fixed',
      missedFix: c.expected === 'fixed' && notFixed,
      quotes: f?.quotes.length ?? 0,
      injectionFlagged: r?.ok ? r.value.injectionSuspected : false,
      reason: f?.reason ?? (r && !r.ok ? r.error.code : 'no recording'),
      why: c.why,
    });
  }
  return {
    promptVersion: FIX_CHECK_PROMPT_VERSION,
    model: o.model,
    cases: results.length,
    acceptable: results.filter((x) => x.ok).length,
    exact: results.filter((x) => x.exact).length,
    falseFixes: results.filter((x) => x.falseFix).length,
    missedFixes: results.filter((x) => x.missedFix).length,
    errors: results.filter((x) => x.got === 'error').length,
    results,
  };
}

export function fixReportMarkdown(r: FixEvalReport, date: string): string {
  const pct = (n: number) => `${((n / Math.max(1, r.cases)) * 100).toFixed(1)}%`;
  const fixedCases = r.results.filter((x) => x.expected === 'fixed').length;
  return [
    `# Fix-check eval, ${date}`,
    '',
    `Model \`${r.model}\`, prompt ${r.promptVersion}, ${r.cases} cases (\`evals/fixtures/fix-cases.ts\`), through the product's own \`runFixCheck\` (validation, quote check, settlement).`,
    '',
    '| Measure | Result |',
    '| --- | --- |',
    `| False fixes (a change that does not fix it, called fixed) | **${r.falseFixes} of ${r.cases - fixedCases}** |`,
    `| Verdict a reviewer would accept | ${r.acceptable} of ${r.cases} (${pct(r.acceptable)}) |`,
    `| Exactly the reviewer's verdict | ${r.exact} of ${r.cases} (${pct(r.exact)}) |`,
    `| Real fixes held for a champion | ${r.missedFixes} of ${fixedCases} |`,
    `| Errors | ${r.errors} |`,
    '',
    '| Case | Language | Expected | Got | Quotes | Why the case exists |',
    '| --- | --- | --- | --- | --- | --- |',
    ...r.results.map((x) => `| ${x.id}${x.ok ? '' : ' ✗'} | ${x.language} | ${x.expected} | ${x.got}${x.injectionFlagged ? ' (injection flagged)' : ''} | ${x.quotes} | ${x.why} |`),
    '',
  ].join('\n');
}
