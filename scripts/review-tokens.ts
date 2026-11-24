// Measures what one Threatline Engine review sends to and gets back from the model, per stage, from recordings
// already in the repo. It makes no model call: it replays a record set (default evals/results/opus-5-v1.5) through the
// same code the Engine runs (agent runs → assembly → gap check → verifier) and meters every request and reply.
//   pnpm tsx scripts/review-tokens.ts [record-set] [--json out.json]
// The recordings keep reply text only (no usage fields), so tokens are estimated as characters / 4, the same estimate
// the Engine uses to reserve budget (packages/core/src/pipeline.ts). The injection check (balanced tier) is not part of
// the eval: its prompt is rebuilt here exactly (extractPrompt over the case's facts); its reply size comes from the
// earlier pipeline recordings (evals/results/recorded-pipeline, first reply of each case = the extraction).
import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { extractPrompt } from '../packages/prompts/src/index.js';
import { buildReviewContext, renderReviewContext, type LlmPort } from '../packages/core/src/index.js';
import { CLEAN_CASES, POISONED_CASES, type CleanCase } from '../evals/fixtures/cases.js';
import { FRESH_CASES } from '../evals/fixtures/fresh-cases.js';
import { bundleFor, runCase } from '../evals/runner/run.js';
import { loadRecording, replayLlm } from '../evals/runner/recorded.js';

type Stage = 'extract' | 'runs' | 'gaps' | 'verify';
interface Call { inChars: number; outChars: number }
interface CaseUsage { id: string; contextChars: number; injection: boolean; calls: Record<Stage, Call[]> }

const args = process.argv.slice(2);
const set = args.find((a) => !a.startsWith('--')) ?? 'opus-5-v1.5';
const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : undefined;
const dir = join('evals/results', set);
const tok = (chars: number) => Math.ceil(chars / 4);

/** Wraps a replayed model and records the size of every request it is given and every reply it returns. */
function metered(inner: LlmPort, into: Call[]): LlmPort {
  return {
    async complete(req) {
      const r = await inner.complete(req);
      into.push({ inChars: req.system.length + req.user.length, outChars: r.ok ? r.value.text.length : 0 });
      return r;
    },
  };
}

// Extraction replies recorded by the earlier extract→propose design (Sonnet 4.5): their median size stands in for the
// injection check's reply, which the current eval does not record.
const extractReplyChars = (() => {
  const d = 'evals/results/recorded-pipeline';
  if (!existsSync(d)) return 2300;
  const sizes = readdirSync(d)
    .filter((f) => f.endsWith('.json'))
    .map((f) => loadRecording(d, f.replace(/\.json$/, ''))?.replies[0]?.text.length ?? 0)
    .filter((n) => n > 0)
    .sort((a, b) => a - b);
  return sizes[Math.floor(sizes.length / 2)] ?? 2300;
})();

const cases: CleanCase[] = [...CLEAN_CASES, ...POISONED_CASES, ...FRESH_CASES];
const out: CaseUsage[] = [];
for (const c of cases) {
  const runs = loadRecording(join(dir, 'recorded'), c.id);
  if (!runs) continue;
  const gaps = loadRecording(join(dir, 'gaps'), c.id);
  const ver = loadRecording(join(dir, 'verified'), c.id);
  const calls: Record<Stage, Call[]> = { extract: [], runs: [], gaps: [], verify: [] };
  const b = bundleFor(c);
  const x = extractPrompt(b.facts);
  calls.extract.push({ inChars: x.system.length + x.user.length, outChars: extractReplyChars });
  const r = await runCase(
    c,
    metered(replayLlm(runs), calls.runs),
    3,
    'engine',
    true,
    ver ? metered(replayLlm(ver), calls.verify) : null,
    gaps ? metered(replayLlm(gaps), calls.gaps) : null,
  );
  if (!r.ok) {
    console.error(`${c.id}: ${r.error.code} ${r.error.message}`);
    continue;
  }
  const contextChars = renderReviewContext(buildReviewContext(b, { revision: 1 })).length;
  out.push({ id: c.id, contextChars, injection: r.value.injectionSuspected, calls });
}

const sum = (cs: Call[], k: keyof Call) => cs.reduce((n, x) => n + tok(x[k]), 0);
const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)] ?? 0;
};
const median = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : Math.round((s[m - 1]! + s[m]!) / 2);
};
const row = (label: string, xs: number[]) => `| ${label} | ${median(xs).toLocaleString('en-US')} | ${pct(xs, 90).toLocaleString('en-US')} | ${Math.max(...xs).toLocaleString('en-US')} |`;

const stages: Stage[] = ['extract', 'runs', 'gaps', 'verify'];
const lines = [
  `Record set ${set}: ${out.length} cases (${out.filter((c) => c.injection).length} with injection suspected, so no gap check or verifier). Tokens = characters / 4.`,
  `Injection-check reply estimated at ${extractReplyChars.toLocaleString('en-US')} characters (median of the recorded extractions).`,
  '',
  '| Per review | Median | p90 | Max |',
  '| --- | --- | --- | --- |',
];
for (const s of stages) {
  lines.push(row(`${s} input`, out.map((c) => sum(c.calls[s], 'inChars'))));
  lines.push(row(`${s} output`, out.map((c) => sum(c.calls[s], 'outChars'))));
}
lines.push(row('deep tier input (runs + gaps + verify)', out.map((c) => sum(c.calls.runs, 'inChars') + sum(c.calls.gaps, 'inChars') + sum(c.calls.verify, 'inChars'))));
lines.push(row('deep tier output', out.map((c) => sum(c.calls.runs, 'outChars') + sum(c.calls.gaps, 'outChars') + sum(c.calls.verify, 'outChars'))));
lines.push(row('total input', out.map((c) => stages.reduce((n, s) => n + sum(c.calls[s], 'inChars'), 0))));
lines.push(row('total output', out.map((c) => stages.reduce((n, s) => n + sum(c.calls[s], 'outChars'), 0))));
lines.push(row('review context (characters)', out.map((c) => c.contextChars)));
lines.push(row('model calls', out.map((c) => stages.reduce((n, s) => n + c.calls[s].length, 0))));
console.log(lines.join('\n'));
if (jsonOut) writeFileSync(jsonOut, `${JSON.stringify(out, null, 2)}\n`);
