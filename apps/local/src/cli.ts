#!/usr/bin/env tsx
/**
 * Offline harness: `pnpm threatline <command>`.
 *   review <caseId> [--llm fake|claude-code] [--samples 3] [--model m] [--path agent|pipeline|engine] [--yes]
 *   eval [--subset all|<n>] [--llm fake|claude-code|recorded] [--samples 3] [--model m] [--path agent|pipeline|engine] [--concurrency 1] [--yes]
 *        [--write-baseline] [--gate evals/results/baseline.json] [--resume] [--judge claude-code|recorded] [--record-set name] [--judge-model m]
 *        [--verify recorded|claude-code|resume] [--no-coverage] [--annotate-judged]
 *     --judge grades every reported threat outside a case's must-find list with a separate claude -p call (recorded
 *     into evals/results/judged/), so the report shows judged precision next to strict precision.
 *     claude-code runs record every raw reply into evals/results/recorded/; `--llm recorded` replays them offline (CI).
 *     --path engine adds the Engine's verifier: --verify recorded (default) replays its verdicts, claude-code calls it
 *     live on --model, resume calls it only for cases without a recorded verdict (both live modes ask first).
 *   rematch --record-set <name> [--subset 30|all|holdout] [--match claude-code|recorded|resume] [--match-model m] [--concurrency 4] [--yes]
 *     replays a recorded Engine run and has a separate claude -p call decide which reported threat finds each must-find
 *     threat (recorded into evals/results/<name>/matched/), so recall is not limited by the keyword matcher.
 *   sign-demo
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { decodeAttestation, generateKeyPair } from '@threatline/crypto';
import { claudeCodeLlm } from '@threatline/llm-dev';
import { computeVerdict, DEFAULT_SITE_POLICY, issueAttestation, type LlmPort } from '@threatline/core';
import { CLEAN_CASES, POISONED_CASES } from '../../../evals/fixtures/cases.js';
import { reportMarkdown, runCase, runEval, selectCases, type EvalPath } from '../../../evals/runner/run.js';
import { scoreCase } from '../../../evals/runner/metrics.js';
import { gateCheck, loadRecording, recordingLlm, replayLlm, saveRecording } from '../../../evals/runner/recorded.js';
import { addMatch, emptyTotals, matchCase, MATCH_VERSION, parseMatch, type MatchItem } from '../../../evals/runner/match.js';

const AGENT_RECORDED = 'evals/results/recorded';
const BASELINE = 'evals/results/baseline.json';
const AGENT_JUDGED = 'evals/results/judged';

const argv = process.argv.slice(2);
const flag = (name: string, def?: string) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : def;
};
const has = (name: string) => argv.includes(`--${name}`);

/** eval's `--subset`: `all` or a positive whole number of cases. Anything else used to become NaN and select no case. */
export function evalSubset(raw: string | undefined): number | 'all' {
  if (raw === 'all') return 'all';
  if (raw !== undefined && /^[1-9]\d*$/.test(raw)) return Number(raw);
  throw new Error(`--subset takes all or a positive whole number of cases, not "${(raw ?? '').slice(0, 20)}"`);
}

/** rematch's `--subset`: every clean case, the 30-case tuning set, or the held-out rest. */
export function rematchSubset(raw: string | undefined): 'all' | '30' | 'holdout' {
  if (raw === 'all' || raw === '30' || raw === 'holdout') return raw;
  throw new Error(`rematch --subset takes all, 30 or holdout, not "${(raw ?? '').slice(0, 20)}"`);
}

/** The Engine verifier's mode (`--verify`, path engine): recorded replays; claude-code and resume call claude -p live. */
export function verifyMode(raw: string | undefined): { mode: 'recorded' | 'claude-code' | 'resume'; live: boolean } {
  if (raw === 'recorded' || raw === 'claude-code' || raw === 'resume') return { mode: raw, live: raw !== 'recorded' };
  throw new Error(`--verify takes recorded, claude-code or resume, not "${(raw ?? '').slice(0, 20)}"`);
}

async function confirm(calls: number, model: string): Promise<boolean> {
  if (has('yes')) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const a = await rl.question(`This will make ${calls} \`claude -p\` call(s) on ${model} under your Claude subscription. Continue? [y/N] `);
  rl.close();
  return a.trim().toLowerCase() === 'y';
}

function llmFrom(): { llm: LlmPort | null; name: string; model: string } {
  const which = flag('llm', 'fake');
  const model = flag('model', 'claude-sonnet-4-5')!;
  if (which === 'claude-code') return { llm: claudeCodeLlm({ model }), name: 'claude-code', model };
  return { llm: null, name: 'fake', model: 'none' };
}

async function main() {
  const cmd = argv[0];
  const samples = Number(flag('samples', '3'));
  const path = (flag('path', 'agent') as EvalPath) ?? 'agent';
  // Threatline Engine (pipeline path) keeps its own recordings, so the agent path's offline CI gate is never overwritten.
  // Path `engine` replays the agent runs (same recordings) and adds the verifier; the earlier extract→propose design
  // (`pipeline`) keeps its own. Judge verdicts are matched by threat title, so `engine` reuses the agent path's.
  // `--record-set <name>` keeps a model's recordings in evals/results/<name>/, so measuring another model (for example
  // the Engine's production model) never overwrites the recordings the offline CI gate replays.
  const set = flag('record-set');
  if (set !== undefined && !/^[a-z0-9][a-z0-9.-]*$/.test(set)) throw new Error('--record-set takes a lowercase name like opus-5');
  const RECORDED = set ? `evals/results/${set}/recorded` : path === 'pipeline' ? 'evals/results/recorded-pipeline' : AGENT_RECORDED;
  const JUDGED = set ? `evals/results/${set}/judged` : path === 'pipeline' ? 'evals/results/judged-pipeline' : AGENT_JUDGED;
  const VERIFIED = set ? `evals/results/${set}/verified` : 'evals/results/verified-engine';
  if (cmd === 'review') {
    const id = argv[1];
    const c = [...CLEAN_CASES, ...POISONED_CASES].find((x) => x.id === id);
    if (!c) throw new Error(`unknown case ${id}; try one of: ${CLEAN_CASES.slice(0, 5).map((x) => x.id).join(', ')}…`);
    const { llm, name, model } = llmFrom();
    if (llm && !(await confirm(samples * (path === 'pipeline' ? 2 : 1), model))) return;
    const r = await runCase(c, llm, samples, path);
    if (!r.ok) throw new Error(`${r.error.code}: ${r.error.message}`);
    console.log(`\n${c.id} — ${c.summary}  [${name}${r.value.modelIds.length ? `: ${r.value.modelIds.join(', ')}` : ''}]`);
    console.log(`risk score ${r.value.riskScore} · blocking ${r.value.blocking} · injection suspected ${r.value.injectionSuspected}`);
    for (const t of r.value.threats) console.log(`  ${t.severity.padEnd(8)} ${t.state.padEnd(11)} ${t.stride.padEnd(22)} ${t.title}  (${t.origin}, ${t.votes}/${t.samples})`);
    if (r.value.modelIds.length) {
      mkdirSync('evals/results', { recursive: true });
      writeFileSync('evals/results/MODEL.md', `Model used by claude -p: ${r.value.modelIds.join(', ')} (${new Date().toISOString()})\n`);
    }
    return;
  }
  if (cmd === 'eval') {
    const subset = evalSubset(flag('subset', 'all'));
    const { llm, name, model } = llmFrom();
    const sel = selectCases(subset);
    const n = sel.clean.length + sel.poisoned.length;
    if (llm && !(await confirm(n * samples * (path === 'pipeline' ? 2 : 1), model))) return;
    // The Engine's verifier makes its own claude -p calls even when the reviews are replayed (`--llm recorded`).
    const verify = path === 'engine' ? verifyMode(flag('verify', 'recorded')) : null;
    const verifyModel = flag('model', 'claude-sonnet-4-5')!;
    if (verify?.live && !(await confirm(n, `${verifyModel} (verifier, at most one call per case${verify.mode === 'resume' ? ' without a recorded verdict' : ''})`))) return;
    const recorded = flag('llm') === 'recorded';
    const judgeWith = flag('judge');
    // The judge always runs on a real model, even when the reviews are replayed (`--llm recorded` has model "none").
    // `--judge-model` keeps the judge fixed while the reviewed model changes, so judged precision stays comparable.
    const judgeModel = flag('judge-model', flag('model', 'claude-sonnet-4-5'))!;
    const judgeLive = judgeWith === 'claude-code' ? claudeCodeLlm({ model: judgeModel }) : null;
    if (judgeLive && !(await confirm(sel.clean.length, `${judgeModel} (judge, at most one call per clean case)`))) return;
    const judgeFor = (id: string) => {
      const rec = judgeWith === 'recorded' || has('resume') ? loadRecording(JUDGED, id) : null;
      return rec ? replayLlm(rec) : judgeLive;
    };
    const r = await runEval({
      llm,
      llmName: recorded ? 'recorded' : name,
      subset,
      samples,
      path,
      concurrency: Number(flag('concurrency', '1')),
      onProgress: (d, t) => process.stderr.write(`\r${d}/${t}`),
      ...(llm ? { recordDir: RECORDED, resume: has('resume') } : {}),
      ...(recorded ? { llmFor: (id: string) => { const rec = loadRecording(RECORDED, id); return rec ? replayLlm(rec) : null; } } : {}),
      ...(judgeWith
        ? {
            judge: {
              llmFor: judgeFor,
              recordingFor: (id: string) => loadRecording(JUDGED, id),
              ...(judgeLive ? { recordDir: JUDGED, live: judgeLive } : {}),
              ...(has('annotate-judged') ? { annotateDir: JUDGED } : {}),
            },
          }
        : {}),
      ...(has('no-coverage') ? { coverage: false } : {}),
      ...(verify
        ? (() => {
            const which = verify.mode;
            // `resume`: replay recorded verdicts, and call the model (recording it) only for cases without a recording.
            const live = verify.live ? claudeCodeLlm({ model: verifyModel }) : null;
            const replayedVerify = new Set<string>();
            return {
              verify: {
                llmFor: (id: string) => {
                  const rec = which === 'recorded' || which === 'resume' ? loadRecording(VERIFIED, id) : null;
                  if (rec) replayedVerify.add(id);
                  return rec ? replayLlm(rec) : live;
                },
                ...(live ? { recordDir: VERIFIED } : {}),
                ...(which === 'resume' ? { replayed: (id: string) => replayedVerify.has(id) } : {}),
              },
            };
          })()
        : {}),
    });
    process.stderr.write('\n');
    if (!r.ok) throw new Error(`${r.error.code}: ${r.error.message}`);
    mkdirSync('evals/results', { recursive: true });
    const base = `evals/results/${r.value.date}-${recorded ? 'recorded' : name}-${subset}${path === 'pipeline' ? '-pipeline' : path === 'engine' ? '-engine' : ''}${set ? `-${set}` : ''}`;
    writeFileSync(`${base}.json`, JSON.stringify(r.value, null, 2));
    writeFileSync(`${base}.md`, reportMarkdown(r.value));
    console.log(reportMarkdown(r.value));
    console.log(`wrote ${base}.json and ${base}.md`);
    if (has('write-baseline')) {
      writeFileSync(BASELINE, `${JSON.stringify({ label: r.value.label, promptVersion: r.value.promptVersion, subset, samples, modelIds: r.value.modelIds, summary: r.value.summary }, null, 2)}\n`);
      console.log(`wrote ${BASELINE}`);
    }
    const gate = flag('gate');
    if (gate) {
      const g = gateCheck(r.value.summary, (JSON.parse(readFileSync(gate, 'utf8')) as { summary: Parameters<typeof gateCheck>[1] }).summary);
      console.log(g.message);
      if (!g.ok || r.value.failures.length > 0) process.exit(1);
    }
    return;
  }
  if (cmd === 'rematch') {
    const set = flag('record-set');
    if (!set || !/^[a-z0-9][a-z0-9.-]*$/.test(set)) throw new Error('rematch needs --record-set <name>, for example opus-5');
    const which = rematchSubset(flag('subset', 'all'));
    const tuning = new Set(selectCases(30).clean.map((c) => c.id));
    const clean = which === 'all' ? CLEAN_CASES : which === 'holdout' ? CLEAN_CASES.filter((c) => !tuning.has(c.id)) : CLEAN_CASES.filter((c) => tuning.has(c.id));
    const dir = `evals/results/${set}`;
    const mode = flag('match', 'recorded');
    const model = flag('match-model', 'claude-sonnet-4-5')!;
    if (mode !== 'recorded' && !(await confirm(clean.length, `${model} (match judge, one call per clean case)`))) return;
    const totals = emptyTotals();
    const keyword = { found: 0, expected: 0 };
    const rows: string[] = [];
    const missing: string[] = [];
    const conc = Math.max(1, Number(flag('concurrency', '4')));
    for (let i = 0; i < clean.length; i += conc) {
      await Promise.all(
        clean.slice(i, i + conc).map(async (c) => {
          const rec = loadRecording(`${dir}/recorded`, c.id);
          if (!rec) return void missing.push(`${c.id}: no review recording`);
          const ver = loadRecording(`${dir}/verified`, c.id);
          const run = await runCase(c, replayLlm(rec), rec.replies.length, 'engine', true, ver ? replayLlm(ver) : null);
          if (!run.ok) return void missing.push(`${c.id}: ${run.error.code}`);
          const shown = run.value.threats.filter((t) => t.state === 'accepted' || t.state === 'needs_human');
          const reported: MatchItem[] = shown.map((t, n) => ({ id: `T${n + 1}`, stride: t.stride, severity: t.severity, title: t.title, scenario: t.scenario }));
          const kw = scoreCase(shown, c.expected);
          keyword.found += kw.tp;
          keyword.expected += c.expected.length;
          let saved = mode === 'recorded' || mode === 'resume' ? loadRecording(`${dir}/matched`, c.id) : null;
          // Recorded verdicts name threats by position; the list they rated is saved with them, so each verdict is
          // matched to today's list by STRIDE and title. A verdict whose threat is no longer listed under that title is
          // stale (the threat may have been renamed, not lost): re-graded live under `resume`, otherwise not graded.
          const remapped = (() => {
            if (!saved?.items || !saved.replies[0]) return null;
            const p = parseMatch(saved.replies[saved.replies.length - 1]!.text, c.expected.map((_, k) => `E${k + 1}`), saved.items.map((x) => x.id));
            if (!p.ok) return null;
            const value = p.value.map((m) => {
              const was = m.reported ? saved!.items!.find((x) => x.id === m.reported) : undefined;
              const now = was ? reported.find((x) => x.stride === was.stride && x.title === was.title) : undefined;
              return { ...m, reported: now ? now.id : null, stale: Boolean(was && !now) };
            });
            return value.some((m) => m.stale) ? 'stale' : value.map(({ stale: _, ...m }) => m);
          })();
          if (remapped === 'stale') {
            if (mode !== 'resume') return void missing.push(`${c.id}: stale match recording (re-grade with --match resume)`);
            saved = null;
          }
          const live = mode === 'claude-code' || (mode === 'resume' && !saved) ? recordingLlm(claudeCodeLlm({ model })) : null;
          let v: Awaited<ReturnType<typeof matchCase>>;
          if (remapped && remapped !== 'stale') {
            v = { ok: true as const, value: remapped };
          } else {
            const llm = saved ? replayLlm(saved) : live?.llm;
            if (!llm) return void missing.push(`${c.id}: no match recording`);
            v = await matchCase(llm, c, reported);
          }
          if (!v.ok) return void missing.push(`${c.id}: match ${v.error.code} (${v.error.message})`);
          if (live && live.replies().length) saveRecording(`${dir}/matched`, { caseId: c.id, promptVersion: MATCH_VERSION, replies: live.replies(), items: reported.map((x) => ({ id: x.id, stride: x.stride, title: x.title })) });
          addMatch(totals, c, v.value, reported);
          v.value.forEach((m, k) => {
            if (!m.reported) rows.push(`| ${c.id} | ${c.expected[k]!.severity} | ${c.expected[k]!.title} | ${m.reason.replace(/\|/g, '/')} |`);
          });
        }),
      );
      process.stderr.write(`${Math.min(i + conc, clean.length)}/${clean.length}\r`);
    }
    const pct = (a: number, b: number) => (b ? `${((a / b) * 100).toFixed(1)}%` : 'n/a');
    const date = new Date().toISOString().slice(0, 10);
    const md = `# Threatline recall, judged — ${set}, ${which} (${date})

_Each must-find threat graded by a separate ${model} call (${MATCH_VERSION}) against the threats the review showed;
replayed from \`evals/results/${set}/\`. ${clean.length - missing.length} of ${clean.length} clean cases graded._

| Metric | Judged | Keyword matcher |
| --- | --- | --- |
| Recall | ${pct(totals.found, totals.expected)} (${totals.found} of ${totals.expected}) | ${pct(keyword.found, keyword.expected)} (${keyword.found} of ${keyword.expected}) |
| High-severity recall | ${pct(totals.highFound, totals.highExpected)} (${totals.highFound} of ${totals.highExpected}) | |
| Severity vs expected (found threats) | ${totals.severity.higher} higher, ${totals.severity.same} same, ${totals.severity.lower} lower | |

Not found:

| Case | Expected severity | Expected threat | Judge's reason |
| --- | --- | --- | --- |
${rows.sort().join('\n') || '| — | | | |'}
${missing.length ? `\nNot graded: ${missing.sort().join('; ')}\n` : ''}`;
    const base = `evals/results/${date}-match-${set}-${which}`;
    writeFileSync(`${base}.md`, md);
    writeFileSync(`${base}.json`, JSON.stringify({ set, subset: which, model, version: MATCH_VERSION, date, totals, keyword, missing }, null, 2));
    console.log(md);
    console.log(`wrote ${base}.md and ${base}.json`);
    return;
  }
  if (cmd === 'sign-demo') {
    const key = generateKeyPair();
    const nowSec = Math.floor(Date.now() / 1000);
    const verdict = computeVerdict({ review: { id: 'rev_demo', issueId: '1', issueKey: 'PROJ-142', revision: 1, status: 'ready', contextHash: 'h', riskScore: 40, partial: false, promptVersion: 'v1', modelIds: [], samplesExpected: 3, samplesReceived: 3, tokensIn: 0, tokensOut: 0, createdAt: 't', updatedAt: 't' }, currentContextHash: 'h', threats: [], requirements: [], acceptances: [], policy: DEFAULT_SITE_POLICY, projectKey: 'PROJ', championConfirmations: [], breakGlass: [], budgetPaused: false, injectionSuspected: false, now: new Date(), panelUrl: 'https://example' });
    const att = issueAttestation({ issueKey: 'PROJ-142', repo: 'acme/shop', commitSha: 'a'.repeat(40), verdict, requirements: [], key, nowSec, ttlHours: 24 });
    if (!att.ok) throw new Error(att.error.message);
    const keys = { [key.kid]: key.publicKey };
    const tok = att.value.token;
    const i = Math.floor(tok.length / 2);
    const tampered = tok.slice(0, i) + (tok[i] === 'A' ? 'B' : 'A') + tok.slice(i + 1);
    console.log(`public key (${key.kid}): ${key.publicKey}\n\nattestation:\n${tok}\n`);
    console.log('verify original →', decodeAttestation(tok, keys, nowSec).ok ? 'PASS' : 'FAIL');
    const t = decodeAttestation(tampered, keys, nowSec);
    console.log('verify with one character changed →', t.ok ? 'PASS (unexpected!)' : `FAIL: ${t.error.message}`);
    return;
  }
  console.log(
    'usage: pnpm threatline review <caseId> | eval [--subset all|<n>] [--path agent|pipeline|engine] [--verify recorded|claude-code|resume] | rematch --record-set <name> [--subset all|30|holdout] [--match recorded|claude-code|resume] | sign-demo   (add --llm claude-code to use your Claude subscription; every live call asks first unless --yes)',
  );
}

// Run only as the entry point, so tests can import the argument parsers above without starting a command.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch((e: unknown) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
