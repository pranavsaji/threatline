import {
  requirementIdsIn,
  severityRank,
  type FixCheckRecord,
  type FixFinding,
  type FixQuote,
  type Requirement,
  type Result,
  type Threat,
} from '@threatline/shared';
import { FittedFixCheckSchema, fixCheckPrompt, type FixCheckFile, type FixCheckItem, type FixCheckOutput } from '@threatline/prompts';
import { appError, err, ok } from '@threatline/shared';
import { scanForInjection } from './context/injection.js';
import { isSensitive } from './policy.js';
import { callStage, type PipelineDeps, type StageBudget, type Usage } from './pipeline.js';

/**
 * Fix check (docs/FIX_CHECK.md): does the pull request actually fix what the review asked for? CI sends the change's
 * diff; Threatline Engine judges each requirement against it, quoting the added lines that enforce it; code checks every
 * quote and decides. The model can only ever hold a verified requirement for a security champion: "fixed" removes
 * nothing that would otherwise block, and a claim code cannot check counts as not shown.
 */

export interface ChangedLine {
  /** Line number in the new file (0 for a removed line). */
  line: number;
  kind: 'add' | 'context' | 'remove';
  text: string;
}
export interface ChangedFile {
  path: string;
  lines: ChangedLine[];
  added: number;
  binary: boolean;
  deleted: boolean;
}

/** The largest diff CI may send (characters). Over it, the report is refused, never cut silently. */
export const MAX_FIX_DIFF = 200_000;
/** What the model sees at most: the files most likely to hold the fix come first. */
export const FIX_PROMPT_BUDGET = 80_000;
const PER_FILE_BUDGET = 24_000;
const MAX_LINE = 400;
/** Requirements checked in one call (the most severe first). */
export const MAX_FIX_REQUIREMENTS = 20;
/** A pending fix check older than this has failed (the job died): it counts as not shown, never as passed. */
export const FIX_CHECK_TIMEOUT_MS = 30 * 60 * 1000;
const QUOTE_SLACK = 3;

const GENERATED = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|poetry\.lock|Pipfile\.lock|go\.sum|composer\.lock|Gemfile\.lock|gradle\.lockfile)$|\.min\.(js|css)$|\.(map|snap|svg|png|jpe?g|gif|ico|pdf|woff2?|ttf)$|(^|\/)(dist|build|vendor|node_modules|__snapshots__)\//i;
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs)\/|\.(test|spec)\.[a-z]+$|_test\.(go|py)$|(^|\/)test_[^/]+\.py$/i;

/** Parses `git diff` / Bitbucket / GitHub unified diff text into files with new-file line numbers. Never throws. */
export function parseUnifiedDiff(text: string): ChangedFile[] {
  const files: ChangedFile[] = [];
  const st: { cur: ChangedFile | null; newLine: number; oldLeft: number; newLeft: number } = { cur: null, newLine: 0, oldLeft: 0, newLeft: 0 };
  const start = (path: string): ChangedFile => {
    const f: ChangedFile = { path, lines: [], added: 0, binary: false, deleted: false };
    files.push(f);
    st.cur = f;
    return f;
  };
  const strip = (p: string) => p.replace(/^"|"$/g, '').replace(/^[ab]\//, '');
  for (const raw of text.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const cur = st.cur;
    if (cur && (st.oldLeft > 0 || st.newLeft > 0)) {
      const c = line[0];
      const body = line.slice(1);
      if (c === '+' && st.newLeft > 0) {
        cur.lines.push({ line: st.newLine++, kind: 'add', text: body });
        cur.added++;
        st.newLeft--;
        continue;
      }
      if (c === '-' && st.oldLeft > 0) {
        cur.lines.push({ line: 0, kind: 'remove', text: body });
        st.oldLeft--;
        continue;
      }
      if (c === ' ' || line === '') {
        cur.lines.push({ line: st.newLine++, kind: 'context', text: body });
        st.oldLeft = Math.max(0, st.oldLeft - 1);
        st.newLeft = Math.max(0, st.newLeft - 1);
        continue;
      }
      if (c === '\\') continue;
      // Anything else ends the hunk early (a truncated diff): it is read as a header below.
      st.oldLeft = 0;
      st.newLeft = 0;
    }
    if (line.startsWith('diff --git ')) {
      const m = /^diff --git "?a\/(.+?)"? "?b\/(.+?)"?$/.exec(line);
      start(m ? m[2]! : line.slice(11));
      continue;
    }
    if (line.startsWith('--- ')) {
      if (!cur || cur.lines.length > 0) start(strip(line.slice(4).split('\t')[0]!));
      continue;
    }
    if (line.startsWith('+++ ')) {
      const p = line.slice(4).split('\t')[0]!;
      const f = cur ?? start(strip(p));
      if (p === '/dev/null') f.deleted = true;
      else f.path = strip(p);
      continue;
    }
    if (line.startsWith('Binary files ') || line.startsWith('GIT binary patch')) {
      if (cur) cur.binary = true;
      continue;
    }
    const h = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (h) {
      if (!cur) start('(unknown)');
      st.oldLeft = h[1] === undefined ? 1 : Number(h[1]);
      st.newLine = Number(h[2]);
      st.newLeft = h[3] === undefined ? 1 : Number(h[3]);
    }
  }
  return files;
}

/** The requirements a fix check judges: Open, In progress or Verified (never an accepted risk or Not applicable). */
export function fixCheckTargets(requirements: readonly Requirement[]): Requirement[] {
  return requirements
    .filter((r) => r.status === 'Open' || r.status === 'InProgress' || r.status === 'Verified')
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id))
    .slice(0, MAX_FIX_REQUIREMENTS);
}

const render = (l: ChangedLine) => {
  const t = l.text.length > MAX_LINE ? `${l.text.slice(0, MAX_LINE)}…` : l.text;
  return l.kind === 'add' ? `+${l.line} ${t}` : l.kind === 'context' ? ` ${l.line} ${t}` : `-  ${t}`;
};

/**
 * What the model sees, within FIX_PROMPT_BUDGET: generated, binary and deleted files are left out; files a requirement's
 * hints point to come first, then source before tests, larger changes first. A file over its budget is cut at a line.
 */
export function fixCheckFiles(files: readonly ChangedFile[], requirements: readonly Requirement[]): { shown: FixCheckFile[]; omitted: number } {
  const hints = [...new Set(requirements.flatMap((r) => r.fileHints ?? []))];
  const usable = files.filter((f) => !f.binary && !f.deleted && f.added > 0 && !GENERATED.test(f.path));
  const rank = (f: ChangedFile) => (isSensitive(f.path, hints) ? 0 : TEST_PATH.test(f.path) ? 2 : 1);
  const ordered = [...usable].sort((a, b) => rank(a) - rank(b) || b.added - a.added || a.path.localeCompare(b.path));
  const shown: FixCheckFile[] = [];
  let left = FIX_PROMPT_BUDGET;
  for (const f of ordered) {
    if (left < 400) break;
    const cap = Math.min(PER_FILE_BUDGET, left);
    const lines: string[] = [];
    let used = 0;
    for (const l of f.lines) {
      const r = render(l);
      if (used + r.length + 1 > cap) {
        lines.push('… (rest of this file left out)');
        break;
      }
      lines.push(r);
      used += r.length + 1;
    }
    shown.push({ path: f.path, lines });
    left -= used + f.path.length + 40;
  }
  return { shown, omitted: files.length - shown.length };
}

const norm = (s: string) => s.replace(/\s+/g, ' ').trim();
const COMMENT = /^(\/\/|#|\/\*|\*|<!--|--|"""|''')/;
const isComment = (s: string) => COMMENT.test(norm(s));

/**
 * A quote counts when it is code on an added line of that file within ±3 lines of where the model said: at least 8
 * characters (or the whole line), never a comment. Whitespace is ignored.
 */
export function checkQuote(files: readonly ChangedFile[], q: FixQuote): FixQuote | null {
  const want = norm(q.text.replace(/^\+\d*\s?/, ''));
  if (!want || isComment(want)) return null;
  const f = files.find((x) => x.path === q.path);
  if (!f) return null;
  const hit = f.lines.find((l) => l.kind === 'add' && Math.abs(l.line - q.line) <= QUOTE_SLACK && !isComment(l.text) && (norm(l.text) === want || (want.length >= 8 && norm(l.text).includes(want))));
  return hit ? { path: f.path, line: hit.line, text: norm(hit.text).slice(0, 300) } : null;
}

/** Deterministic signals that need no model: tests named for the requirement, and files its hints point to. */
export function fixSignals(files: readonly ChangedFile[], r: Requirement): { testsNamed: number; touchesHints: boolean | null } {
  let testsNamed = 0;
  for (const f of files) for (const l of f.lines) if (l.kind === 'add' && requirementIdsIn(l.text).includes(r.id)) testsNamed++;
  const hints = r.fileHints ?? [];
  return { testsNamed, touchesHints: hints.length === 0 ? null : files.some((f) => !f.deleted && isSensitive(f.path, hints)) };
}

/** The added text of a change, scanned like any untrusted source: text that reads as instructions to an AI. */
export function changeLooksInjected(files: readonly ChangedFile[]): boolean {
  return files.some((f) => scanForInjection(f.lines.filter((l) => l.kind === 'add').map((l) => l.text).join('\n')).suspected);
}

/**
 * Turns the model's reply into findings. Every requirement gets one: no answer, or a "fixed"/"partial" with no quote
 * code can find in the change, is `unclear`. Suggestions are kept only where something is still missing.
 */
export function settleFixCheck(targets: readonly Requirement[], files: readonly ChangedFile[], out: FixCheckOutput | null): FixFinding[] {
  const byId = new Map((out?.results ?? []).map((r) => [r.id, r]));
  return targets.map((req, n) => {
    const signals = fixSignals(files, req);
    const r = byId.get(`R${n + 1}`);
    if (!r) return { requirementId: req.id, verdict: 'unclear', reason: 'The fix check gave no answer for this requirement.', quotes: [], ...signals };
    const quotes = r.quotes.map((q) => checkQuote(files, q)).filter((q): q is FixQuote => q !== null);
    const claimed = r.verdict === 'fixed' || r.verdict === 'partial';
    const verdict = claimed && quotes.length === 0 ? 'unclear' : r.verdict;
    const reason = verdict === 'unclear' ? `None of the check's evidence is added code in this change, so its claim does not count. It said: ${r.reason}`.slice(0, 400) : r.reason;
    const suggestion = verdict !== 'fixed' && r.suggestion ? { suggestion: r.suggestion } : {};
    return { requirementId: req.id, verdict, reason, quotes: verdict === 'unclear' ? [] : quotes, ...(r.missing && verdict !== 'fixed' ? { missing: r.missing } : {}), ...suggestion, ...signals };
  });
}

/** The prompt items: each requirement with its threat's own words, so "fixed" means the attack stops. */
export function fixCheckItems(targets: readonly Requirement[], threats: readonly Threat[]): FixCheckItem[] {
  return targets.map((r, n) => {
    const t = threats.find((x) => x.id === r.threatId);
    return { id: `R${n + 1}`, severity: r.severity, title: r.title, criteria: r.criteria, ...(t ? { threat: `${t.title}. ${t.scenario}`.slice(0, 700) } : {}) };
  });
}

/** Runs the check: one deep-tier call, validated (one repair), then settled by code. */
export async function runFixCheck(
  deps: Pick<PipelineDeps, 'llm' | 'policy'> & { budget?: StageBudget },
  input: { requirements: readonly Requirement[]; threats: readonly Threat[]; diff: string },
  usage: Usage,
  nonce: string,
): Promise<Result<{ findings: FixFinding[]; files: number; omittedFiles: number; injectionSuspected: boolean }>> {
  const files = parseUnifiedDiff(input.diff);
  const targets = fixCheckTargets(input.requirements);
  if (targets.length === 0) return ok({ findings: [], files: files.length, omittedFiles: 0, injectionSuspected: false });
  const { shown, omitted } = fixCheckFiles(files, targets);
  const injectionSuspected = changeLooksInjected(files);
  if (shown.length === 0) {
    const findings = settleFixCheck(targets, files, { results: targets.map((_, n) => ({ id: `R${n + 1}`, verdict: 'not_addressed', reason: 'The change adds no source code Threatline can read.', quotes: [] })) });
    return ok({ findings, files: files.length, omittedFiles: omitted, injectionSuspected });
  }
  const note = omitted > 0 ? `${omitted} other changed file${omitted === 1 ? ' is' : 's are'} not shown` : undefined;
  const p = fixCheckPrompt(fixCheckItems(targets, input.threats), shown, nonce, note);
  const r = await callStage(deps, usage, { ...p, purpose: 'fix_check', tier: 'deep', maxOutputTokens: 12000 }, FittedFixCheckSchema, null);
  if (!r.ok) return r.error.code === 'schema' ? err(appError('schema', 'the fix check reply was not valid after one repair')) : r;
  return ok({ findings: settleFixCheck(targets, files, r.value), files: files.length, omittedFiles: omitted, injectionSuspected });
}

const sameLink = (a: string, b: string) => a.trim().replace(/\/+$/, '').toLowerCase() === b.trim().replace(/\/+$/, '').toLowerCase();

/**
 * Whether a fix check speaks for a requirement's verification: it is Verified by CI in the same repository, or by a
 * pull request link to the same pull request. Evidence from elsewhere (another pull request, a Confluence page, a
 * person's note) is not about this change.
 */
export function fixCheckCovers(record: Pick<FixCheckRecord, 'repo' | 'prUrl'>, req: Requirement): boolean {
  if (req.status !== 'Verified' || !req.evidence) return false;
  const e = req.evidence;
  if (e.kind === 'ci') return !!e.repo && e.repo.toLowerCase() === record.repo.toLowerCase();
  if (e.kind === 'pr') return !!record.prUrl && sameLink(e.ref, record.prUrl);
  return false;
}

export type FixHold = { kind: 'pending' } | { kind: 'unconfirmed'; why: 'not_fixed' | 'partial' | 'unclear' | 'failed' | 'injection' };

/**
 * Deterministic: what a fix check does to one verified requirement. null: nothing (not covered, confirmed by a champion,
 * not part of the check, or shown fixed). A check still running holds it; a failed or timed-out check, a change that
 * looks like it addresses the AI, or anything but "fixed" holds it for a champion.
 */
export function fixHold(record: FixCheckRecord | null | undefined, req: Requirement, now: Date): FixHold | null {
  if (!record || !fixCheckCovers(record, req)) return null;
  if (record.confirmations.some((c) => c.requirementId === req.id)) return null;
  if (record.status === 'pending') return now.getTime() - Date.parse(record.requestedAt) < FIX_CHECK_TIMEOUT_MS ? { kind: 'pending' } : { kind: 'unconfirmed', why: 'failed' };
  if (record.status === 'failed') return { kind: 'unconfirmed', why: 'failed' };
  const f = record.findings.find((x) => x.requirementId === req.id);
  if (!f) return null;
  if (record.injectionSuspected) return { kind: 'unconfirmed', why: 'injection' };
  if (f.verdict === 'fixed') return null;
  return { kind: 'unconfirmed', why: f.verdict === 'partial' ? 'partial' : f.verdict === 'unclear' ? 'unclear' : 'not_fixed' };
}
