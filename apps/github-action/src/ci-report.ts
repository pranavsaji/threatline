import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { explicitIssueKeys, namedIssueKeys, requirementIdsIn } from '@threatline/shared/ci';
import { parseJUnit, type TestCase } from './junit.js';

/**
 * Verification from CI, client side (docs/CI_VERIFICATION.md), shared by the GitHub Action and the Bitbucket Pipelines
 * script (scripts/threatline-ci-report.mjs is built from this): read JUnit XML, keep the tests whose names carry a
 * requirement id, and post them to Threatline's `ci-verify` web trigger once per named work item. Results are never
 * dropped to make a report fit (a dropped failure could verify a requirement), so an oversized report fails instead.
 * Configuration problems fail the step; a busy or unreachable Threatline only warns, because nothing is verified
 * then and the Done gate stays closed.
 */
export interface CiReportInput {
  url: string;
  token: string;
  /** JUnit XML globs, one per line, relative to `root`. */
  junit: string;
  root: string;
  issueKeys: string[];
  repo: string;
  commitSha: string;
  runUrl: string;
  /**
   * Fix check (docs/FIX_CHECK.md): also send the pull request's change (`git diff base...head`), so Threatline checks
   * whether it fixes each requirement. `base` is the pull request's base commit; `prUrl` its https link.
   */
  fixCheck?: { base: string; prUrl?: string };
  /** Runs git with these arguments in `root` and returns stdout (injected in tests). */
  git?: (args: string[]) => string;
  fetch?: typeof fetch;
}
export interface CiReportOutcome {
  success: boolean;
  /** True when the step passes but the report did not get through (or there was nothing to report). */
  warning?: boolean;
  message: string;
  lines: string[];
}
interface ServerResult {
  requirementId: string;
  outcome: string;
  passed: number;
  failed: number;
  skipped: number;
  message?: string;
}

const MAX_BODY_BYTES = 256 * 1024;
const MAX_FILES = 500;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 100_000;
const MAX_KEYS = 5;
const SKIP_DIRS = new Set(['node_modules', '.git']);
const TIMEOUT_MS = 30_000;

/** A path glob → RegExp over `/`-separated relative paths: `**`, `*`, `?` and `{a,b}`. */
export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === '*' && glob[i + 1] === '*') {
      i++;
      if (glob[i + 1] === '/') {
        i++;
        re += '(?:.*/)?';
      } else re += '.*';
    } else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '{') {
      const close = glob.indexOf('}', i);
      if (close === -1) re += '\\{';
      else {
        re += `(?:${glob.slice(i + 1, close).split(',').map((p) => p.replace(/[.+^${}()|[\]\\*?]/g, '\\$&')).join('|')})`;
        i = close;
      }
    } else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

/** Files under `root` matching any of the globs (one per line), sorted; symlinks, node_modules and .git are skipped. */
export function findJUnitFiles(root: string, globs: string): string[] {
  const patterns = globs.split('\n').map((g) => g.trim().replace(/^\.\//, '')).filter(Boolean).map(globToRegExp);
  const found: string[] = [];
  let seen = 0;
  const walk = (dir: string, rel: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (++seen > MAX_ENTRIES) throw new Error(`more than ${MAX_ENTRIES} files to search; narrow the junit glob`);
      const path = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory() && !SKIP_DIRS.has(e.name)) walk(join(dir, e.name), path);
      else if (e.isFile() && patterns.some((p) => p.test(path))) found.push(path);
    }
  };
  walk(root, '');
  return found.sort();
}

/** The parts of a GitHub event the report reads. */
export interface GitHubEventLike {
  pull_request?: { title?: string; html_url?: string; head?: { ref?: string; sha?: string }; base?: { sha?: string } };
}

/**
 * The GitHub Action's report settings, or null when the report inputs are not set. The work item comes from the pull
 * request title and branch, exactly as the merge gate finds it (namedIssueKeys); on a push, from the branch name.
 */
export function actionReportConfig(
  inputs: { url?: string; token?: string; junit?: string; fixCheck?: string },
  env: Record<string, string | undefined>,
  event: GitHubEventLike,
): { ok: true; value: Omit<CiReportInput, 'fetch'> | null } | { ok: false; message: string } {
  const url = (inputs.url ?? '').trim();
  const token = (inputs.token ?? '').trim();
  const junit = (inputs.junit ?? '').trim();
  const fix = (inputs.fixCheck ?? '').trim().toLowerCase() || 'false';
  if (fix !== 'true' && fix !== 'false') return { ok: false, message: 'Threatline: fix-check must be true or false.' };
  if (!url && !token && !junit && fix === 'false') return { ok: true, value: null };
  if (!url || !token || (!junit && fix === 'false')) return { ok: false, message: 'Threatline: to report to Threatline, set threatline-url, threatline-token (a secret), and junit, fix-check: true, or both.' };
  const pr = event.pull_request;
  if (fix === 'true' && !pr?.base?.sha) return { ok: false, message: 'Threatline: fix-check runs on pull_request events (it checks the pull request\'s change). Run this step on pull_request.' };
  const branch = pr?.head?.ref ?? (env.GITHUB_HEAD_REF || env.GITHUB_REF_NAME || '');
  const repo = env.GITHUB_REPOSITORY ?? '';
  const attempt = Number(env.GITHUB_RUN_ATTEMPT ?? '1');
  const runUrl = `${(env.GITHUB_SERVER_URL ?? 'https://github.com').replace(/\/+$/, '')}/${repo}/actions/runs/${env.GITHUB_RUN_ID ?? ''}${attempt > 1 ? `/attempts/${attempt}` : ''}`;
  return {
    ok: true,
    value: {
      url, token, junit, root: env.GITHUB_WORKSPACE || process.cwd(), issueKeys: namedIssueKeys(pr?.title ?? '', branch), repo, commitSha: pr?.head?.sha ?? env.GITHUB_SHA ?? '', runUrl,
      ...(fix === 'true' && pr?.base?.sha ? { fixCheck: { base: pr.base.sha, ...(pr.html_url?.startsWith('https://') ? { prUrl: pr.html_url } : {}) } } : {}),
    },
  };
}

const fail = (message: string, lines: string[] = []): CiReportOutcome => ({ success: false, message, lines });
const warn = (message: string, lines: string[] = []): CiReportOutcome => ({ success: true, warning: true, message, lines });

function allowedUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    // Plain http only to this machine (a local stand-in for tests); a real Threatline URL is always https.
    return u.protocol === 'https:' || (u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost'));
  } catch {
    return false;
  }
}

const resultLine = (key: string, r: ServerResult) => {
  const counts = [`${r.passed} passed`, ...(r.failed ? [`${r.failed} failed`] : []), ...(r.skipped ? [`${r.skipped} skipped`] : [])].join(', ');
  return `${key}: ${r.outcome.replace(/_/g, ' ')} ${r.requirementId} (${counts})${r.message ? `: ${r.message}` : ''}`;
};

/** Lock files, bundles, maps and binaries: never the fix, and the first to go when the change does not fit. */
const GENERATED = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|poetry\.lock|Pipfile\.lock|go\.sum|composer\.lock|Gemfile\.lock|gradle\.lockfile)$|\.min\.(js|css)$|\.(map|snap|svg|png|jpe?g|gif|ico|pdf|woff2?|ttf)$|(^|\/)(dist|build|vendor|node_modules|__snapshots__)\//i;
/** What Threatline accepts as the change (characters). */
const MAX_DIFF = 200_000;
const COMMITISH = /^[0-9a-f]{7,40}$/i;

const defaultGit = (root: string) => (args: string[]) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });

/**
 * The change as `git diff base...head` (what the pull request merges), with generated files left out, and cut at whole
 * files to fit `budget` bytes of the report. Returns the files it had to leave out, so the log can say so.
 */
export function fitDiff(text: string, budget: number): { text: string; left: string[] } {
  const parts = text.split(/(?=^diff --git )/m).filter((p) => p.trim());
  const pathOf = (p: string) => /^diff --git "?a\/.+?"? "?b\/(.+?)"?$/m.exec(p)?.[1] ?? '(unknown)';
  let size = 2;
  let chars = 0;
  const kept: string[] = [];
  const left: string[] = [];
  for (const p of parts) {
    const path = pathOf(p);
    const cost = Buffer.byteLength(JSON.stringify(p), 'utf8') - 2;
    if (GENERATED.test(path) || size + cost > budget || chars + p.length > MAX_DIFF) {
      left.push(path);
      continue;
    }
    kept.push(p);
    size += cost;
    chars += p.length;
  }
  return { text: kept.join(''), left };
}

function readChange(i: CiReportInput, head: string): { ok: true; text: string } | { ok: false; message: string } {
  const base = i.fixCheck!.base.trim();
  if (!COMMITISH.test(base)) return { ok: false, message: 'Threatline: the fix check needs the pull request base commit (a hash).' };
  const git = i.git ?? defaultGit(i.root);
  try {
    return { ok: true, text: git(['diff', '--no-color', '--no-ext-diff', '--find-renames', '--unified=3', `${base}...${head}`]) };
  } catch {
    return {
      ok: false,
      message: `Threatline: could not compute the change (git diff ${base.slice(0, 12)}...${head.slice(0, 12)}). Fetch the base branch's history: actions/checkout with fetch-depth: 0, or clone depth: full in bitbucket-pipelines.yml.`,
    };
  }
}

export async function runCiReport(i: CiReportInput): Promise<CiReportOutcome> {
  const doFetch = i.fetch ?? fetch;
  if (!allowedUrl(i.url)) return fail('Threatline: threatline-url must be the https web trigger URL from Threatline admin → CI verification.');
  if (!i.token.trim()) return fail('Threatline: threatline-token is empty. Store the CI token as a secret and pass it in.');
  const commitSha = i.commitSha.trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(commitSha)) return fail('Threatline: the commit is not a full 40-character hash.');
  if (!allowedUrl(i.runUrl) || !i.runUrl.startsWith('https://')) return fail('Threatline: the CI run link must be an https URL.');

  let files: string[] = [];
  if (i.junit.trim()) {
    try {
      files = findJUnitFiles(i.root, i.junit);
    } catch (e) {
      return fail(`Threatline: could not search for JUnit files (${e instanceof Error ? e.message : 'error'}).`);
    }
    if (files.length === 0) return fail(`Threatline: junit matched no files (${i.junit.split('\n').map((s) => s.trim()).filter(Boolean).join(', ')}). Run this after the tests, and check the reporter's output path.`);
    if (files.length > MAX_FILES) return fail(`Threatline: junit matched ${files.length} files; narrow it to at most ${MAX_FILES}.`);
  } else if (!i.fixCheck) return fail('Threatline: set junit (test results), the fix check, or both.');
  let change: string | undefined;
  if (i.fixCheck) {
    const c = readChange(i, commitSha);
    if (!c.ok) return fail(c.message);
    change = c.text;
  }

  const cases: TestCase[] = [];
  let total = 0;
  for (const f of files) {
    const path = join(i.root, f);
    if (statSync(path).size > MAX_FILE_BYTES) return fail(`Threatline: ${f} is larger than ${MAX_FILE_BYTES / 1024 / 1024} MB.`);
    const parsed = parseJUnit(readFileSync(path, 'utf8'));
    if (!parsed.ok) return fail(`Threatline: ${f} is not valid JUnit XML (${parsed.message}).`);
    total += parsed.cases.length;
    for (const c of parsed.cases) if (requirementIdsIn(c.name).length > 0) cases.push({ name: c.name.slice(0, 2000), status: c.status });
  }
  const lines = files.length > 0 ? [`Threatline: ${cases.length} of ${total} tests in ${files.length} JUnit file(s) name a requirement.`] : [];
  const keys = [...new Set(i.issueKeys)];
  if (keys.length === 0) return warn('Threatline: the branch or pull request title names no Jira work item, so no requirement was reported.', lines);
  if (keys.length > MAX_KEYS) return fail(`Threatline: the branch and title name ${keys.length} work items; name at most ${MAX_KEYS}.`, lines);

  let verified = 0;
  let detailed = false;
  const problems: string[] = [];
  /** Keys Threatline does not know (404) or this token may not report on (403): another project, or not a work item. */
  const unknown: string[] = [];
  // Threatline's web trigger is static (Runs on Atlassian), so it answers with the verdict only; the per-requirement
  // summary comes from these JUnit results: a requirement whose tests all passed here is what CI asks to verify.
  const local = new Map<string, { passed: number; failed: number; skipped: number }>();
  for (const c of cases)
    for (const id of requirementIdsIn(c.name)) {
      const t = local.get(id) ?? { passed: 0, failed: 0, skipped: 0 };
      t[c.status]++;
      local.set(id, t);
    }
  const passing = [...local.values()].filter((t) => t.passed > 0 && t.failed === 0).length;
  for (const issueKey of keys) {
    const report = { issueKey, repo: i.repo, commitSha, runUrl: i.runUrl, results: cases, ...(i.fixCheck?.prUrl ? { prUrl: i.fixCheck.prUrl } : {}) };
    let body = JSON.stringify(report);
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES)
      return fail(`Threatline: the report for ${issueKey} is larger than 256 KB (${cases.length} tests). Report fewer test files with the junit input; results are never dropped to fit.`, lines);
    if (change !== undefined) {
      // Test results are never dropped; the change is cut at whole files to fit what is left of the report.
      const fit = fitDiff(change, MAX_BODY_BYTES - Buffer.byteLength(body, 'utf8') - 64);
      if (!fit.text) {
        lines.push(`${issueKey}: the change has no reviewable files${fit.left.length ? ` (${fit.left.length} generated or too large)` : ''}, so no fix check was sent.`);
      } else {
        body = JSON.stringify({ ...report, diff: fit.text });
        lines.push(`${issueKey}: sent the change for a fix check (${(fit.text.length / 1024).toFixed(0)} KB${fit.left.length ? `; left out ${fit.left.length} file(s): ${fit.left.slice(0, 5).join(', ')}${fit.left.length > 5 ? ', …' : ''}` : ''}).`);
      }
    }
    let res: Response;
    try {
      res = await doFetch(i.url, { method: 'POST', headers: { authorization: `Bearer ${i.token}`, 'content-type': 'application/json', 'user-agent': 'threatline-ci-report' }, body, signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (e) {
      problems.push(`${issueKey}: could not reach Threatline (${e instanceof Error ? e.name : 'error'})`);
      continue;
    }
    const text = await res.text().catch(() => '');
    let parsed: { message?: unknown; verdict?: unknown; results?: unknown; fixCheck?: unknown } = {};
    try {
      parsed = JSON.parse(text) as typeof parsed;
    } catch {
      // A non-JSON answer: reported by status below.
    }
    const serverMessage = typeof parsed.message === 'string' ? ` ${parsed.message.slice(0, 300)}` : '';
    if (Array.isArray(parsed.results)) detailed = true;
    if (Array.isArray(parsed.results))
      for (const r of parsed.results as ServerResult[]) {
        lines.push(resultLine(issueKey, r));
        if (r.outcome === 'verified') verified++;
      }
    if (parsed.fixCheck === 'checking') lines.push(`${issueKey}: Threatline is checking whether this change fixes its security requirements. Done and merge wait for the check (the work item's Threatline panel shows the result).`);
    if (typeof parsed.verdict === 'string') lines.push(`${issueKey} verdict: ${parsed.verdict}${!Array.isArray(parsed.results) && serverMessage ? ` (${serverMessage.trim()})` : ''}`);
    if (res.ok) continue;
    if (res.status === 429 || res.status >= 500) {
      problems.push(`${issueKey}: Threatline answered HTTP ${res.status}, so the report was not recorded.${serverMessage}`);
      continue;
    }
    if (res.status === 404 || res.status === 403) {
      unknown.push(`${issueKey} (HTTP ${res.status}${serverMessage ? `:${serverMessage}` : ''})`);
      continue;
    }
    return fail(`Threatline: the report for ${issueKey} was refused (HTTP ${res.status}).${serverMessage}`, lines);
  }
  if (unknown.length > 0) {
    // One key that is not a reviewable work item must not stop the others being reported; all of them failing is a misconfiguration.
    if (unknown.length === keys.length) return fail(`Threatline: no work item named here could be reported: ${unknown.join(', ')}. Check the key in the branch or title, and that the CI token's project list includes it.`, lines);
    lines.push(`Skipped ${unknown.join(', ')}: not a work item this token can report on.`);
  }
  if (problems.length > 0) return warn(`Threatline: ${problems.join('; ')} Nothing unrecorded was verified; re-run the job to retry.`, lines);
  if (!detailed) {
    for (const [id, t] of [...local.entries()].sort(([a], [b]) => a.localeCompare(b)))
      lines.push(`${id}: ${t.failed > 0 ? 'tests failed' : t.passed > 0 ? 'tests passed' : 'skipped'} (${t.passed} passed${t.failed ? `, ${t.failed} failed` : ''}${t.skipped ? `, ${t.skipped} skipped` : ''})`);
    return { success: true, message: `Threatline: report recorded; ${passing} requirement${passing === 1 ? '' : 's'} had only passing tests in this run. Open requirements among them are now Verified (the work item's Threatline panel shows which).`, lines };
  }
  return { success: true, message: `Threatline: ${verified} requirement${verified === 1 ? '' : 's'} verified from this run.`, lines };
}

/**
 * scripts/threatline-ci-report.mjs: settings from flags and the environment, for Bitbucket Pipelines (or any CI).
 * The token is read only from THREATLINE_TOKEN, never a flag, so it stays out of process lists and logs.
 */
export function cliReportConfig(argv: string[], env: Record<string, string | undefined>): { ok: true; value: Omit<CiReportInput, 'fetch'> } | { ok: false; message: string } {
  const flags: Record<string, string[]> = {};
  let fixFlag = false;
  for (let k = 0; k < argv.length; k++) {
    if (argv[k] === '--fix-check') {
      fixFlag = true;
      continue;
    }
    const m = /^--(junit|issue-key|url|commit|repo|run-url|diff-base|pr-url)(?:=(.*))?$/.exec(argv[k]!);
    if (!m) return { ok: false, message: `Threatline: unknown argument ${argv[k]!.slice(0, 40)}. Use --junit, --fix-check, --diff-base, --pr-url, --issue-key, --url, --commit, --repo or --run-url (the token comes from THREATLINE_TOKEN).` };
    const value = m[2] ?? argv[++k];
    if (value === undefined) return { ok: false, message: `Threatline: --${m[1]} needs a value.` };
    (flags[m[1]!] ??= []).push(value);
  }
  const one = (flag: string, ...vars: Array<string | undefined>) => flags[flag]?.[0] ?? vars.find((v) => v !== undefined && v !== '') ?? '';
  const repo = one('repo', env.THREATLINE_REPO, env.BITBUCKET_REPO_FULL_NAME, env.GITHUB_REPOSITORY);
  const bitbucketRun = env.BITBUCKET_BUILD_NUMBER && repo ? `https://bitbucket.org/${repo}/pipelines/results/${env.BITBUCKET_BUILD_NUMBER}` : undefined;
  const githubRun = env.GITHUB_RUN_ID && repo ? `${env.GITHUB_SERVER_URL ?? 'https://github.com'}/${repo}/actions/runs/${env.GITHUB_RUN_ID}` : undefined;
  // `||`: on a GitHub push event GITHUB_HEAD_REF is set but empty, and the branch is GITHUB_REF_NAME.
  const branch = env.BITBUCKET_BRANCH || env.GITHUB_HEAD_REF || env.GITHUB_REF_NAME || '';
  const explicit = [...(flags['issue-key'] ?? []), ...(env.THREATLINE_ISSUE_KEY ? env.THREATLINE_ISSUE_KEY.split(',') : [])].map((s) => s.trim().toUpperCase()).filter(Boolean);
  const value = {
    url: one('url', env.THREATLINE_URL),
    token: env.THREATLINE_TOKEN ?? '',
    junit: (flags.junit ?? (env.THREATLINE_JUNIT ? env.THREATLINE_JUNIT.split('\n') : [])).join('\n'),
    root: env.BITBUCKET_CLONE_DIR || env.GITHUB_WORKSPACE || process.cwd(),
    issueKeys: explicit.length > 0 ? explicitIssueKeys(explicit.join(' ')) : namedIssueKeys(branch),
    repo,
    commitSha: one('commit', env.THREATLINE_COMMIT, env.BITBUCKET_COMMIT, env.GITHUB_SHA),
    runUrl: one('run-url', env.THREATLINE_RUN_URL, bitbucketRun, githubRun),
  };
  // Fix check: --fix-check (or --diff-base) sends the pull request's change; in Bitbucket Pipelines the base is the
  // pull request's destination commit and the link is built from BITBUCKET_PR_ID.
  const base = one('diff-base', env.THREATLINE_DIFF_BASE, fixFlag ? env.BITBUCKET_PR_DESTINATION_COMMIT : undefined);
  const prUrl = one('pr-url', env.THREATLINE_PR_URL, env.BITBUCKET_PR_ID && repo ? `https://bitbucket.org/${repo}/pull-requests/${env.BITBUCKET_PR_ID}` : undefined);
  if ((fixFlag || base) && !base) return { ok: false, message: 'Threatline: --fix-check needs the pull request base commit: run it in a pull-requests pipeline (BITBUCKET_PR_DESTINATION_COMMIT), or pass --diff-base.' };
  const withFix = base ? { ...value, fixCheck: { base, ...(prUrl.startsWith('https://') ? { prUrl } : {}) } } : value;
  if (!value.url) return { ok: false, message: 'Threatline: set THREATLINE_URL (or --url) to the web trigger URL from Threatline admin → CI verification.' };
  if (!value.token) return { ok: false, message: 'Threatline: set THREATLINE_TOKEN to the CI token (a secured repository variable).' };
  if (!value.junit.trim() && !base) return { ok: false, message: 'Threatline: pass --junit <glob> (for example --junit "test-results/**/*.xml"), --fix-check, or both.' };
  if (!value.repo || !value.runUrl) return { ok: false, message: 'Threatline: cannot tell the repository or the run link; set --repo and --run-url.' };
  return { ok: true, value: withFix };
}
