import { allAddedText, DIFF_UNREAD_PATH, evaluateMergeCheck, GATE_CONFIG_PATHS, MAX_DIFF_TEXT, parseTrustedKeys, TRUNCATED_PATH, type CheckResult, type DiffFile, type RepoSettings } from '@threatline/core';

/** What the merge gate needs from GitHub's REST API, read with the workflow's token. */
export interface GitHubPr {
  body: string | null;
  title: string;
  head: { sha: string; ref: string };
  base: { sha: string; repo: { full_name: string } };
}
export interface GitHubFile {
  filename: string;
  status: string;
  additions: number;
  previous_filename?: string;
  /** Absent for binary files and for text diffs too large for GitHub to return. */
  patch?: string;
}
export type Fetched<T> = { ok: true; value: T } | { ok: false; status: number };
export interface GitHubClient {
  pullRequest(): Promise<Fetched<GitHubPr>>;
  /** The changed files; `truncated` when the pull request changes more files than GitHub lists (3,000). */
  files(): Promise<Fetched<{ files: GitHubFile[]; truncated: boolean }>>;
  /** File text at a commit on the base branch; null when the file does not exist there. */
  fileAt(ref: string, path: string): Promise<Fetched<string | null>>;
}

export const WARN_MAX_DAYS = 14;
const KEY_HINT = 'Add it to the public-keys input of the Threatline step in your workflow (Threatline admin → Signing keys → Copy public key).';
const lines = (v: string | undefined) => (v ?? '').split('\n').map((l) => l.trim()).filter(Boolean);

/**
 * The clock the gate checks expiry against: THREATLINE_NOW (Unix seconds, for tests) only when it is a positive whole
 * number. Anything else is ignored, never NaN: every comparison with NaN is false, so expiry, warn-until and key
 * retirement would all silently stop applying.
 */
export function nowSecFrom(raw: string | undefined, nowMs = Date.now()): number {
  const s = (raw ?? '').trim();
  const n = /^\d+$/.test(s) ? Number(s) : NaN;
  return Number.isSafeInteger(n) && n > 0 ? n : Math.floor(nowMs / 1000);
}

/** The step's `with:` inputs → repository settings. Rejects anything it cannot honour rather than guessing. */
export function parseInputs(input: Record<string, string | undefined>, nowSec: number): { ok: true; value: RepoSettings } | { ok: false; message: string } {
  // One key per line, optionally `<key> until=<ISO date>` when it retires (after a rotation's 7-day overlap).
  const keys = parseTrustedKeys(lines(input['public-keys']));
  if (!keys.ok)
    return { ok: false, message: keys.reason === 'until' ? `Threatline: public-keys line ${keys.line}: ${keys.message}.` : `Threatline: ${keys.message}. Copy it from Threatline admin → Signing keys.` };
  const { publicKeys, keyRetireAt } = keys;
  // Without a key no attestation can ever verify: say so as a configuration error, not on every pull request's check.
  if (Object.keys(publicKeys).length === 0) return { ok: false, message: "Threatline: public-keys is required when merge-gate is on (no attestation can verify without Threatline's public key). Paste it from Threatline admin → Signing keys → Copy public key, or set merge-gate: false to only report test results." };
  const mode = (input.mode ?? '').trim() || 'block';
  if (mode !== 'block' && mode !== 'warn') return { ok: false, message: `Threatline: mode must be block or warn, not "${mode.slice(0, 20)}".` };
  const rawThreshold = (input['diff-score-threshold'] ?? '').trim();
  const threshold = rawThreshold === '' ? 40 : Number(rawThreshold);
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) return { ok: false, message: 'Threatline: diff-score-threshold must be a number from 0 to 100.' };
  // The shared gate always adds GATE_CONFIG_PATHS (packages/core); listed here too so the settings show them.
  const settings: RepoSettings = { publicKeys, ...(Object.keys(keyRetireAt).length > 0 ? { keyRetireAt } : {}), sensitivePaths: [...GATE_CONFIG_PATHS, ...lines(input['sensitive-paths'])], mode, diffScoreThreshold: threshold, keyHint: KEY_HINT };
  if (mode === 'warn') {
    const until = (input['warn-until'] ?? '').trim();
    const at = Date.parse(until);
    if (!until || Number.isNaN(at)) return { ok: false, message: 'Threatline: warn mode needs warn-until, a date at most 14 days away (warn-only mode expires).' };
    if (at / 1000 > nowSec + WARN_MAX_DAYS * 86_400) return { ok: false, message: `Threatline: warn-until is more than ${WARN_MAX_DAYS} days away; warn-only mode lasts at most ${WARN_MAX_DAYS} days.` };
    settings.warnUntil = until;
  }
  return { ok: true, value: settings };
}

const STATUS: Record<string, DiffFile['status']> = { added: 'added', copied: 'added', removed: 'removed', renamed: 'renamed', modified: 'modified', changed: 'modified', unchanged: 'modified' };

/** GitHub's changed files → the gate's diff, with every added line for the secret scan. Unreadable text fails closed. */
export function toDiffFiles(files: GitHubFile[], truncated: boolean): DiffFile[] {
  const out: DiffFile[] = files.map((f) => ({
    path: f.filename,
    ...(f.previous_filename && f.previous_filename !== f.filename ? { oldPath: f.previous_filename } : {}),
    status: STATUS[f.status] ?? 'modified',
    linesAdded: f.additions,
  }));
  // A text change GitHub would not return (no patch, but lines were added) cannot be scanned: sensitive.
  const unread = files.some((f) => f.patch === undefined && f.additions > 0);
  const added = files.map((f) => (f.patch ? allAddedText(f.patch) : '')).join('');
  if (unread || added.length > MAX_DIFF_TEXT) out.push({ path: DIFF_UNREAD_PATH, status: 'modified', linesAdded: 0 });
  else if (added) out.push({ path: '(added lines)', status: 'modified', linesAdded: 0, addedText: added });
  if (truncated) out.push({ path: TRUNCATED_PATH, status: 'modified', linesAdded: 0 });
  return out;
}

/** Reads the pull request from GitHub and decides, exactly as Threatline for Bitbucket does. Fails closed. */
export async function runGitHubCheck(i: { settings: RepoSettings; client: GitHubClient; nowSec: number }): Promise<CheckResult> {
  const warnActive = i.settings.mode === 'warn' && !!i.settings.warnUntil && Date.parse(i.settings.warnUntil) / 1000 > i.nowSec;
  const unreadable = (what: string, status: number): CheckResult => {
    const message = `Threatline: could not read this pull request from GitHub (${what}, HTTP ${status}), so it cannot be checked. Re-run the job in a minute.`;
    return warnActive ? { success: true, outcome: 'warn', message: `Warning: ${message}` } : { success: false, outcome: 'fail_missing', message };
  };
  const [pr, files] = await Promise.all([i.client.pullRequest(), i.client.files()]);
  if (!pr.ok) return unreadable('pull request', pr.status);
  if (!files.ok) return unreadable('changed files', files.status);
  // `.redline/policy.yml`: the name before the rename to Threatline, still read when the new file is absent.
  const current = await i.client.fileAt(pr.value.base.sha, '.threatline/policy.yml');
  const policy = current.ok && current.value === null ? await i.client.fileAt(pr.value.base.sha, '.redline/policy.yml') : current;
  if (!policy.ok) return unreadable('policy file', policy.status);
  return evaluateMergeCheck({
    pr: { description: pr.value.body ?? '', headSha: pr.value.head.sha, destSha: pr.value.base.sha, repoFullName: pr.value.base.repo.full_name, title: pr.value.title, branch: pr.value.head.ref },
    files: toDiffFiles(files.value.files, files.value.truncated),
    repoPolicyYaml: policy.value,
    settings: i.settings,
    nowSec: i.nowSec,
  });
}
