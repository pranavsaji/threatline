import { decodeAttestation, findAttestations, fromB64url, fromUtf8, isValidPublicKey, kidOf } from '@threatline/crypto';
import { namedIssueKeys, type AttestationPayload } from '@threatline/shared';
import { DEFAULT_SITE_POLICY, parseRepoPolicy } from './policy.js';
import { scoreDiff, type DiffFile } from './diffscore.js';

/**
 * The merge gate's decision, shared by Threatline for Bitbucket (merge check) and the Threatline GitHub Action: given a pull
 * request's description, head commit, changed files and the repository's settings, does the change need an
 * attestation, and does the one in the description verify? Pure: the callers fetch, this decides. Fails closed.
 */

/** Diff text Threatline scans (2 MB); a bigger diff is scanned up to here. */
export const MAX_DIFF_TEXT = 2_000_000;

/** Marker file for diff text Threatline could not read whole (unreadable, or over MAX_DIFF_TEXT): treated as sensitive. */
export const DIFF_UNREAD_PATH = '(diff text Threatline could not read)';

/**
 * Every added line in a unified diff, whichever file it belongs to. The secret scan does not need per-file mapping, so
 * no header parsing is trusted: a line that only looks like a `+++` header inside a hunk cannot move text out of the
 * scan (security review). File headers themselves are included, which can only add text to scan.
 */
export function allAddedText(diff: string): string {
  let out = '';
  for (const line of diff.split('\n')) if (line.startsWith('+')) out += `${line.slice(1)}\n`;
  return out;
}

/** Appended when the PR changes more files than Threatline pages through; the merge check treats it as sensitive. */
export const TRUNCATED_PATH = '(more files than Threatline reads)';

export interface RepoSettings {
  /** Where an admin pastes Threatline's public key on this platform; used in the missing-key message. */
  keyHint?: string;
  /** kid → base64url Ed25519 public key, copied from Threatline's admin page. */
  publicKeys: Record<string, string>;
  /**
   * kid → ISO time a trusted key retires (from a `<key> until=<date>` line). From then on tokens signed by it fail: set
   * it on the old key after a rotation's 7-day overlap, or just remove the key.
   */
  keyRetireAt?: Record<string, string>;
  sensitivePaths: string[];
  mode: 'warn' | 'block';
  /** Warn mode ends here (set when an admin saves warn mode, at most 14 days); after it, or without it, the check blocks. */
  warnUntil?: string;
  diffScoreThreshold: number;
}
export const DEFAULT_REPO_SETTINGS: RepoSettings = { publicKeys: {}, sensitivePaths: [], mode: 'block', diffScoreThreshold: 40 };

export type Outcome =
  | 'pass_attested'
  | 'pass_not_sensitive'
  | 'fail_missing'
  | 'fail_signature'
  | 'fail_stale_commit'
  | 'fail_expired'
  | 'fail_other_repo'
  | 'fail_other_issue'
  | 'warn';
export interface CheckResult {
  success: boolean;
  message: string;
  outcome: Outcome;
}
export interface PrFacts {
  description: string;
  headSha: string;
  repoFullName: string;
  destSha: string;
  title?: string;
  branch?: string;
}

/** Work-item keys a pull request names in its title or branch (rules in @threatline/shared/ci). */
export { namedIssueKeys };
const FULL_SHA = /^[0-9a-f]{40}$/;

/**
 * Trusted public keys as an admin pastes them, one per line: `<base64url key>` or `<base64url key> until=<ISO date or
 * time>` (a date alone means 00:00 UTC that day). Shared by Threatline for Bitbucket's settings and the GitHub Action's
 * `public-keys` input. Bare keys are trusted until removed.
 */
export function parseTrustedKeys(lines: string[]): { ok: true; publicKeys: Record<string, string>; keyRetireAt: Record<string, string> } | { ok: false; line: number; reason: 'key' | 'until'; message: string } {
  const publicKeys: Record<string, string> = {};
  const keyRetireAt: Record<string, string> = {};
  for (const [n, line] of lines.entries()) {
    const [key = '', ...rest] = line.trim().split(/\s+/);
    if (!isValidPublicKey(key)) return { ok: false, line: n + 1, reason: 'key', message: `"${key.slice(0, 12)}…" is not a Threatline public key` };
    const kid = kidOf(fromB64url(key)!);
    publicKeys[kid] = key;
    if (rest.length === 0) continue;
    const until = rest.length === 1 && rest[0]!.startsWith('until=') ? rest[0]!.slice('until='.length) : '';
    // A time without a zone is UTC (JavaScript would otherwise read it in the runner's local time).
    const at = /^\d{4}-\d{2}-\d{2}/.test(until) ? Date.parse(/T[\d:.]+$/.test(until) ? `${until}Z` : until) : NaN;
    if (Number.isNaN(at)) return { ok: false, line: n + 1, reason: 'until', message: 'after the key, only until=<ISO date> (for example until=2026-12-01) is allowed' };
    keyRetireAt[kid] = new Date(at).toISOString();
  }
  return { ok: true, publicKeys, keyRetireAt };
}
const MSG_SIGNATURE = 'Threatline: attestation signature invalid. Copy a fresh attestation from the Jira issue panel.';
/** Bitbucket stores descriptions as Markdown and escapes punctuation (`\_`, `\-`); undo that before looking for tokens. */
export const unescapeMarkdown = (text: string) => text.replace(/\\([\\`*_{}[\]()#+\-.!|~<>])/g, '$1');
const utcMinute = (sec: number) => `${new Date(sec * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC`;

/** The payload's repo, iat and kid, read without trusting them (only to choose which token to verify and explain why). */
function peek(token: string): (Pick<AttestationPayload, 'repo' | 'iat'> & { kid?: string }) | null {
  const body = token.split('.')[2];
  const bytes = body ? fromB64url(body) : null;
  if (!bytes) return null;
  try {
    const p = JSON.parse(fromUtf8(bytes)) as { repo?: unknown; iat?: unknown; kid?: unknown };
    return typeof p.repo === 'string' && typeof p.iat === 'number' ? { repo: p.repo, iat: p.iat, ...(typeof p.kid === 'string' ? { kid: p.kid } : {}) } : null;
  } catch {
    return null;
  }
}

/**
 * The gate's own configuration, on every platform: the CI that runs it (GitHub workflows and local actions, Bitbucket
 * Pipelines) and Threatline's policy file (`.redline/` is its name from before the rename). Changing any of it is always
 * sensitive, so a pull request cannot loosen the gate (edit, delete or shadow policy.yml) and then pass freely: the
 * loosening itself needs an attestation like any other security change.
 */
export const GATE_CONFIG_PATHS = ['.github/workflows/**', '.github/actions/**', '.threatline/**', '.redline/**', 'bitbucket-pipelines.yml'];

function effectivePolicy(settings: RepoSettings, yaml: string | null): { sensitivePaths: string[]; threshold: number; invalid: boolean } {
  // Gate config ∪ site defaults ∪ repo settings ∪ the destination's policy.yml: a file can add paths and lower the
  // threshold, never weaken.
  const paths = new Set([...GATE_CONFIG_PATHS, ...DEFAULT_SITE_POLICY.sensitivePaths, ...settings.sensitivePaths]);
  let threshold = settings.diffScoreThreshold;
  if (yaml === null) return { sensitivePaths: [...paths], threshold, invalid: false };
  const parsed = parseRepoPolicy(yaml);
  if (!parsed.ok) return { sensitivePaths: [...paths], threshold, invalid: true };
  for (const p of parsed.value.sensitivePaths) paths.add(p);
  threshold = Math.min(threshold, parsed.value.diffScoreThreshold);
  return { sensitivePaths: [...paths], threshold, invalid: false };
}

/**
 * EN-5/EN-6/AT-2. Changes that touch no sensitive path (and score under the threshold) pass. Otherwise the newest
 * attestation for this repository in the description must verify, be unexpired, and name the PR's head commit.
 * Warn mode reports failures but lets the merge through.
 */
export async function evaluateMergeCheck(i: { pr: PrFacts; files: DiffFile[]; repoPolicyYaml: string | null; settings: RepoSettings; nowSec: number }): Promise<CheckResult> {
  const r = decide(i);
  if (r.success || i.settings.mode !== 'warn') return r;
  const until = i.settings.warnUntil ? Date.parse(i.settings.warnUntil) / 1000 : NaN;
  if (!(until > i.nowSec)) {
    const ended = Number.isFinite(until) ? `Threatline: warn-only mode ended ${utcMinute(until)}, so this check blocks again. ` : 'Threatline: warn-only mode has no end date, so this check blocks. ';
    return { ...r, message: `${ended}${r.message}` };
  }
  return { success: true, outcome: 'warn', message: `Warning: ${r.message}` };
}

function decide(i: { pr: PrFacts; files: DiffFile[]; repoPolicyYaml: string | null; settings: RepoSettings; nowSec: number }): CheckResult {
  const policy = effectivePolicy(i.settings, i.repoPolicyYaml);
  const score = scoreDiff(i.files, { sensitivePaths: policy.sensitivePaths });
  const markers = i.files.filter((f) => f.path === TRUNCATED_PATH || f.path === DIFF_UNREAD_PATH).map((f) => f.path);
  const truncated = markers.length > 0;
  // An unreadable policy file on the target branch fails closed: every changed file counts as sensitive.
  const sensitive = policy.invalid ? i.files.map((f) => f.path) : truncated ? [...markers, ...score.sensitiveFiles] : score.sensitiveFiles;
  if (sensitive.length === 0 && score.score < policy.threshold) return { success: true, outcome: 'pass_not_sensitive', message: 'Threatline: no security-sensitive changes.' };

  const named = namedIssueKeys(i.pr.title ?? '', i.pr.branch ?? '');
  const key = named[0] ?? 'the linked issue';
  const shown = [...new Set(sensitive.length > 0 ? sensitive : i.files.map((f) => f.path))].slice(0, 3).join(', ');
  const missing: CheckResult = {
    success: false,
    outcome: 'fail_missing',
    message: `Threatline: this change touches security-sensitive files (${shown}) and has no attestation. Ask your IDE agent for get-merge-attestation on ${key}, or click Copy attestation in Jira.`,
  };

  const tokens = findAttestations(unescapeMarkdown(i.pr.description));
  if (tokens.length === 0) return missing;
  const repo = i.pr.repoFullName.toLowerCase();
  const peeked = tokens.map((t) => ({ t, p: peek(t) }));
  const mine = peeked.filter((x) => x.p?.repo.toLowerCase() === repo).sort((a, b) => b.p!.iat - a.p!.iat);
  if (mine.length === 0) {
    // Every token is readable but none is for this repository → say which repository they are for.
    const others = [...new Set(peeked.flatMap((x) => (x.p ? [x.p.repo] : [])))];
    if (peeked.every((x) => x.p))
      return { success: false, outcome: 'fail_other_repo', message: `Threatline: the attestation in this pull request is for ${others.slice(0, 2).join(', ')}, not ${i.pr.repoFullName}. Request one for this repository.` };
    return { success: false, outcome: 'fail_signature', message: MSG_SIGNATURE };
  }

  if (Object.keys(i.settings.publicKeys).length === 0)
    return { success: false, outcome: 'fail_signature', message: `Threatline: no Threatline public key is configured for this repository. ${i.settings.keyHint ?? 'A repository admin must paste it in Repository settings → Threatline.'}` };
  // Keys past their retire date are no longer trusted (rotated keys must stop verifying at some point).
  const retiredAt = (kid: string | undefined) => {
    const at = kid ? i.settings.keyRetireAt?.[kid] : undefined;
    const sec = at ? Date.parse(at) / 1000 : NaN;
    return sec <= i.nowSec ? sec : null;
  };
  const trusted = Object.fromEntries(Object.entries(i.settings.publicKeys).filter(([kid]) => retiredAt(kid) === null));
  const v = decodeAttestation(mine[0]!.t, trusted, i.nowSec);
  if (!v.ok) {
    const retired = retiredAt(mine[0]!.p!.kid);
    if (retired !== null && (v.error.code === 'bad_signature' || v.error.code === 'unknown_key'))
      return { success: false, outcome: 'fail_signature', message: `Threatline: this attestation is signed with key ${mine[0]!.p!.kid}, which this repository retired at ${utcMinute(retired)}. Request a new attestation (it is signed with Threatline's current key).` };
    if (v.error.code === 'lifetime')
      return { success: false, outcome: 'fail_signature', message: 'Threatline: this attestation is valid for longer than Threatline ever issues (7 days), so it is refused. Request a new one from the Jira issue panel.' };
    if (v.error.code === 'expired') {
      const exp = (() => {
        try {
          return (JSON.parse(fromUtf8(fromB64url(mine[0]!.t.split('.')[2]!)!)) as { exp: number }).exp;
        } catch {
          return i.nowSec;
        }
      })();
      return { success: false, outcome: 'fail_expired', message: `Threatline: attestation expired at ${utcMinute(exp)}. Request a new one.` };
    }
    return { success: false, outcome: 'fail_signature', message: MSG_SIGNATURE };
  }
  const p = v.value;
  const head = i.pr.headSha.toLowerCase();
  // The attestation names the full 40-character commit and must match exactly. Bitbucket's pull request API reports
  // 12-character hashes; Threatline for Bitbucket resolves them to the full hash before calling the gate.
  if (!FULL_SHA.test(head))
    return { success: false, outcome: 'fail_stale_commit', message: `Threatline: the PR head commit ${head.slice(0, 12) || '(none)'} is not a full 40-character hash, so the attestation cannot be matched to it. Re-run the check.` };
  if (p.commitSha !== head)
    return { success: false, outcome: 'fail_stale_commit', message: `Threatline: attestation is for commit ${p.commitSha.slice(0, 7)} but the PR head is ${head.slice(0, 7)}. Request a new attestation for the latest commit.` };
  // The attestation must be for a work item this PR names: otherwise any passing item's token could carry a blocked change.
  if (named.length === 0)
    return { success: false, outcome: 'fail_other_issue', message: `Threatline: this pull request names no Jira work item. Put the work item key (${p.issueKey}) in the pull request title or branch name, then re-run the check.` };
  if (!named.includes(p.issueKey))
    return { success: false, outcome: 'fail_other_issue', message: `Threatline: the attestation is for ${p.issueKey}, but this pull request is for ${named.join(', ')}. Request an attestation from ${named[0]}.` };
  // Final review I1: every work item the PR names needs its own valid attestation for this commit; otherwise a passing
  // item named next to a blocked one ("PAY-6 …, see PAY-7") would carry the blocked change.
  const attested = (key: string) =>
    mine.some((x) => {
      const d = decodeAttestation(x.t, trusted, i.nowSec);
      return d.ok && d.value.issueKey === key && d.value.commitSha === head;
    });
  const unattested = named.find((k) => k !== p.issueKey && !attested(k));
  if (unattested)
    return {
      success: false,
      outcome: 'fail_other_issue',
      message: `Threatline: this pull request also names ${unattested}, which has no valid attestation for this commit. Add one from ${unattested}, or remove ${unattested} from the title and branch name.`,
    };
  const verified = p.requirements.filter((r) => r.status === 'Verified').length;
  const pass = `Threatline: attested by ${p.issueKey}, ${verified} requirements verified${p.partial ? ' (reviewed with partial context)' : ''}.`;
  const lenient = p.override === 'break_glass' ? 'Warning: attested under a break-glass override. ' : p.override === 'warn_only' ? 'Warning: attested under warn-only mode. ' : '';
  return { success: true, outcome: 'pass_attested', message: `${lenient}${pass}` };
}

export function withAddedText(files: DiffFile[], patch: { ok: true; value: string } | { ok: false } | null): DiffFile[] {
  if (patch === null) return files; // a client that cannot fetch diff text (tests, older wiring): paths only
  if (!patch.ok || patch.value.length > MAX_DIFF_TEXT) return [...files, { path: DIFF_UNREAD_PATH, status: 'modified', linesAdded: 0 }];
  return [...files, { path: '(added lines)', status: 'modified', linesAdded: 0, addedText: allAddedText(patch.value) }];
}

