import { DEFAULT_REPO_SETTINGS, evaluateMergeCheck, withAddedText, type DiffFile, type RepoSettings } from '@threatline/core';
import { appError, err, log, type Result } from '@threatline/shared';
import type { BitbucketClient, DiffstatEntry } from './bitbucket-client.js';

const STATUS: Record<string, DiffFile['status']> = { added: 'added', removed: 'removed', renamed: 'renamed', modified: 'modified' };

export { DEFAULT_REPO_SETTINGS, evaluateMergeCheck, WARN_ONLY_MAX_DAYS, type RepoSettings } from '@threatline/core';

export function toDiffFiles(entries: DiffstatEntry[]): DiffFile[] {
  return entries.flatMap((e) => {
    const path = e.new?.path ?? e.old?.path;
    if (!path) return [];
    const oldPath = e.old?.path && e.old.path !== path ? e.old.path : undefined;
    return [{ path, ...(oldPath ? { oldPath } : {}), status: STATUS[e.status ?? ''] ?? 'modified', linesAdded: e.lines_added ?? 0 }];
  });
}

/**
 * A Bitbucket read that throws (requestBitbucket's network error, a body that is not JSON) is a failed read like any
 * other, so the check fails closed with its "re-run in a minute" message instead of an unhandled error.
 */
const settle = <T>(read: () => Promise<Result<T>>): Promise<Result<T>> =>
  Promise.resolve()
    .then(read)
    .catch((e: unknown) => err(appError('upstream', `request failed (${e instanceof Error ? e.name : 'error'})`)));

export interface PRCheckEvent {
  workspace: { uuid: string };
  repository: { uuid: string };
  pullrequest: { id: number };
  trigger?: { type: string };
}

/** Fetches the PR, its diffstat, the destination's policy.yml and the repo settings, then evaluates. Fails closed. */
export async function runMergeCheck(
  event: PRCheckEvent,
  deps: { client: BitbucketClient; settings: (repoUuid: string) => Promise<RepoSettings | null>; nowSec: () => number },
): Promise<{ success: boolean; message: string }> {
  // null: no settings were ever saved, so the defaults apply. A failed or corrupt read fails closed instead: the defaults
  // would drop the admin's sensitive paths and pass a change that touches them.
  const read = await deps.settings(event.repository.uuid).then(
    (s) => ({ ok: true as const, s }),
    () => ({ ok: false as const }),
  );
  if (!read.ok) return { success: false, message: "Threatline: could not read this repository's Threatline settings, so this pull request cannot be checked. Re-run the check in a minute." };
  const settings = read.s ?? DEFAULT_REPO_SETTINGS;
  const warnActive = settings.mode === 'warn' && !!settings.warnUntil && Date.parse(settings.warnUntil) / 1000 > deps.nowSec();
  const unreadable = (why: string) => {
    const message = `Threatline: could not read this pull request from Bitbucket (${why}), so it cannot be checked. Re-run the check in a minute.`;
    return warnActive ? { success: true, message: `Warning: ${message}` } : { success: false, message };
  };
  const ws = event.workspace.uuid;
  const repo = event.repository.uuid;
  const { client } = deps;
  const readDiff = client.diff;
  const [pr, diff, patch] = await Promise.all([
    settle(() => client.pullRequest(ws, repo, event.pullrequest.id)),
    settle(() => client.diffstat(ws, repo, event.pullrequest.id)),
    // A diff that throws is unread text: withAddedText treats it as sensitive.
    readDiff ? settle(() => readDiff.call(client, ws, repo, event.pullrequest.id)) : Promise.resolve(null),
  ]);
  if (!pr.ok) return unreadable('pull request');
  if (!diff.ok) return unreadable('changed files');
  const shortHead = pr.value.source?.commit?.hash ?? '';
  const dest = pr.value.destination?.commit?.hash ?? '';
  const fullName = pr.value.destination?.repository?.full_name ?? '';
  if (!shortHead || !dest || !fullName) return unreadable('commits');
  // `.redline/policy.yml`: the name before the rename to Threatline, still read when the new file is absent.
  const current = await settle(() => client.fileAt(ws, repo, dest, '.threatline/policy.yml'));
  const policy = current.ok && current.value === null ? await settle(() => client.fileAt(ws, repo, dest, '.redline/policy.yml')) : current;
  if (!policy.ok) return unreadable('policy file');
  const input = (headSha: string) => ({
    pr: { description: pr.value.description ?? '', headSha, destSha: dest, repoFullName: fullName, title: pr.value.title ?? '', branch: pr.value.source?.branch?.name ?? '' },
    // M7: every added line feeds the secret-pattern signal; unreadable or over-long diff text fails closed (sensitive).
    files: withAddedText(toDiffFiles(diff.value), patch),
    repoPolicyYaml: policy.value,
    settings,
    nowSec: deps.nowSec(),
  });
  // A pull request that touches nothing sensitive passes without looking at its head commit at all.
  let r = await evaluateMergeCheck(input(shortHead));
  if (r.outcome !== 'pass_not_sensitive' && !/^[0-9a-f]{40}$/i.test(shortHead)) {
    // The pull request API reports 12-character hashes; the gate matches the attestation's full hash exactly. The full
    // hash comes from the pull request's own commit list (forks included); anything that does not match fails closed.
    const resolved = await settle(() => client.headCommit(ws, repo, event.pullrequest.id, shortHead));
    if (!resolved.ok || !resolved.value.startsWith(shortHead.toLowerCase())) return unreadable('head commit');
    r = await evaluateMergeCheck(input(resolved.value));
  }
  log('merge_check', { outcome: r.outcome, files: diff.value.length });
  return { success: r.success, message: r.message };
}
