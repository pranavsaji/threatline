import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { encodeAttestation, generateKeyPair, type KeyPair } from '@threatline/crypto';
import type { AttestationPayload } from '@threatline/shared';
import type { DiffFile } from '@threatline/core';
import { evaluateMergeCheck, runMergeCheck, type RepoSettings } from '../src/merge-check.js';
import { bitbucketClient, type BitbucketClient } from '../src/bitbucket-client.js';
import { kvsSettingsStore } from '../src/settings-store.js';

const fixture = (p: string) => readFileSync(new URL(`./fixtures/${p}`, import.meta.url), 'utf8');
const HEAD = 'b'.repeat(40);
const OLD = 'a'.repeat(40);
const NOW = 1_763_208_000; // 2025-11-15T12:00:00Z
const REPO = 'acme/payments';

const key = generateKeyPair();
const settings = (o: Partial<RepoSettings> = {}, k: KeyPair = key): RepoSettings => ({ publicKeys: { [k.kid]: k.publicKey }, sensitivePaths: [], mode: 'block', diffScoreThreshold: 40, ...o });
function token(o: Partial<AttestationPayload> = {}, k: KeyPair = key): string {
  const p: AttestationPayload = {
    v: 1,
    kid: k.kid,
    issueKey: 'PAY-7',
    repo: REPO,
    commitSha: HEAD,
    verdict: 'pass',
    requirements: [
      { id: 'req_1', status: 'Verified' },
      { id: 'req_2', status: 'Verified' },
      { id: 'req_3', status: 'NotApplicable' },
    ],
    iat: NOW - 60,
    exp: NOW + 3600,
    nonce: 'n0nce1',
    ...o,
  };
  return encodeAttestation(p, k);
}
const AUTH = [{ path: 'src/auth/webhook.ts', status: 'modified' as const, linesAdded: 40 }];
const DOCS = [{ path: 'README.md', status: 'modified' as const, linesAdded: 2 }];
// The gate compares full 40-character hashes; runMergeCheck resolves Bitbucket's 12-character ones first (bug 7).
const pr = (description: string, headSha = HEAD) => ({ description, headSha, repoFullName: REPO, destSha: 'd'.repeat(12), title: 'PAY-7 Verify refund webhook signatures', branch: 'feature/PAY-7-webhook-hmac' });
const run = (description: string, o: { files?: DiffFile[]; yaml?: string | null; s?: RepoSettings; head?: string } = {}) =>
  evaluateMergeCheck({ pr: pr(description, o.head), files: o.files ?? AUTH, repoPolicyYaml: o.yaml ?? null, settings: o.s ?? settings(), nowSec: NOW });

describe('evaluateMergeCheck (EN-5, EN-6, AT-2)', () => {
  it('changes that touch no sensitive paths merge freely', async () => {
    expect(await run('', { files: DOCS })).toEqual({ success: true, outcome: 'pass_not_sensitive', message: 'Threatline: no security-sensitive changes.' });
  });

  it('a sensitive change with no attestation fails and says how to get one', async () => {
    expect(await run('Adds HMAC verification.')).toEqual({
      success: false,
      outcome: 'fail_missing',
      message: "Threatline: this change touches security-sensitive files (src/auth/webhook.ts) and has no attestation. Ask your IDE agent for get-merge-attestation on PAY-7, or click Copy attestation in Jira.",
    });
  });

  it('names "the linked issue" when no key is in the title or branch, and at most three files', async () => {
    const files = ['src/auth/a.ts', 'src/auth/b.ts', 'src/auth/c.ts', 'src/auth/d.ts'].map((path) => ({ path, status: 'modified' as const, linesAdded: 1 }));
    const r = await evaluateMergeCheck({ pr: { ...pr(''), title: 'Tidy', branch: 'tidy' }, files, repoPolicyYaml: null, settings: settings(), nowSec: NOW });
    expect(r.message).toBe("Threatline: this change touches security-sensitive files (src/auth/a.ts, src/auth/b.ts, src/auth/c.ts) and has no attestation. Ask your IDE agent for get-merge-attestation on the linked issue, or click Copy attestation in Jira.");
  });

  it('a valid attestation for the head commit passes', async () => {
    expect(await run(`Ready.\n${token()}`)).toEqual({ success: true, outcome: 'pass_attested', message: 'Threatline: attested by PAY-7, 2 requirements verified.' });
  });

  it('a token pasted through Bitbucket’s Markdown editor (underscores escaped as \\_) still verifies', async () => {
    let t = token();
    for (let n = 0; !t.includes('_') && n < 50; n++) t = token({ nonce: `nonce${n}` });
    expect(t).toContain('_');
    const markdown = `Threatline attestation for PAY-7 \\(expires soon\\):  \n${t.replace(/_/g, '\\_').replace(/-/g, '\\-')}`;
    expect((await run(markdown)).outcome).toBe('pass_attested');
  });

  it('Review Focus 3: an older attestation for commit A and a newer one for head B passes', async () => {
    const older = token({ commitSha: OLD, iat: NOW - 7200, nonce: 'older1' });
    const newer = token({ commitSha: HEAD, iat: NOW - 60, nonce: 'newer1' });
    expect((await run(`${older}\n\nUpdated:\n${newer}`)).outcome).toBe('pass_attested');
    expect((await run(`${newer}\n\n${older}`)).outcome).toBe('pass_attested');
  });

  it('only another repository’s attestation → fail_other_repo', async () => {
    const r = await run(token({ repo: 'acme/other' }));
    expect(r).toMatchObject({ success: false, outcome: 'fail_other_repo' });
    expect(r.message).toMatch(/acme\/other/);
  });

  it('one edited character → fail_signature with the exact copy', async () => {
    const t = token();
    const i = t.length - 5;
    const edited = t.slice(0, i) + (t[i] === 'A' ? 'B' : 'A') + t.slice(i + 1);
    expect(await run(edited)).toEqual({ success: false, outcome: 'fail_signature', message: 'Threatline: attestation signature invalid. Copy a fresh attestation from the Jira issue panel.' });
    const body = t.split('.')[2]!;
    const garbled = t.replace(body, body.slice(0, 10) + (body[10] === 'x' ? 'y' : 'x') + body.slice(11));
    expect((await run(garbled)).outcome).toBe('fail_signature');
  });

  it('a token signed by an untrusted key → fail_signature; no configured key says so', async () => {
    const other = generateKeyPair();
    expect((await run(token({}, other))).outcome).toBe('fail_signature');
    const r = await run(token(), { s: settings({ publicKeys: {} }) });
    expect(r).toMatchObject({ success: false, outcome: 'fail_signature' });
    expect(r.message).toMatch(/no Threatline public key/);
  });

  it('an attestation for an older commit → fail_stale_commit with both short hashes', async () => {
    expect(await run(token({ commitSha: OLD }))).toEqual({
      success: false,
      outcome: 'fail_stale_commit',
      message: 'Threatline: attestation is for commit aaaaaaa but the PR head is bbbbbbb. Request a new attestation for the latest commit.',
    });
  });

  it('bug 4a: a token with a lifetime longer than Threatline issues is refused, saying why', async () => {
    expect(await run(token({ iat: NOW - 60, exp: NOW + 400 * 86_400 }))).toEqual({
      success: false,
      outcome: 'fail_signature',
      message: 'Threatline: this attestation is valid for longer than Threatline ever issues (7 days), so it is refused. Request a new one from the Jira issue panel.',
    });
  });

  it('bug 4b: a trusted key with a retire date stops verifying from then on, with a clear message', async () => {
    const old = generateKeyPair();
    const retiring = (at: number) => settings({ publicKeys: { [key.kid]: key.publicKey, [old.kid]: old.publicKey }, keyRetireAt: { [old.kid]: new Date(at * 1000).toISOString() } });
    expect(await run(token({}, old), { s: retiring(NOW + 60) })).toMatchObject({ success: true, outcome: 'pass_attested' });
    expect(await run(token({}, old), { s: retiring(NOW - 60) })).toEqual({
      success: false,
      outcome: 'fail_signature',
      message: `Threatline: this attestation is signed with key ${old.kid}, which this repository retired at 2025-11-15 11:59 UTC. Request a new attestation (it is signed with Threatline's current key).`,
    });
    // The current key still works next to a retired one.
    expect(await run(token(), { s: retiring(NOW - 60) })).toMatchObject({ success: true });
    // A second work item's token signed by the retired key does not count either.
    const multi = await evaluateMergeCheck({ pr: { ...pr(`${token()}\n${token({ issueKey: 'PAY-6', nonce: 'n0nce2' }, old)}`), title: 'PAY-7 and PAY-6' }, files: AUTH, repoPolicyYaml: null, settings: retiring(NOW - 60), nowSec: NOW });
    expect(multi).toMatchObject({ success: false, outcome: 'fail_other_issue' });
  });

  it('an expired attestation → fail_expired with the time', async () => {
    expect(await run(token({ iat: NOW - 90_000, exp: NOW - 3600 }))).toEqual({ success: false, outcome: 'fail_expired', message: 'Threatline: attestation expired at 2025-11-15 11:00 UTC. Request a new one.' });
  });

  it('security: an attestation for a different work item than the PR names fails (no borrowing a passing item’s token)', async () => {
    const r = await run(token({ issueKey: 'PAY-99' }));
    expect(r).toEqual({
      success: false,
      outcome: 'fail_other_issue',
      message: 'Threatline: the attestation is for PAY-99, but this pull request is for PAY-7. Request an attestation from PAY-7.',
    });
  });

  it('final review I1: a PR naming several work items needs a valid attestation for each, not just one of them', async () => {
    const multi = (description: string) =>
      evaluateMergeCheck({ pr: { ...pr(description), title: 'PAY-6: harden refunds, see PAY-7', branch: 'feature/PAY-6-webhook' }, files: AUTH, repoPolicyYaml: null, settings: settings(), nowSec: NOW });
    expect(await multi(token())).toEqual({
      success: false,
      outcome: 'fail_other_issue',
      message: 'Threatline: this pull request also names PAY-6, which has no valid attestation for this commit. Add one from PAY-6, or remove PAY-6 from the title and branch name.',
    });
    expect(await multi(`${token()}\n${token({ issueKey: 'PAY-6', nonce: 'n0nce2', iat: NOW - 30 })}`)).toMatchObject({ success: true, outcome: 'pass_attested' });
    // A second token that is for another commit does not count.
    expect(await multi(`${token()}\n${token({ issueKey: 'PAY-6', nonce: 'n0nce3', commitSha: OLD, iat: NOW - 120 })}`)).toMatchObject({ success: false, outcome: 'fail_other_issue' });
  });

  it('bug 7: the attestation must name exactly the head commit (no prefix match on a short hash)', async () => {
    const lookalike = `${HEAD.slice(0, 12)}${'c'.repeat(28)}`;
    expect(await run(token({ commitSha: lookalike }))).toMatchObject({ success: false, outcome: 'fail_stale_commit' });
    // A short head (what Bitbucket's pull request API reports) is never accepted by the gate itself.
    expect(await run(token(), { head: HEAD.slice(0, 12) })).toMatchObject({ success: false, outcome: 'fail_stale_commit', message: expect.stringMatching(/full 40-character/) });
  });

  it('bug 8: a key next to an underscore (PAY-7_fix) is still a named work item that needs its own attestation', async () => {
    const named = (title: string, branch: string, description = token({ issueKey: 'PAY-6' })) =>
      evaluateMergeCheck({ pr: { ...pr(description), title, branch }, files: AUTH, repoPolicyYaml: null, settings: settings(), nowSec: NOW });
    for (const branch of ['PAY-7_fix', 'feature/PAY-7_hotfix', 'fix_PAY-7', 'pay-7-fix', 'feature/pay-7_fix'])
      expect(await named('PAY-6 harden refunds', branch)).toMatchObject({ success: false, outcome: 'fail_other_issue', message: expect.stringMatching(/also names PAY-7/) });
    // A lowercase look-alike in another project is not a work item (no false requirement): utf-8, sha-256.
    expect(await named('PAY-6 parse utf-8 bodies', 'feature/sha-256-hmac')).toMatchObject({ success: true, outcome: 'pass_attested' });
    // An underscore-adjacent key alone is recognised for the attestation.
    expect(await named('Harden refunds', 'PAY-6_hotfix')).toMatchObject({ success: true, outcome: 'pass_attested' });
    // Lowercase only counts next to an uppercase key of the same project: alone it is not a key.
    expect(await named('Harden refunds', 'pay-6-fix')).toMatchObject({ success: false, outcome: 'fail_other_issue', message: expect.stringMatching(/names no Jira work item/) });
  });

  it('a standard named next to the work item (SHA-256, CVE-2025-1234) is not a second work item needing an attestation', async () => {
    const titled = (title: string, branch = 'feature/x') => evaluateMergeCheck({ pr: { ...pr(token()), title, branch }, files: AUTH, repoPolicyYaml: null, settings: settings(), nowSec: NOW });
    expect(await titled('PAY-7 switch to SHA-256')).toMatchObject({ success: true, outcome: 'pass_attested' });
    expect(await titled('Fix CVE-2025-1234 in PAY-7')).toMatchObject({ success: true, outcome: 'pass_attested' });
    expect(await titled('Harden webhooks', 'fix/PAY-7-SHA-256')).toMatchObject({ success: true, outcome: 'pass_attested' });
    // A standard alone names no work item.
    expect(await titled('Switch to SHA-256', 'fix/CVE-2025-1234')).toMatchObject({ success: false, outcome: 'fail_other_issue', message: expect.stringMatching(/names no Jira work item/) });
  });

  it('a garbage token claiming a later iat does not hide a valid attestation behind it', async () => {
    const valid = token();
    const stranger = generateKeyPair();
    const forged = token({ iat: NOW + 10, nonce: 'forged1' }, stranger); // untrusted key, newer claimed time
    const body = valid.split('.')[2]!;
    const tampered = valid.replace(body, Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(body, 'base64url').toString()), iat: NOW })).toString('base64url'));
    for (const description of [`${forged}\n${valid}`, `${valid}\n${forged}`, `${tampered}\n${valid}`])
      expect(await run(description)).toMatchObject({ success: true, outcome: 'pass_attested' });
    // None verifies: the newest one's failure is reported, as before.
    expect(await run(`${forged}\n${token({ iat: NOW - 90_000, exp: NOW - 3600 })}`)).toMatchObject({ success: false, outcome: 'fail_signature' });
    expect(await run(`${token({ iat: NOW - 90_000, exp: NOW - 3600 })}\n${token({ iat: NOW - 200_000, exp: NOW - 7200, nonce: 'n0nce2' }, stranger)}`)).toMatchObject({ success: false, outcome: 'fail_expired' });
  });

  it('M9: an attestation for a review made with partial context says so in the check message', async () => {
    expect(await run(token({ partial: true }))).toMatchObject({ success: true, outcome: 'pass_attested', message: expect.stringMatching(/reviewed with partial context/) });
  });

  it('M8: a project key with an underscore (allowed by Jira and the attestation schema) is recognised in the title', async () => {
    const r = await evaluateMergeCheck({ pr: { ...pr(token({ issueKey: 'MY_PROJ-12' })), title: 'MY_PROJ-12 harden webhook', branch: 'feature/x' }, files: AUTH, repoPolicyYaml: null, settings: settings(), nowSec: NOW });
    expect(r).toMatchObject({ success: true, outcome: 'pass_attested' });
  });

  it('security: a PR that names no work item cannot pass on an attestation', async () => {
    const r = await evaluateMergeCheck({ pr: { ...pr(token()), title: 'Tidy', branch: 'tidy' }, files: AUTH, repoPolicyYaml: null, settings: settings(), nowSec: NOW });
    expect(r).toMatchObject({ success: false, outcome: 'fail_other_issue', message: expect.stringMatching(/Put the work item key \(PAY-7\) in the pull request title or branch name/) });
  });

  it('final review I2: warn mode ends at warnUntil (at most 14 days); an ended or undated warn mode blocks again', async () => {
    const ended = await run('', { s: settings({ mode: 'warn', warnUntil: new Date((NOW - 60) * 1000).toISOString() }) });
    expect(ended).toMatchObject({ success: false, outcome: 'fail_missing', message: expect.stringMatching(/^Threatline: warn-only mode ended 2025-11-15 11:59 UTC, so this check blocks again\. /) });
    expect(await run('', { s: settings({ mode: 'warn' }) })).toMatchObject({ success: false, outcome: 'fail_missing' });
  });

  it('warn mode turns a failure into success with a Warning: prefix', async () => {
    const r = await run('', { s: settings({ mode: 'warn', warnUntil: new Date((NOW + 86_400) * 1000).toISOString() }) });
    expect(r).toMatchObject({ success: true, outcome: 'warn' });
    expect(r.message).toMatch(/^Warning: Threatline: this change touches security-sensitive files/);
  });

  it('an attestation issued under warn-only or break-glass passes but says so', async () => {
    expect((await run(token({ override: 'break_glass' }))).message).toBe('Warning: attested under a break-glass override. Threatline: attested by PAY-7, 2 requirements verified.');
  });

  it('policy.yml adds sensitive paths and can only lower the threshold (it never weakens the gate)', async () => {
    const billing = [{ path: 'billing/invoice.ts', status: 'modified' as const, linesAdded: 3 }];
    expect((await run('', { files: billing })).outcome).toBe('pass_not_sensitive');
    expect((await run('', { files: billing, yaml: fixture('policy/billing.yml') })).outcome).toBe('fail_missing');
    // The file asks for 60 but the repo setting (40) is lower, so src/auth still needs an attestation.
    expect((await run('', { yaml: fixture('policy/billing.yml') })).outcome).toBe('fail_missing');
    expect((await run('', { yaml: 'sensitivePaths: []\nmode: warn\n' })).outcome).toBe('fail_missing');
  });

  it('bug 1: editing, deleting or shadowing the gate configuration is always sensitive (no loosening policy.yml in one PR)', async () => {
    const f = (path: string, status: 'modified' | 'removed' | 'added' = 'modified') => [{ path, status, linesAdded: status === 'removed' ? 0 : 1 }];
    for (const files of [
      f('.threatline/policy.yml'),
      f('.threatline/policy.yml', 'removed'),
      f('.threatline/policy.yml', 'added'), // an empty file that shadows a legacy .redline/policy.yml
      f('.redline/policy.yml', 'removed'),
      f('bitbucket-pipelines.yml'),
      f('.github/actions/setup/action.yml'),
      [{ path: 'docs/old-policy.yml', oldPath: '.threatline/policy.yml', status: 'renamed' as const, linesAdded: 0 }],
    ])
      expect((await run('', { files, s: settings({ sensitivePaths: [] }) })).outcome).toBe('fail_missing');
  });

  it('an invalid policy.yml on the target branch fails closed: the change needs an attestation', async () => {
    const r = await run('', { files: DOCS, yaml: 'sensitivePaths: [unclosed' });
    expect(r).toMatchObject({ success: false, outcome: 'fail_missing' });
    expect(r.message).toMatch(/README\.md/);
  });

  it('a high diff score without a sensitive path still needs an attestation', async () => {
    const deps = [{ path: 'package.json', status: 'modified' as const, linesAdded: 1 }, { path: 'lib/session.ts', status: 'modified' as const, linesAdded: 4 }];
    expect((await run('', { files: deps })).outcome).toBe('fail_missing');
  });
});

describe('runMergeCheck: reads the PR, its diffstat, the destination policy and repo settings', () => {
  function client(o: { description: string; diff?: string; policy?: string | null; fail?: 'pr' | 'diff' | 'commit'; patch?: string | null; fullHead?: string }) {
    const calls: string[] = [];
    const prJson = JSON.parse(fixture('pr/auth-change.json').replace('{{ATTESTATION}}', o.description.replace(/\n/g, '\\n')));
    const c: BitbucketClient = {
      pullRequest: async (_ws, _repo, id) => (calls.push(`pr:${id}`), o.fail === 'pr' ? { ok: false, error: { code: 'upstream', message: '500' } } : { ok: true, value: prJson }),
      diffstat: async (_ws, _repo, id) => (calls.push(`diff:${id}`), o.fail === 'diff' ? { ok: false, error: { code: 'upstream', message: '500' } } : { ok: true, value: JSON.parse(o.diff ?? fixture('diffstat/auth-change.json')).values }),
      fileAt: async (_ws, _repo, commit, path) => (calls.push(`file:${commit}:${path}`), { ok: true, value: o.policy ?? null }),
      diff: async (_ws, _repo, id) => (calls.push(`patch:${id}`), o.patch === null ? { ok: false, error: { code: 'upstream', message: '500' } } : { ok: true, value: o.patch ?? '' }),
      headCommit: async (_ws, _repo, id, hash) => (calls.push(`head:${id}:${hash}`), o.fail === 'commit' ? { ok: false, error: { code: 'upstream', message: '500' } } : { ok: true, value: o.fullHead ?? 'b'.repeat(40) }),
    };
    return { c, calls };
  }
  const event = { workspace: { uuid: '{ws}' }, repository: { uuid: '{repo-uuid}' }, pullrequest: { id: 7 }, trigger: { type: 'pre-merge' } };

  it('passes with a valid attestation and reads policy.yml from the destination commit', async () => {
    const { c, calls } = client({ description: token({ commitSha: 'b'.repeat(40) }) });
    const r = await runMergeCheck(event, { client: c, settings: async () => settings(), nowSec: () => NOW });
    expect(r).toEqual({ success: true, message: 'Threatline: attested by PAY-7, 2 requirements verified.' });
    expect(calls).toContain('file:dddddddddddd:.threatline/policy.yml');
    // No .threatline/policy.yml: the file's name from before the rename is read instead.
    expect(calls).toContain('file:dddddddddddd:.redline/policy.yml');
  });

  it('bug 7: resolves Bitbucket’s short head hash to the full commit, and fails closed when it cannot', async () => {
    const t = token({ commitSha: 'b'.repeat(40) });
    const { c, calls } = client({ description: t });
    expect(await runMergeCheck(event, { client: c, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: true });
    expect(calls).toContain('head:7:bbbbbbbbbbbb');
    // The short hash resolves to a different commit than the attestation names (same 12-character prefix).
    const { c: other } = client({ description: t, fullHead: `${'b'.repeat(12)}${'e'.repeat(28)}` });
    expect(await runMergeCheck(event, { client: other, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: false, message: expect.stringMatching(/attestation is for commit/) });
    for (const bad of [client({ description: t, fail: 'commit' }).c, client({ description: t, fullHead: 'f'.repeat(40) }).c, client({ description: t, fullHead: 'bbbb' }).c])
      expect(await runMergeCheck(event, { client: bad, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: false, message: expect.stringMatching(/could not read this pull request from Bitbucket \(head commit\)/) });
  });

  it('seam review 4: a docs-only PR passes even when Bitbucket cannot list its commits (the head is only looked up when needed)', async () => {
    const { c, calls } = client({ description: '', diff: fixture('diffstat/docs-only.json'), fail: 'commit' });
    expect(await runMergeCheck(event, { client: c, settings: async () => settings(), nowSec: () => NOW })).toEqual({ success: true, message: 'Threatline: no security-sensitive changes.' });
    expect(calls.some((x) => x.startsWith('head:'))).toBe(false);
  });

  it('a docs-only PR passes without an attestation', async () => {
    const { c } = client({ description: '', diff: fixture('diffstat/docs-only.json') });
    expect(await runMergeCheck(event, { client: c, settings: async () => settings(), nowSec: () => NOW })).toEqual({ success: true, message: 'Threatline: no security-sensitive changes.' });
  });

  it('fails closed when Bitbucket cannot be read (and warns in warn mode)', async () => {
    const { c } = client({ description: '', fail: 'diff' });
    const r = await runMergeCheck(event, { client: c, settings: async () => settings(), nowSec: () => NOW });
    expect(r.success).toBe(false);
    expect(r.message).toMatch(/could not read this pull request/);
    expect((await runMergeCheck(event, { client: c, settings: async () => settings({ mode: 'warn', warnUntil: new Date((NOW + 60) * 1000).toISOString() }), nowSec: () => NOW })).success).toBe(true);
  });

  it('M7: a secret added in a file outside the sensitive paths still needs an attestation (the diff text is read)', async () => {
    const patch = [
      'diff --git a/README.md b/README.md',
      '--- a/README.md',
      '+++ b/README.md',
      '@@ -1,2 +1,3 @@',
      ' # Docs',
      // nosemgrep: detected-aws-access-key-id-value -- fake key (see .gitleaks.toml)
      '+aws_access_key_id = AKIAABCDEFGHIJKLMNOP',
    ].join('\n');
    const { c, calls } = client({ description: '', diff: fixture('diffstat/docs-only.json'), patch });
    expect(await runMergeCheck(event, { client: c, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: false, message: expect.stringMatching(/has no attestation/) });
    expect(calls).toContain('patch:7');
    // Fail closed: diff text that cannot be read is treated as sensitive, like a file list that is too long to read.
    const { c: c2 } = client({ description: '', diff: fixture('diffstat/docs-only.json'), patch: null });
    expect(await runMergeCheck(event, { client: c2, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: false, message: expect.stringMatching(/diff text Threatline could not read/) });
  });

  it('security review: a fake file header inside a hunk cannot hide a secret from the scan, and a truncated diff is sensitive', async () => {
    const patch = [
      'diff --git a/README.md b/README.md',
      '--- a/README.md',
      '+++ b/README.md',
      '@@ -1,1 +1,3 @@',
      '++++ b/not-in-this-pr.txt',
      // nosemgrep: detected-aws-access-key-id-value -- fake key (see .gitleaks.toml)
      '+aws_access_key_id = AKIAABCDEFGHIJKLMNOP',
    ].join('\n');
    const { c } = client({ description: '', diff: fixture('diffstat/docs-only.json'), patch });
    expect(await runMergeCheck(event, { client: c, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: false, message: expect.stringMatching(/has no attestation/) });
    const huge = `diff --git a/README.md b/README.md\n+++ b/README.md\n${'+x\n'.repeat(1_100_000)}`;
    const { c: c3 } = client({ description: '', diff: fixture('diffstat/docs-only.json'), patch: huge });
    expect(await runMergeCheck(event, { client: c3, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: false });
  });

  it('a Bitbucket read that throws (network error, a body that is not JSON) fails closed with the re-run message', async () => {
    const t = token({ commitSha: 'b'.repeat(40) });
    const boom = async () => {
      throw new TypeError('fetch failed');
    };
    const cases: Array<[keyof BitbucketClient, RegExp]> = [
      ['pullRequest', /\(pull request\)/],
      ['diffstat', /\(changed files\)/],
      ['fileAt', /\(policy file\)/],
      ['headCommit', /\(head commit\)/],
    ];
    for (const [method, why] of cases) {
      const { c } = client({ description: t });
      const broken = { ...c, [method]: boom } as BitbucketClient;
      expect(await runMergeCheck(event, { client: broken, settings: async () => settings(), nowSec: () => NOW }), method).toEqual({
        success: false,
        message: expect.stringMatching(new RegExp(`could not read this pull request from Bitbucket ${why.source}, so it cannot be checked\\. Re-run the check in a minute\\.`)),
      });
    }
    // Diff text that throws is unread text: sensitive, never a pass.
    const { c } = client({ description: '', diff: fixture('diffstat/docs-only.json') });
    expect(await runMergeCheck(event, { client: { ...c, diff: boom }, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: false, message: expect.stringMatching(/diff text Threatline could not read/) });
    // Through the real client: requestBitbucket rejecting, or a 200 whose body is not JSON.
    const notJson = bitbucketClient(async () => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => JSON.parse('<html>'), text: async () => '<html>' }));
    const offline = bitbucketClient(async () => Promise.reject(new TypeError('fetch failed')));
    for (const real of [notJson, offline])
      expect(await runMergeCheck(event, { client: real, settings: async () => settings(), nowSec: () => NOW })).toMatchObject({ success: false, message: expect.stringMatching(/Re-run the check in a minute/) });
    // Warn mode still only warns.
    const warn = settings({ mode: 'warn', warnUntil: new Date((NOW + 60) * 1000).toISOString() });
    expect(await runMergeCheck(event, { client: offline, settings: async () => warn, nowSec: () => NOW })).toMatchObject({ success: true, message: expect.stringMatching(/^Warning: /) });
  });

  it('I2 follow-up: an unreadable pull request blocks once warn mode has ended', async () => {
    const { c } = client({ description: '', fail: 'diff' });
    const ended = settings({ mode: 'warn', warnUntil: new Date((NOW - 60) * 1000).toISOString() });
    expect((await runMergeCheck(event, { client: c, settings: async () => ended, nowSec: () => NOW })).success).toBe(false);
  });

  it('bug 3: settings that cannot be read (storage down, or a stored value that no longer parses) fail closed', async () => {
    const billing = JSON.stringify({ values: [{ status: 'modified', lines_added: 3, old: { path: 'billing/invoice.ts' }, new: { path: 'billing/invoice.ts' } }] });
    const { c } = client({ description: '', diff: billing });
    // With the admin's settings, billing/** is sensitive; with no settings ever saved, it is not.
    expect(await runMergeCheck(event, { client: c, settings: async () => settings({ sensitivePaths: ['billing/**'] }), nowSec: () => NOW })).toMatchObject({ success: false });
    expect(await runMergeCheck(event, { client: c, settings: async () => null, nowSec: () => NOW })).toMatchObject({ success: true });
    const kv = new Map<string, unknown>([['settings:0b1c2d3e-0000-4000-8000-000000000001', { mode: 'sideways' }]]);
    const corrupt = kvsSettingsStore({ get: async (k) => kv.get(k) as never, set: async () => undefined });
    for (const read of [async () => Promise.reject(new Error('kvs down')), (uuid: string) => corrupt.get(uuid)]) {
      const r = await runMergeCheck({ ...event, repository: { uuid: '{0b1c2d3e-0000-4000-8000-000000000001}' } }, { client: c, settings: read, nowSec: () => NOW });
      expect(r).toEqual({ success: false, message: "Threatline: could not read this repository's Threatline settings, so this pull request cannot be checked. Re-run the check in a minute." });
    }
  });

  it('a repository with no settings yet uses the defaults: block mode and the built-in sensitive paths', async () => {
    const { c } = client({ description: '' });
    expect(await runMergeCheck(event, { client: c, settings: async () => null, nowSec: () => NOW })).toMatchObject({ success: false, message: expect.stringMatching(/no Threatline public key|has no attestation/) });
  });
});
