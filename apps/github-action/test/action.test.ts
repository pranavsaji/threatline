import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { encodeAttestation, generateKeyPair } from '@threatline/crypto';
import type { AttestationPayload } from '@threatline/shared';
import { nowSecFrom, parseInputs, runGitHubCheck, type GitHubClient, type GitHubFile, type GitHubPr } from '../src/run.js';

const NOW = 1_763_208_000; // 2025-11-15T12:00:00Z
const HEAD = 'c'.repeat(40);
const REPO = 'acme/payments';
const key = generateKeyPair();

function token(o: Partial<AttestationPayload> = {}): string {
  return encodeAttestation(
    { v: 1, kid: key.kid, issueKey: 'PAY-7', repo: REPO, commitSha: HEAD, verdict: 'pass', requirements: [{ id: 'req_1', status: 'Verified' }], iat: NOW - 60, exp: NOW + 3600, nonce: 'n0nce1', ...o },
    key,
  );
}
const PR = (body: string | null, o: Partial<GitHubPr> = {}): GitHubPr => ({ body, title: 'PAY-7 Verify refund webhook signatures', head: { sha: HEAD, ref: 'feature/PAY-7-hmac' }, base: { sha: 'b'.repeat(40), repo: { full_name: REPO } }, ...o });
const AUTH: GitHubFile = { filename: 'src/auth/webhook.ts', status: 'modified', additions: 40, patch: '@@ -1 +1 @@\n+export const verify = true;' };
const DOCS: GitHubFile = { filename: 'README.md', status: 'modified', additions: 1, patch: '@@ -1 +1 @@\n+More docs.' };

function client(o: { pr?: GitHubPr | 'fail'; files?: GitHubFile[] | 'fail'; truncated?: boolean; policy?: string | null | 'fail' } = {}): GitHubClient {
  return {
    pullRequest: async () => (o.pr === 'fail' ? { ok: false, status: 502 } : { ok: true, value: o.pr ?? PR(null) }),
    files: async () => (o.files === 'fail' ? { ok: false, status: 502 } : { ok: true, value: { files: o.files ?? [AUTH], truncated: o.truncated ?? false } }),
    fileAt: async () => (o.policy === 'fail' ? { ok: false, status: 500 } : { ok: true, value: o.policy ?? null }),
  };
}
const inputs = (o: Record<string, string> = {}) => {
  const r = parseInputs({ 'public-keys': key.publicKey, ...o }, NOW);
  if (!r.ok) throw new Error(r.message);
  return r.value;
};

describe('parseInputs (GitHub Action inputs)', () => {
  it('derives each key id from the pasted public keys, one per line, like Threatline for Bitbucket', () => {
    const other = generateKeyPair();
    expect(inputs({ 'public-keys': `${key.publicKey}\n\n  ${other.publicKey}  ` }).publicKeys).toEqual({ [key.kid]: key.publicKey, [other.kid]: other.publicKey });
  });
  it('bug 4b: a public-keys line can carry a retire date; tokens signed by that key fail after it', async () => {
    const old = generateKeyPair();
    const s = inputs({ 'public-keys': `${key.publicKey}\n${old.publicKey} until=2025-11-15T11:00:00Z` });
    expect(s.keyRetireAt).toEqual({ [old.kid]: '2025-11-15T11:00:00.000Z' });
    const signedByOld = encodeAttestation({ v: 1, kid: old.kid, issueKey: 'PAY-7', repo: REPO, commitSha: HEAD, verdict: 'pass', requirements: [], iat: NOW - 60, exp: NOW + 3600, nonce: 'n0nce9' }, old);
    expect(await runGitHubCheck({ settings: s, client: client({ pr: PR(signedByOld) }), nowSec: NOW })).toMatchObject({ success: false, message: expect.stringMatching(/retired at 2025-11-15 11:00 UTC/) });
    expect(parseInputs({ 'public-keys': `${old.publicKey} until=soon` }, NOW)).toMatchObject({ ok: false, message: expect.stringMatching(/until=/) });
  });

  it('public-keys is required: with no key the gate is a configuration error, not a check every pull request fails', () => {
    for (const keys of [undefined, '', '  \n \n'])
      expect(parseInputs({ 'public-keys': keys }, NOW)).toMatchObject({ ok: false, message: expect.stringMatching(/public-keys is required when merge-gate is on/) });
  });

  it('THREATLINE_NOW is honoured only as a positive whole number of seconds; anything else is the real clock', () => {
    const real = Date.UTC(2026, 0, 1);
    expect(nowSecFrom(String(NOW), real)).toBe(NOW);
    expect(nowSecFrom(` ${NOW} `, real)).toBe(NOW);
    for (const raw of [undefined, '', 'x', 'NaN', '0', '-5', '1.5', '1e9', 'Infinity', '99999999999999999999'])
      expect(nowSecFrom(raw, real), String(raw)).toBe(real / 1000);
  });

  it('rejects a malformed key, an unknown mode, and a bad threshold', () => {
    expect(parseInputs({ 'public-keys': 'not-a-key' }, NOW)).toMatchObject({ ok: false, message: expect.stringMatching(/public key/) });
    expect(parseInputs({ 'public-keys': key.publicKey, mode: 'off' }, NOW)).toMatchObject({ ok: false, message: expect.stringMatching(/mode/) });
    expect(parseInputs({ 'public-keys': key.publicKey, 'diff-score-threshold': '101' }, NOW)).toMatchObject({ ok: false });
  });
  it('warn mode needs an end date at most 14 days away (warn-only expires)', () => {
    const day = 86_400;
    const at = (d: number) => new Date((NOW + d * day) * 1000).toISOString();
    expect(parseInputs({ 'public-keys': key.publicKey, mode: 'warn' }, NOW)).toMatchObject({ ok: false, message: expect.stringMatching(/warn-until/) });
    expect(parseInputs({ 'public-keys': key.publicKey, mode: 'warn', 'warn-until': at(15) }, NOW)).toMatchObject({ ok: false, message: expect.stringMatching(/14 days/) });
    expect(inputs({ mode: 'warn', 'warn-until': at(10) })).toMatchObject({ mode: 'warn', warnUntil: at(10) });
  });
});

describe('runGitHubCheck (the merge gate on GitHub)', () => {
  it("changing the gate's own configuration is always sensitive (workflows, local actions, .threatline)", async () => {
    for (const filename of ['.github/workflows/threatline.yml', '.github/actions/setup/action.yml', '.threatline/policy.yml'])
      expect(await runGitHubCheck({ settings: inputs(), client: client({ files: [{ ...DOCS, filename }] }), nowSec: NOW })).toMatchObject({ success: false, outcome: 'fail_missing' });
  });
  it('changes that touch no sensitive paths merge freely', async () => {
    expect(await runGitHubCheck({ settings: inputs(), client: client({ files: [DOCS] }), nowSec: NOW })).toMatchObject({ success: true, outcome: 'pass_not_sensitive' });
  });
  it('a sensitive change passes with a valid attestation for the head commit and the named work item', async () => {
    const r = await runGitHubCheck({ settings: inputs(), client: client({ pr: PR(`Fixes the webhook.\n\n${token()}`) }), nowSec: NOW });
    expect(r).toMatchObject({ success: true, outcome: 'pass_attested', message: expect.stringMatching(/attested by PAY-7/) });
  });
  it('a sensitive change without an attestation is blocked, saying how to get one', async () => {
    const r = await runGitHubCheck({ settings: inputs(), client: client({ pr: PR(null) }), nowSec: NOW });
    expect(r).toMatchObject({ success: false, outcome: 'fail_missing', message: expect.stringMatching(/get-merge-attestation on PAY-7/) });
  });
  it('a new commit after the attestation is blocked as stale', async () => {
    const r = await runGitHubCheck({ settings: inputs(), client: client({ pr: PR(token(), { head: { sha: 'd'.repeat(40), ref: 'feature/PAY-7-hmac' } }) }), nowSec: NOW });
    expect(r).toMatchObject({ success: false, outcome: 'fail_stale_commit' });
  });
  it('a secret added to any file makes the change sensitive', async () => {
    // nosemgrep: detected-aws-access-key-id-value -- fake key (see .gitleaks.toml)
    const leak: GitHubFile = { ...DOCS, patch: '@@ -1 +1 @@\n+aws_access_key_id = AKIAABCDEFGHIJKLMNOP' };
    expect(await runGitHubCheck({ settings: inputs(), client: client({ files: [leak] }), nowSec: NOW })).toMatchObject({ success: false, outcome: 'fail_missing' });
  });
  it('fails closed: a text diff GitHub would not return, or more files than it lists, counts as sensitive', async () => {
    const big: GitHubFile = { filename: 'docs/huge.md', status: 'modified', additions: 9000 };
    expect(await runGitHubCheck({ settings: inputs(), client: client({ files: [big] }), nowSec: NOW })).toMatchObject({ success: false, outcome: 'fail_missing' });
    expect(await runGitHubCheck({ settings: inputs(), client: client({ files: [DOCS], truncated: true }), nowSec: NOW })).toMatchObject({ success: false, outcome: 'fail_missing' });
    // A binary file (no patch, no added lines) is not by itself sensitive.
    expect(await runGitHubCheck({ settings: inputs(), client: client({ files: [{ filename: 'docs/logo.png', status: 'added', additions: 0 }] }), nowSec: NOW })).toMatchObject({ success: true });
  });
  it("the base branch's .threatline/policy.yml can add sensitive paths", async () => {
    const r = await runGitHubCheck({ settings: inputs(), client: client({ files: [DOCS], policy: 'sensitivePaths:\n  - "README.md"\n' }), nowSec: NOW });
    expect(r).toMatchObject({ success: false, outcome: 'fail_missing' });
  });
  it('fails closed when GitHub cannot be read, unless warn-only mode is active', async () => {
    for (const c of [client({ pr: 'fail' }), client({ files: 'fail' }), client({ policy: 'fail' })])
      expect(await runGitHubCheck({ settings: inputs(), client: c, nowSec: NOW })).toMatchObject({ success: false, message: expect.stringMatching(/could not read this pull request from GitHub/) });
    const warn = inputs({ mode: 'warn', 'warn-until': new Date((NOW + 86_400) * 1000).toISOString() });
    expect(await runGitHubCheck({ settings: warn, client: client({ pr: 'fail' }), nowSec: NOW })).toMatchObject({ success: true, message: expect.stringMatching(/^Warning:/) });
  });
  it('with no public key configured, says where to put it on GitHub', async () => {
    const r = await runGitHubCheck({ settings: { ...inputs(), publicKeys: {} }, client: client({ pr: PR(token()) }), nowSec: NOW });
    expect(r.message).toMatch(/public-keys input of the Threatline step/);
  });
});

describe('runtime', () => {
  it('bug 11: runs on Node 24 (GitHub is retiring Node 20 for actions) and the bundle targets the same version', () => {
    expect(readFileSync(new URL('../action.yml', import.meta.url), 'utf8')).toMatch(/^runs:\n {2}using: node24\n/m);
    expect(readFileSync(new URL('../build.mjs', import.meta.url), 'utf8')).toMatch(/target: 'node24'/);
  });
});

// The committed bundle (dist/index.mjs) is what GitHub runs: drive it against a stand-in GitHub API.
describe('the bundled action', () => {
  const dist = new URL('../dist/index.mjs', import.meta.url);
  let server: Server;
  let api = '';
  let body = '';
  beforeAll(async () => {
    server = createServer((req, res) => {
      const url = req.url ?? '';
      res.setHeader('content-type', 'application/json');
      if (req.headers.authorization !== 'Bearer test-token') return res.writeHead(401).end('{}');
      if (url.startsWith('/repos/acme/payments/pulls/12/files')) return res.end(JSON.stringify(url.includes('page=1') ? [AUTH] : []));
      if (url.startsWith('/repos/acme/payments/pulls/12')) return res.end(JSON.stringify(PR(body)));
      if (url.startsWith('/repos/acme/payments/contents/.threatline/policy.yml')) return res.writeHead(404).end('{}');
      res.writeHead(404).end('{}');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    api = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  const runDist = (description: string, eventName = 'pull_request_target', extraEnv: Record<string, string> = {}) => {
    body = description;
    const dir = mkdtempSync(join(tmpdir(), 'threatline-action-'));
    const event = join(dir, 'event.json');
    writeFileSync(event, JSON.stringify({ pull_request: { number: 12 }, repository: { full_name: REPO } }));
    const out = join(dir, 'out.txt');
    const summary = join(dir, 'summary.md');
    writeFileSync(out, '');
    writeFileSync(summary, '');
    // Async, so this process can keep serving the stand-in API while the action runs.
    const child = spawn(process.execPath, [dist.pathname], {
      env: { PATH: process.env.PATH ?? '', GITHUB_EVENT_NAME: eventName, GITHUB_EVENT_PATH: event, GITHUB_API_URL: api, GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: summary, 'INPUT_GITHUB-TOKEN': 'test-token', 'INPUT_PUBLIC-KEYS': key.publicKey, THREATLINE_NOW: String(NOW), ...extraEnv },
    });
    let stdout = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    return new Promise<{ status: number | null; stdout: string; outputs: string; summary: string }>((resolve) =>
      child.on('close', (status) => resolve({ status, stdout, outputs: readFileSync(out, 'utf8'), summary: readFileSync(summary, 'utf8') })),
    );
  };

  it.skipIf(!existsSync(dist))('passes an attested change and blocks an unattested one, with an annotation and outputs', async () => {
    const pass = await runDist(token());
    expect(pass.status).toBe(0);
    expect(pass.outputs).toMatch(/outcome=pass_attested/);
    expect(pass.summary).toMatch(/attested by PAY-7/);
    const fail = await runDist('No attestation here.');
    expect(fail.status).toBe(1);
    expect(fail.stdout).toMatch(/::error title=Threatline::Threatline: this change touches security-sensitive files/);
    expect(fail.outputs).toMatch(/outcome=fail_missing/);
    expect(fail.stdout).not.toMatch(/::warning/);
  });

  it.skipIf(!existsSync(dist))('no public keys is a config_error; a THREATLINE_NOW that is not a number does not switch expiry off', async () => {
    const none = await runDist(token(), 'pull_request_target', { 'INPUT_PUBLIC-KEYS': '' });
    expect(none.status).toBe(1);
    expect(none.outputs).toMatch(/outcome=config_error/);
    // An attestation that expired long ago (by the real clock) stays expired when THREATLINE_NOW is garbage.
    const expired = await runDist(token({ iat: NOW - 60, exp: NOW + 3600 }), 'pull_request_target', { THREATLINE_NOW: 'x' });
    expect(expired.status).toBe(1);
    expect(expired.outputs).toMatch(/outcome=fail_expired/);
  });

  it.skipIf(!existsSync(dist))('warns when run on pull_request, where the pull request controls its own workflow', async () => {
    expect((await runDist(token(), 'pull_request')).stdout).toMatch(/::warning title=Threatline::.*pull_request_target/);
  });
});
