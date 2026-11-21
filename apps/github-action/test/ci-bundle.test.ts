import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const here = fileURLToPath(new URL('..', import.meta.url));
const dist = join(here, 'dist/index.mjs');
const script = join(here, '../../scripts/threatline-ci-report.mjs');
const A = 'req_1a2b3c4d5e6f7a8b';
const TOKEN = 'tlci_0123456789abcdef_' + 'S'.repeat(43);
const SHA = 'c'.repeat(40);

describe('bundle sync (feature: verification from CI)', () => {
  it('the committed action bundle and CI report script are exactly what build.mjs builds from source', () => {
    const out = mkdtempSync(join(tmpdir(), 'threatline-build-'));
    const r = spawnSync(process.execPath, ['build.mjs'], { cwd: here, env: { ...process.env, THREATLINE_BUILD_OUT: out }, encoding: 'utf8' });
    expect(r.status, r.stderr).toBe(0);
    expect(readFileSync(join(out, 'dist/index.mjs'), 'utf8') === readFileSync(dist, 'utf8'), 'dist/index.mjs is stale: run node build.mjs').toBe(true);
    expect(readFileSync(join(out, 'scripts/threatline-ci-report.mjs'), 'utf8') === readFileSync(script, 'utf8'), 'scripts/threatline-ci-report.mjs is stale: run node build.mjs').toBe(true);
  }, 60_000);

  it('the CI report script imports nothing but Node built-ins', () => {
    const imports = [...readFileSync(script, 'utf8').matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const i of imports) expect(i).toMatch(/^node:/);
  });
});

describe('the bundled CI report (GitHub Action and Bitbucket script) against a stand-in Threatline', () => {
  let server: Server;
  let url = '';
  const seen: Array<{ auth?: string; body: Record<string, unknown> }> = [];
  beforeAll(async () => {
    server = createServer((req, res) => {
      let data = '';
      req.on('data', (d: Buffer) => (data += d.toString()));
      req.on('end', () => {
        const body = JSON.parse(data) as Record<string, unknown>;
        seen.push({ ...(req.headers.authorization ? { auth: req.headers.authorization } : {}), body });
        res.setHeader('content-type', 'application/json');
        if (req.headers.authorization !== `Bearer ${TOKEN}`) return res.writeHead(401).end(JSON.stringify({ error: 'unauthorized', message: 'Send Authorization: Bearer <CI token>.' }));
        res.end(JSON.stringify({ issueKey: body.issueKey, commitSha: body.commitSha, verdict: 'pass', verified: 1, ignoredTests: 0, results: [{ requirementId: A, outcome: 'verified', passed: 1, failed: 0, skipped: 0 }] }));
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/ci-verify`;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  const workspace = () => {
    const root = mkdtempSync(join(tmpdir(), 'threatline-ws-'));
    mkdirSync(join(root, 'reports'));
    writeFileSync(join(root, 'reports/TEST-a.xml'), `<testsuite><testcase classname="w" name="${A} rejects"/><testcase name="other"/></testsuite>`);
    return root;
  };
  const run = (file: string, args: string[], env: Record<string, string>) => {
    const child = spawn(process.execPath, [file, ...args], { env: { PATH: process.env.PATH ?? '', ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    return new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => child.on('close', (status) => resolve({ status, stdout, stderr })));
  };

  it('GitHub Action, report only (merge-gate: false) on a push: posts the run and prints what was verified', async () => {
    const root = workspace();
    const out = join(root, 'out.txt');
    writeFileSync(out, '');
    seen.length = 0;
    const r = await run(dist, [], {
      'INPUT_MERGE-GATE': 'false',
      'INPUT_THREATLINE-URL': url,
      'INPUT_THREATLINE-TOKEN': TOKEN,
      INPUT_JUNIT: 'reports/*.xml',
      GITHUB_WORKSPACE: root,
      GITHUB_REPOSITORY: 'acme/payments',
      GITHUB_RUN_ID: '42',
      GITHUB_SHA: SHA,
      GITHUB_REF_NAME: 'PAY-7-webhooks',
      GITHUB_EVENT_NAME: 'push',
      GITHUB_OUTPUT: out,
    });
    expect(r.status, r.stdout).toBe(0);
    expect(seen).toEqual([{ auth: `Bearer ${TOKEN}`, body: { issueKey: 'PAY-7', repo: 'acme/payments', commitSha: SHA, runUrl: 'https://github.com/acme/payments/actions/runs/42', results: [{ name: `w ${A} rejects`, status: 'passed' }] } }]);
    expect(r.stdout).toContain(`::add-mask::${TOKEN}`);
    expect(r.stdout).toMatch(/PAY-7: verified req_1a2b3c4d5e6f7a8b/);
    expect(r.stdout).toMatch(/::notice title=Threatline CI verification::Threatline: 1 requirement verified/);
    expect(readFileSync(out, 'utf8')).toMatch(/ci-report=reported/);
  });

  it('GitHub Action: a partial report setup is a configuration error', async () => {
    const r = await run(dist, [], { 'INPUT_MERGE-GATE': 'false', 'INPUT_THREATLINE-URL': url, GITHUB_EVENT_NAME: 'push' });
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/::error title=Threatline::Threatline: to report test results, set all of/);
  });

  it('Bitbucket Pipelines script: reads the pipeline variables, never echoes the token, and fails on a refused token', async () => {
    const root = workspace();
    const env = { THREATLINE_URL: url, THREATLINE_TOKEN: TOKEN, BITBUCKET_CLONE_DIR: root, BITBUCKET_REPO_FULL_NAME: 'acme/payments', BITBUCKET_BUILD_NUMBER: '17', BITBUCKET_COMMIT: SHA, BITBUCKET_BRANCH: 'feature/PAY-7-hmac' };
    seen.length = 0;
    const ok = await run(script, ['--junit', 'reports/**/*.xml'], env);
    expect(ok.status, ok.stderr).toBe(0);
    expect(seen[0]!.body).toEqual({ issueKey: 'PAY-7', repo: 'acme/payments', commitSha: SHA, runUrl: 'https://bitbucket.org/acme/payments/pipelines/results/17', results: [{ name: `w ${A} rejects`, status: 'passed' }] });
    expect(ok.stdout).toMatch(/PAY-7: verified req_1a2b3c4d5e6f7a8b/);
    expect(ok.stdout + ok.stderr).not.toContain(TOKEN);
    const bad = await run(script, ['--junit', 'reports/*.xml', '--issue-key', 'PAY-8'], { ...env, THREATLINE_TOKEN: 'tlci_0000000000000000_' + 'x'.repeat(43) });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toMatch(/refused \(HTTP 401\)/);
    expect(seen.at(-1)!.body.issueKey).toBe('PAY-8');
    expect((await run(script, ['--token', 'x'], env)).stderr).toMatch(/unknown argument --token/);
  });
});
