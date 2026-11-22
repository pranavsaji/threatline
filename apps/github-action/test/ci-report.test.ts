import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { actionReportConfig, cliReportConfig, findJUnitFiles, globToRegExp, runCiReport, type CiReportInput } from '../src/ci-report.js';

const A = 'req_1a2b3c4d5e6f7a8b';
const B = 'req_0000ffff0000ffff';
const TOKEN = 'tlci_0123456789abcdef_' + 'S'.repeat(43);
const SHA = 'AB'.repeat(20);

function workspace(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'threatline-ci-'));
  for (const [p, body] of Object.entries(files)) {
    mkdirSync(join(root, p, '..'), { recursive: true });
    writeFileSync(join(root, p), body);
  }
  return root;
}
const suite = (cases: string) => `<?xml version="1.0"?><testsuites><testsuite name="s">${cases}</testsuite></testsuites>`;

function fakeFetch(respond: (body: Record<string, unknown>) => Response | Promise<Response>) {
  const calls: Array<{ url: string; headers: Record<string, string>; body: Record<string, unknown> }> = [];
  const f = (async (url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    calls.push({ url: String(url), headers: { ...(init?.headers as Record<string, string>) }, body });
    return respond(body);
  }) as typeof fetch;
  return { f, calls };
}
const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const verified = (b: Record<string, unknown>) =>
  answer(200, { issueKey: b.issueKey, commitSha: b.commitSha, verdict: 'pass', verified: 1, ignoredTests: 0, results: [{ requirementId: A, outcome: 'verified', passed: 2, failed: 0, skipped: 0 }] });

const input = (root: string, o: Partial<CiReportInput> = {}): CiReportInput => ({
  url: 'https://site.atlassian-dev.net/x1/ci',
  token: TOKEN,
  junit: 'reports/**/*.xml',
  root,
  issueKeys: ['PAY-7'],
  repo: 'acme/payments',
  commitSha: SHA,
  runUrl: 'https://github.com/acme/payments/actions/runs/42',
  ...o,
});

describe('actionReportConfig (the action inputs threatline-url, threatline-token, junit)', () => {
  const env = { GITHUB_REPOSITORY: 'acme/payments', GITHUB_RUN_ID: '42', GITHUB_SERVER_URL: 'https://github.com', GITHUB_SHA: 'f'.repeat(40), GITHUB_WORKSPACE: '/w', GITHUB_REF_NAME: 'PAY-9-push' };
  const set = { url: 'https://x/ci', token: TOKEN, junit: 'reports/*.xml' };
  it('is off when none is set, and refuses a partial setup', () => {
    expect(actionReportConfig({}, env, {})).toEqual({ ok: true, value: null });
    expect(actionReportConfig({ url: 'https://x/ci' }, env, {})).toMatchObject({ ok: false, message: expect.stringMatching(/all of/) });
  });
  it('finds the work item like the merge gate (title and branch), with the head commit and the run link', () => {
    const r = actionReportConfig(set, { ...env, GITHUB_RUN_ATTEMPT: '2' }, { pull_request: { title: 'PAY-7 Verify signatures', head: { ref: 'fix_PAY-8', sha: 'c'.repeat(40) } } });
    expect(r).toEqual({ ok: true, value: { ...set, root: '/w', issueKeys: ['PAY-7', 'PAY-8'], repo: 'acme/payments', commitSha: 'c'.repeat(40), runUrl: 'https://github.com/acme/payments/actions/runs/42/attempts/2' } });
  });
  it('on a push, uses the branch name and GITHUB_SHA', () => {
    expect(actionReportConfig(set, env, {})).toMatchObject({ ok: true, value: { issueKeys: ['PAY-9'], commitSha: 'f'.repeat(40), runUrl: 'https://github.com/acme/payments/actions/runs/42' } });
  });
});

describe('globToRegExp / findJUnitFiles', () => {
  it('matches *, ** and {a,b} on /-separated paths, and skips node_modules and .git', () => {
    expect(globToRegExp('reports/**/*.xml').test('reports/a/b/TEST-x.xml')).toBe(true);
    expect(globToRegExp('reports/**/*.xml').test('reports/TEST-x.xml')).toBe(true);
    expect(globToRegExp('reports/*.xml').test('reports/a/TEST-x.xml')).toBe(false);
    expect(globToRegExp('**/TEST-*.{xml,junit}').test('mod/target/surefire-reports/TEST-a.junit')).toBe(true);
    expect(globToRegExp('a?.xml').test('ab.xml')).toBe(true);
    expect(globToRegExp('a.xml').test('abxml')).toBe(false);
    const root = workspace({ 'reports/a.xml': suite(''), 'reports/deep/b.xml': suite(''), 'node_modules/x/reports/c.xml': suite(''), 'reports/notes.txt': '' });
    expect(findJUnitFiles(root, '**/*.xml')).toEqual(['reports/a.xml', 'reports/deep/b.xml']);
    expect(findJUnitFiles(root, 'reports/a.xml\nreports/deep/*.xml')).toEqual(['reports/a.xml', 'reports/deep/b.xml']);
  });
});

describe('runCiReport (feature: verification from CI)', () => {
  it('posts only tests named with a requirement id, with the bearer token, the lowercase commit and the run link', async () => {
    const root = workspace({
      'reports/unit.xml': suite(`<testcase classname="w" name="${A} rejects"/><testcase classname="w" name="${A} replay"><failure/></testcase><testcase name="plain test"/>`),
      'reports/py/py.xml': suite(`<testcase classname="t" name="test_${B}_x"><skipped/></testcase>`),
    });
    const { f, calls } = fakeFetch(verified);
    const r = await runCiReport({ ...input(root), fetch: f });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://site.atlassian-dev.net/x1/ci');
    expect(calls[0]!.headers).toMatchObject({ authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' });
    expect(calls[0]!.body).toEqual({
      issueKey: 'PAY-7',
      repo: 'acme/payments',
      commitSha: SHA.toLowerCase(),
      runUrl: 'https://github.com/acme/payments/actions/runs/42',
      // Files in path order: reports/py/py.xml, then reports/unit.xml.
      results: [
        { name: `t test_${B}_x`, status: 'skipped' },
        { name: `w ${A} rejects`, status: 'passed' },
        { name: `w ${A} replay`, status: 'failed' },
      ],
    });
    expect(r.success).toBe(true);
    expect(r.lines.join('\n')).toMatch(/PAY-7: verified req_1a2b3c4d5e6f7a8b \(2 passed\)/);
    expect(r.lines.join('\n')).toMatch(/PAY-7 verdict: pass/);
    expect(r.message).toMatch(/1 requirement verified/);
    expect(JSON.stringify(r)).not.toContain(TOKEN);
  });

  it('with Threatline\'s static answer (verdict only), summarises each requirement from the JUnit results', async () => {
    const root = workspace({ 'reports/u.xml': suite(`<testcase name="${A} works"/><testcase name="${A} also works"/>`) });
    const { f } = fakeFetch(() => answer(200, { result: 'recorded', verdict: 'block', message: 'Threatline recorded this CI run. Security requirements still block Done.' }));
    const r = await runCiReport({ ...input(root), fetch: f });
    expect(r.success).toBe(true);
    expect(r.lines.join('\n')).toMatch(/PAY-7 verdict: block \(Threatline recorded this CI run/);
    expect(r.lines.join('\n')).toMatch(/req_1a2b3c4d5e6f7a8b: tests passed \(2 passed\)/);
    expect(r.message).toMatch(/report recorded; 1 requirement had only passing tests/);
  });

  it('reports each named work item separately', async () => {
    const root = workspace({ 'reports/u.xml': suite(`<testcase name="${A}"/>`) });
    const { f, calls } = fakeFetch(verified);
    await runCiReport({ ...input(root, { issueKeys: ['PAY-7', 'PAY-8'] }), fetch: f });
    expect(calls.map((c) => c.body.issueKey)).toEqual(['PAY-7', 'PAY-8']);
  });

  it('shows why a requirement was not verified', async () => {
    const root = workspace({ 'reports/u.xml': suite(`<testcase name="${A}"><failure/></testcase>`) });
    const { f } = fakeFetch(() => answer(200, { issueKey: 'PAY-7', verdict: 'block', verified: 0, ignoredTests: 0, results: [{ requirementId: A, outcome: 'failed', passed: 0, failed: 1, skipped: 0, message: '1 test(s) failed on this run, so it is not verified.' }] }));
    const r = await runCiReport({ ...input(root), fetch: f });
    expect(r.success).toBe(true);
    expect(r.lines.join('\n')).toMatch(/PAY-7: failed req_1a2b3c4d5e6f7a8b \(0 passed, 1 failed\): 1 test\(s\) failed/);
    expect(r.lines.join('\n')).toMatch(/PAY-7 verdict: block/);
  });

  it('configuration problems fail the step: no files, malformed XML, a bad URL, a refused token, a bad request', async () => {
    const root = workspace({ 'reports/u.xml': suite(`<testcase name="${A}"/>`), 'bad/b.xml': '<testsuite><testcase name="x">' });
    const { f } = fakeFetch(verified);
    expect(await runCiReport({ ...input(root, { junit: 'nothing/*.xml' }), fetch: f })).toMatchObject({ success: false, message: expect.stringMatching(/matched no files/) });
    expect(await runCiReport({ ...input(root, { junit: 'bad/*.xml' }), fetch: f })).toMatchObject({ success: false, message: expect.stringMatching(/bad\/b\.xml.*never closed/) });
    expect(await runCiReport({ ...input(root, { url: 'http://site.example/ci' }), fetch: f })).toMatchObject({ success: false, message: expect.stringMatching(/https/) });
    expect(await runCiReport({ ...input(root, { commitSha: 'abc' }), fetch: f })).toMatchObject({ success: false, message: expect.stringMatching(/commit/) });
    // 403 and 404 for the only key named also fail: every key failed, so nothing was reported.
    for (const status of [400, 401, 403, 404, 413]) {
      const r = await runCiReport({ ...input(root), fetch: fakeFetch(() => answer(status, { error: 'x', message: 'Threatline said no.' })).f });
      expect(r, String(status)).toMatchObject({ success: false, message: expect.stringMatching(new RegExp(`HTTP ${status}.*Threatline said no`)) });
    }
  });

  it('a key Threatline does not know (404) or this token may not report on (403) is skipped; the others are still reported', async () => {
    const root = workspace({ 'reports/u.xml': suite(`<testcase name="${A}"/>`) });
    for (const status of [403, 404]) {
      const { f, calls } = fakeFetch((b) => (b.issueKey === 'OTHER-9' ? answer(status, { error: 'not_found', message: 'Unknown work item.' }) : verified(b)));
      const r = await runCiReport({ ...input(root, { issueKeys: ['OTHER-9', 'PAY-7'] }), fetch: f });
      expect(r, String(status)).toMatchObject({ success: true, message: 'Threatline: 1 requirement verified from this run.' });
      expect(r.warning).toBeUndefined();
      expect(calls.map((c) => c.body.issueKey)).toEqual(['OTHER-9', 'PAY-7']);
      expect(r.lines.join('\n')).toMatch(new RegExp(`Skipped OTHER-9 \\(HTTP ${status}: Unknown work item\\.\\): not a work item this token can report on`));
    }
    // Every key unknown is a misconfiguration: the step fails, naming each.
    const { f } = fakeFetch(() => answer(404, { error: 'not_found' }));
    expect(await runCiReport({ ...input(root, { issueKeys: ['OTHER-9', 'PAY-7'] }), fetch: f })).toMatchObject({ success: false, message: expect.stringMatching(/no work item named here could be reported: OTHER-9 \(HTTP 404\), PAY-7 \(HTTP 404\)/) });
  });

  it('a busy or unreachable Threatline only warns (the Done gate stays closed until a report gets through)', async () => {
    const root = workspace({ 'reports/u.xml': suite(`<testcase name="${A}"/>`) });
    for (const respond of [() => answer(503, { error: 'unavailable' }), () => answer(429, { error: 'rate_limited' }), () => Promise.reject(new TypeError('fetch failed'))]) {
      const r = await runCiReport({ ...input(root), fetch: fakeFetch(respond).f });
      expect(r).toMatchObject({ success: true, warning: true, message: expect.stringMatching(/not recorded|could not reach/) });
    }
  });

  it('no work item named: nothing to report, with a warning', async () => {
    const root = workspace({ 'reports/u.xml': suite(`<testcase name="${A}"/>`) });
    const { f, calls } = fakeFetch(verified);
    expect(await runCiReport({ ...input(root, { issueKeys: [] }), fetch: f })).toMatchObject({ success: true, warning: true, message: expect.stringMatching(/names no Jira work item/) });
    expect(calls).toHaveLength(0);
  });

  it('never drops results to fit: a report over 256 KB fails instead', async () => {
    const cases = Array.from({ length: 3000 }, (_, i) => `<testcase classname="${'c'.repeat(60)}" name="${A} case ${i} ${'x'.repeat(40)}"/>`).join('');
    const root = workspace({ 'reports/u.xml': suite(cases) });
    const { f, calls } = fakeFetch(verified);
    expect(await runCiReport({ ...input(root), fetch: f })).toMatchObject({ success: false, message: expect.stringMatching(/256 KB/) });
    expect(calls).toHaveLength(0);
  });
});

describe('cliReportConfig (scripts/threatline-ci-report.mjs)', () => {
  const base = { THREATLINE_URL: 'https://x/ci', THREATLINE_TOKEN: TOKEN, GITHUB_REPOSITORY: 'acme/payments', GITHUB_RUN_ID: '42', GITHUB_SHA: 'f'.repeat(40) };
  it('on a GitHub push GITHUB_HEAD_REF is set but empty: the branch comes from GITHUB_REF_NAME', () => {
    const r = cliReportConfig(['--junit', 'reports/*.xml'], { ...base, GITHUB_HEAD_REF: '', GITHUB_REF_NAME: 'feature/PAY-9-push' });
    expect(r).toMatchObject({ ok: true, value: { issueKeys: ['PAY-9'] } });
    expect(cliReportConfig(['--junit', 'r.xml'], { ...base, BITBUCKET_BRANCH: '', GITHUB_HEAD_REF: 'PAY-3-pr', GITHUB_REF_NAME: '3/merge' })).toMatchObject({ ok: true, value: { issueKeys: ['PAY-3'] } });
  });
  it('a standard in the branch is not a work item', () => {
    expect(cliReportConfig(['--junit', 'r.xml'], { ...base, GITHUB_REF_NAME: 'PAY-9-sha-256-CVE-2025-1234' })).toMatchObject({ ok: true, value: { issueKeys: ['PAY-9'] } });
  });
});
