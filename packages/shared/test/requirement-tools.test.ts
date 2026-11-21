import { describe, expect, it } from 'vitest';
import ts from 'typescript';
import { dueDate, fixBy, requirementIdsIn, SLA_DAYS, testScaffold, type Requirement } from '../src/index.js';

const req = (o: Partial<Requirement> = {}): Requirement => ({
  id: 'req_1a2b3c4d5e6f7a8b',
  threatId: 'thr_1',
  issueId: '10042',
  issueKey: 'PAY-7',
  subtaskKey: 'PAY-101',
  title: 'Mitigate: Forged refund webhooks',
  criteria: [
    { given: 'a refund webhook arrives', when: 'its HMAC signature does not match the shared secret', then: 'the request is rejected with 401 and logged' },
    { given: 'a valid signature', when: 'the timestamp is older than 5 minutes', then: 'the request is rejected as a replay' },
  ],
  asvsIds: ['V6.3.1'],
  severity: 'High',
  status: 'Open',
  createdAt: '2026-11-01T00:00:00.000Z',
  ...o,
});

const parsesAsTs = (code: string) => {
  const out = ts.transpileModule(code, { reportDiagnostics: true, compilerOptions: { module: ts.ModuleKind.ESNext } });
  return out.diagnostics ?? [];
};

describe('testScaffold (feature: test skeletons from requirements)', () => {
  it('TypeScript: one describe per requirement, one test per Given/When/Then, tagged with the requirement id and ASVS', () => {
    const code = testScaffold(req(), 'typescript');
    expect(code).toContain("describe('PAY-101 Mitigate: Forged refund webhooks [req_1a2b3c4d5e6f7a8b]', () => {");
    expect(code.match(/\bit\('/g)).toHaveLength(2);
    expect(code).toContain('Threatline requirement req_1a2b3c4d5e6f7a8b');
    expect(code).toContain('ASVS V6.3.1');
    expect(code).toMatch(/throw new Error\('Write this test/);
    expect(parsesAsTs(code)).toEqual([]);
  });

  it('Python (pytest) and Java (JUnit 5) skeletons use valid identifiers and fail until written', () => {
    const py = testScaffold(req(), 'python');
    expect(py).toMatch(/^def test_req_1a2b3c4d5e6f7a8b_[a-z0-9_]{1,80}\(\):$/m);
    expect(py.match(/^def test_/gm)).toHaveLength(2);
    expect(py).toContain('raise NotImplementedError');
    const java = testScaffold(req(), 'java');
    expect(java).toMatch(/class Pay101SecurityTest \{/);
    expect(java.match(/@Test/g)).toHaveLength(2);
    expect(java).toMatch(/void req_1a2b3c4d5e6f7a8b_[a-z][A-Za-z0-9]{0,80}\(\) \{/);
    expect(java).toContain('fail("Write this test');
  });

  it('security: requirement text from untrusted sources cannot break out of strings or comments', () => {
    const hostile = req({
      title: "Mitigate: it's \\ bad */ \"\"\" `${x}` \n process.exit(1)",
      criteria: [{ given: "x' + require('fs') + '", when: '*/ alert(1) /*', then: '"""\nimport os\n"""' }],
    });
    const code = testScaffold(hostile, 'typescript');
    expect(parsesAsTs(code)).toEqual([]);
    expect(code).not.toMatch(/^\s*process\.exit/m);
    expect(code.split('\n').filter((l) => l.includes('alert(1)')).every((l) => l.trim().startsWith('//') || /'.*alert\(1\).*'/.test(l))).toBe(true);
    const py = testScaffold(hostile, 'python');
    expect(py).not.toMatch(/^import os$/m);
    for (const line of py.split('\n').filter((l) => l.includes('"""'))) expect(line.trim().startsWith('#')).toBe(true);
    const java = testScaffold(hostile, 'java');
    expect(java).not.toMatch(/^\s*import os/m);
    for (const line of java.split('\n').filter((l) => l.includes('fail('))) expect(line).toMatch(/^\s*fail\("(?:[^"\\]|\\.)*"\);$/);
  });
});

/** What javac does first: \\uXXXX escapes become characters, even in comments (an odd run of backslashes only). */
const javaUnicode = (src: string) => src.replace(/(\\+)u+([0-9a-fA-F]{4})/g, (m, slashes: string, hex: string) => (slashes.length % 2 === 1 ? slashes.slice(1) + String.fromCharCode(parseInt(hex, 16)) : m));

describe('testScaffold: Java unicode escapes (commit security review)', () => {
  it('a \\u000a in requirement text cannot start a new Java line inside a comment, or end a string', () => {
    const java = testScaffold(
      req({ title: 'Mitigate \\u000a System.exit(1);', criteria: [{ given: 'x \\u000a Runtime.getRuntime().exec("rm");', when: 'w \\u000d\\u000a int a = 1;', then: 't \\u0022); System.exit(2); //' }] }),
      'java',
    );
    const lines = javaUnicode(java).split(/\r\n|\r|\n/);
    expect(lines.filter((l) => /System\.exit|Runtime\.getRuntime|int a = 1/.test(l)).every((l) => l.trim().startsWith('//') || /^\s*fail\(".*"\);$/.test(l))).toBe(true);
    for (const l of lines.filter((x) => x.includes('fail('))) expect(l).toMatch(/^\s*fail\("(?:[^"\\]|\\.)*"\);$/);
  });
});

describe('testScaffold: the requirement id is in every test name (feature: verification from CI)', () => {
  it('each generated test reports a name CI verification can read the requirement id from', () => {
    // vitest/jest JUnit reports join the describe and it titles; pytest and surefire report the function or method name.
    const code = testScaffold(req(), 'typescript');
    expect(requirementIdsIn(/describe\('([^']*)'/.exec(code)![1]!)).toEqual(['req_1a2b3c4d5e6f7a8b']);
    for (const lang of ['python', 'java'] as const) {
      const names = [...testScaffold(req(), lang).matchAll(/(?:def|void) (\w+)\(/g)].map((m) => m[1]!);
      expect(names, lang).toHaveLength(2);
      for (const n of names) expect(requirementIdsIn(n), `${lang} ${n}`).toEqual(['req_1a2b3c4d5e6f7a8b']);
    }
  });

  it('security: an id not in Threatline’s own format never reaches an identifier', () => {
    const odd = req({ id: 'req_x(); import os #' });
    expect(testScaffold(odd, 'python')).not.toMatch(/def test_req_x/);
    expect(testScaffold(odd, 'java')).not.toMatch(/void req_x/);
    expect(parsesAsTs(testScaffold(odd, 'typescript'))).toEqual([]);
    expect(testScaffold(odd, 'typescript')).not.toContain('[req_x');
  });
});

describe('fix-by deadlines (feature: requirement SLAs)', () => {
  const now = new Date('2026-11-20T00:00:00.000Z');
  it('Critical 7 days, High 30, Medium 90, Low none, counted from when Threatline created the requirement', () => {
    expect(SLA_DAYS).toEqual({ Critical: 7, High: 30, Medium: 90, Low: null });
    expect(dueDate(req({ severity: 'Critical' }))).toBe('2026-11-08T00:00:00.000Z');
    expect(dueDate(req({ severity: 'High' }))).toBe('2026-12-01T00:00:00.000Z');
    expect(dueDate(req({ severity: 'Low' }))).toBeNull();
    expect(dueDate(req({ createdAt: undefined }))).toBeNull();
  });
  it('an open requirement past its date is overdue by whole days; resolved, accepted or undated ones are not', () => {
    expect(fixBy(req({ severity: 'Critical' }), now)).toEqual({ due: '2026-11-08T00:00:00.000Z', overdueDays: 12 });
    expect(fixBy(req({ severity: 'High' }), now)).toEqual({ due: '2026-12-01T00:00:00.000Z', overdueDays: 0 });
    expect(fixBy(req({ severity: 'Critical', status: 'Verified' }), now)).toBeNull();
    expect(fixBy(req({ severity: 'Critical', status: 'AcceptedRisk' }), now)).toBeNull();
    expect(fixBy(req({ severity: 'Low' }), now)).toBeNull();
  });
});
