/**
 * A small JUnit XML reader for verification from CI: test names and outcomes, nothing else. It reads the shapes Maven
 * Surefire, Gradle, pytest, jest-junit and vitest write (`testsuites` > `testsuite` (nested) > `testcase`, with
 * `failure`, `error` or `skipped` children). It fails closed: a `failure` or `error` on a suite fails every test in it,
 * a flaky or rerun failure counts as a failure, and malformed XML is refused rather than guessed at. No entity in a
 * DOCTYPE is ever expanded (a DOCTYPE with an internal subset is refused); only the five XML entities and character
 * references are decoded.
 */
export type TestStatus = 'passed' | 'failed' | 'skipped';
export interface TestCase {
  /** `classname name`, the way reporters spell the test's full name. */
  name: string;
  status: TestStatus;
}
export type JUnitResult = { ok: true; cases: TestCase[] } | { ok: false; message: string };

const FAILURES = new Set(['failure', 'error', 'flakyFailure', 'flakyError', 'rerunFailure', 'rerunError']);
const MAX_DEPTH = 128;
const MAX_CASES = 200_000;
const NAME = /^[A-Za-z_][\w.:-]*/;
const ATTR = /([A-Za-z_][\w.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
const ENTITY = /&(?:(amp|lt|gt|quot|apos)|#(\d{1,7})|#x([0-9a-fA-F]{1,6}));/g;
const NAMED: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

const decode = (s: string) =>
  s.replace(ENTITY, (m, named: string | undefined, dec: string | undefined, hex: string | undefined) => {
    if (named) return NAMED[named]!;
    const code = dec ? Number(dec) : parseInt(hex!, 16);
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
  });

interface Suite {
  cases: TestCase[];
  failed: boolean;
}
interface Frame {
  name: string;
  suite?: Suite;
  testcase?: { name: string; failed: boolean; skipped: boolean };
}

/** The end of the tag starting at `from` (the index of its `>`), honouring quoted attribute values; -1 if none. */
function tagEnd(xml: string, from: number): number {
  let quote = '';
  for (let i = from; i < xml.length; i++) {
    const c = xml[i]!;
    if (quote) {
      if (c === quote) quote = '';
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '>') return i;
    else if (c === '<') return -1;
  }
  return -1;
}

export function parseJUnit(input: string): JUnitResult {
  const xml = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  const fail = (message: string): JUnitResult => ({ ok: false, message });
  const out: TestCase[] = [];
  const stack: Frame[] = [];
  let sawRoot = false;
  let count = 0;
  let i = 0;
  const nearestSuite = () => {
    for (let k = stack.length - 1; k >= 0; k--) if (stack[k]!.suite) return stack[k]!.suite!;
    return null;
  };

  while (i < xml.length) {
    const lt = xml.indexOf('<', i);
    if (lt === -1) {
      if (!sawRoot && xml.slice(i).trim()) return fail('not XML: text outside any element');
      break;
    }
    if (stack.length === 0 && xml.slice(i, lt).trim()) return fail('not XML: text outside any element');
    if (xml.startsWith('<?', lt)) {
      const end = xml.indexOf('?>', lt + 2);
      if (end === -1) return fail('unterminated processing instruction');
      i = end + 2;
      continue;
    }
    if (xml.startsWith('<!--', lt)) {
      const end = xml.indexOf('-->', lt + 4);
      if (end === -1) return fail('unterminated comment');
      i = end + 3;
      continue;
    }
    if (xml.startsWith('<![CDATA[', lt)) {
      const end = xml.indexOf(']]>', lt + 9);
      if (end === -1) return fail('unterminated CDATA section');
      i = end + 3;
      continue;
    }
    if (xml.startsWith('<!', lt)) {
      const end = tagEnd(xml, lt + 2);
      if (end === -1) return fail('malformed declaration');
      if (xml.slice(lt, end).includes('[')) return fail('a DOCTYPE with declarations is not supported');
      i = end + 1;
      continue;
    }
    if (xml.startsWith('</', lt)) {
      const end = xml.indexOf('>', lt + 2);
      if (end === -1) return fail('unterminated closing tag');
      const name = xml.slice(lt + 2, end).trim();
      const frame = stack.pop();
      if (!frame || frame.name !== name) return fail(`unexpected </${name.slice(0, 40)}>`);
      close(frame);
      i = end + 1;
      continue;
    }
    const end = tagEnd(xml, lt + 1);
    if (end === -1) return fail('unterminated tag');
    const body = xml.slice(lt + 1, end);
    const selfClosing = body.endsWith('/');
    const inner = selfClosing ? body.slice(0, -1) : body;
    const m = NAME.exec(inner);
    if (!m) return fail('malformed tag');
    if (stack.length === 0 && sawRoot) return fail('more than one root element');
    sawRoot = true;
    const name = m[0];
    const attrs: Record<string, string> = {};
    for (const a of inner.slice(name.length).matchAll(ATTR)) attrs[a[1]!] = decode(a[2] ?? a[3] ?? '');
    const frame = open(name, attrs);
    if (typeof frame === 'string') return fail(frame);
    if (selfClosing) close(frame);
    else stack.push(frame);
    i = end + 1;
  }
  if (stack.length > 0) return fail(`<${stack.at(-1)!.name.slice(0, 40)}> is never closed`);
  if (!sawRoot) return fail('no XML element found');
  return { ok: true, cases: out };

  function open(name: string, attrs: Record<string, string>): Frame | string {
    if (stack.length >= MAX_DEPTH) return 'nested too deeply';
    const parent = stack.at(-1);
    if (name === 'testsuite') return { name, suite: { cases: [], failed: false } };
    if (name === 'testcase') {
      if (++count > MAX_CASES) return `more than ${MAX_CASES} testcases`;
      const full = [attrs.classname, attrs.name].map((s) => (s ?? '').trim()).filter(Boolean).join(' ');
      return { name, testcase: { name: full, failed: false, skipped: false } };
    }
    if (FAILURES.has(name)) {
      if (parent?.testcase) parent.testcase.failed = true;
      else if (parent?.suite) parent.suite.failed = true;
    } else if (name === 'skipped' && parent?.testcase) parent.testcase.skipped = true;
    return { name };
  }

  function close(frame: Frame) {
    const to = nearestSuite()?.cases ?? out;
    if (frame.testcase) {
      const t = frame.testcase;
      if (t.name) to.push({ name: t.name, status: t.failed ? 'failed' : t.skipped ? 'skipped' : 'passed' });
    } else if (frame.suite) {
      for (const c of frame.suite.cases) to.push(frame.suite.failed ? { ...c, status: 'failed' } : c);
    }
  }
}
