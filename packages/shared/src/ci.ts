/**
 * Verification from CI: a requirement id in a test's name ties the test to the requirement. The skeletons
 * (requirement-tools.ts) write it there; CI reports which named tests passed, and Threatline verifies those requirements.
 * The format is exactly what Threatline generates (`req_` + 16 lowercase hex digits, packages/core/src/requirements.ts),
 * not touching another letter or digit, so `xreq_…` or a longer hex run never counts. `_` separates, so pytest's
 * `test_req_…_rejects` and JUnit's `req_…_rejects()` match.
 */
const ID = 'req_[0-9a-f]{16}';
const IN_NAME = new RegExp(`(?<![A-Za-z0-9])${ID}(?![A-Za-z0-9])`, 'g');

export function isRequirementId(s: string): boolean {
  return new RegExp(`^${ID}$`).test(s);
}

/** The distinct requirement ids a test name carries, in order of first appearance. */
export function requirementIdsIn(name: string): string[] {
  return [...new Set([...name.matchAll(IN_NAME)].map((m) => m[0]))];
}

/**
 * Work-item keys a pull request names in its title or branch (the merge gate, and the CI report finding its work
 * item). `\b` cannot bound them: `_` is a word character, so `PAY-7_fix` and `fix_PAY-7` would hide PAY-7 (and with it the need for PAY-7's own attestation). The rules:
 * - a key is a project (a letter, then letters, digits or `_`) + `-` + digits, not touching another letter or digit
 *   before it, nor a digit after it (`_`, `/`, `-`, `.` and the like separate);
 * - an uppercase key counts (`PAY-7`, `MY_PROJ-12`). In `fix_PAY-7` the longest uppercase `_`-suffix is the project;
 * - a lowercase or mixed-case key (`pay-7-fix`) counts only when its project, uppercased (or an `_`-suffix of it), is the
 *   project of an uppercase key named in the title or branch. Alone, `utf-8` or `sha-256` would be a false requirement;
 * - an algorithm or encoding name (`SHA-256`, `AES-128`, `UTF-8`, `RSA-2048`, `X-509`…) and a CVE id in full
 *   (`CVE-2025-1234`: the year is followed by `-` and four or more digits) are never keys: no attestation can exist
 *   for them, so they would block the merge for good. Only those exact shapes are excluded, never a whole project:
 *   RFC, ISO, CWE and the like are real project keys (change requests, audits), so `RFC-1234` always counts, and a
 *   project called CVE still counts as `CVE-2025` alone. Keys given explicitly (`explicitIssueKeys`) are never excluded.
 */
const STANDARD_ID =
  /^(?:SHA-(?:1|2|3|224|256|384|512)|SHA3-(?:224|256|384|512)|AES-(?:128|192|256)|UTF-(?:7|8|16|32)|RSA-(?:1024|2048|3072|4096)|P-(?:256|384|521)|ED-25519|X-509|HMAC-(?:256|384|512))$/;
/** After `CVE-<year>`, the rest of a CVE id. */
const CVE_REST = /^-\d{4,}/;
const KEY_LIKE = /(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9_]*)-(\d+)(?![0-9])/g;
const UPPER_PROJECT = /^[A-Z][A-Z0-9_]+$/;
/** `fix_PAY` → [`fix_PAY`, `PAY`]: the project with each `_`-separated prefix dropped, longest first. */
const suffixes = (project: string) => project.split('_').map((_, i, parts) => parts.slice(i).join('_'));

export function namedIssueKeys(...texts: string[]): string[] {
  return keysIn(texts, true);
}

/** Keys a person typed on purpose (a CI variable or flag): the same syntax, but nothing is excluded as a standard. */
export function explicitIssueKeys(...texts: string[]): string[] {
  return keysIn(texts, false);
}

function keysIn(texts: string[], excludeStandards: boolean): string[] {
  const found = texts.flatMap((t) =>
    [...t.matchAll(KEY_LIKE)].map((m) => ({ project: m[1]!, num: m[2]!, cveId: CVE_REST.test(t.slice(m.index + m[0].length)) })),
  );
  const standard = (key: string, f: { cveId: boolean }) => excludeStandards && (STANDARD_ID.test(key) || (f.cveId && /^CVE-(?:19|20)\d\d$/.test(key)));
  const upper = found.map((f) => {
    const project = suffixes(f.project).find((p) => UPPER_PROJECT.test(p));
    const key = project ? `${project}-${f.num}` : null;
    return key && !standard(key, f) ? key : null;
  });
  const projects = new Set(upper.flatMap((k) => (k ? [k.slice(0, k.lastIndexOf('-'))] : [])));
  const keys = found.flatMap((f, i) => {
    if (upper[i]) return [upper[i]];
    const project = suffixes(f.project.toUpperCase()).find((p) => projects.has(p));
    return project && !standard(`${project}-${f.num}`, f) ? [`${project}-${f.num}`] : [];
  });
  return [...new Set(keys)];
}
