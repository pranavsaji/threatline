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
 *   project of an uppercase key named in the title or branch. Alone, `utf-8` or `sha-256` would be a false requirement.
 */
const KEY_LIKE = /(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9_]*)-(\d+)(?![0-9])/g;
const UPPER_PROJECT = /^[A-Z][A-Z0-9_]+$/;
/** `fix_PAY` → [`fix_PAY`, `PAY`]: the project with each `_`-separated prefix dropped, longest first. */
const suffixes = (project: string) => project.split('_').map((_, i, parts) => parts.slice(i).join('_'));

export function namedIssueKeys(...texts: string[]): string[] {
  const found = texts.flatMap((t) => [...t.matchAll(KEY_LIKE)].map((m) => ({ project: m[1]!, num: m[2]! })));
  const upper = found.map((f) => {
    const project = suffixes(f.project).find((p) => UPPER_PROJECT.test(p));
    return project ? `${project}-${f.num}` : null;
  });
  const projects = new Set(upper.flatMap((k) => (k ? [k.slice(0, k.lastIndexOf('-'))] : [])));
  const keys = found.flatMap((f, i) => {
    if (upper[i]) return [upper[i]];
    const project = suffixes(f.project.toUpperCase()).find((p) => projects.has(p));
    return project ? [`${project}-${f.num}`] : [];
  });
  return [...new Set(keys)];
}
