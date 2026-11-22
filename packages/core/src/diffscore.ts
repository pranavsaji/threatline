import type { RepoPolicy } from '@threatline/shared';
import { isSensitive } from './policy.js';

export interface DiffFile {
  path: string;
  /** Previous path for renames (Bitbucket diffstat `old.path`); scored too, so moving a file out of a sensitive directory is still sensitive. */
  oldPath?: string;
  status: 'added' | 'modified' | 'removed' | 'renamed';
  linesAdded: number;
  addedText?: string;
}
export type DiffSignal = 'sensitive_path' | 'new_dependency' | 'secret_pattern' | 'auth_crypto_change';
export interface DiffScore {
  score: number;
  sensitiveFiles: string[];
  signals: DiffSignal[];
}

// Case-insensitive like the sensitive globs (policy.ts isSensitive) and AUTH_CRYPTO: `Package.json` on a case-insensitive file system is the same manifest.
const DEPENDENCY_MANIFESTS = /(^|\/)(package\.json|requirements\.txt|go\.mod|pom\.xml|Gemfile|build\.gradle|Cargo\.toml|pyproject\.toml)$/i;

export const SECRET_PATTERNS: ReadonlyArray<{ kind: string; re: RegExp }> = [
  { kind: 'aws_key', re: /AKIA[0-9A-Z]{16}/ },
  { kind: 'private_key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { kind: 'slack_token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { kind: 'github_token', re: /gh[pousr]_[0-9A-Za-z]{36,}/ },
  { kind: 'generic_secret', re: /(?:api|secret)_?key\s*[:=]\s*['"][^'"\s]{16,}['"]/i },
];

const AUTH_CRYPTO = /auth|login|session|token|crypto|jwt|oauth|password/i;
const WEIGHTS: Record<DiffSignal, number> = { sensitive_path: 40, new_dependency: 20, secret_pattern: 40, auth_crypto_change: 20 };

export function scoreDiff(files: DiffFile[], policy: Pick<RepoPolicy, 'sensitivePaths'>): DiffScore {
  const signals = new Set<DiffSignal>();
  const sensitiveFiles: string[] = [];
  for (const f of files) {
    const paths = f.oldPath && f.oldPath !== f.path ? [f.path, f.oldPath] : [f.path];
    for (const p of paths) {
      if (isSensitive(p, policy.sensitivePaths)) {
        sensitiveFiles.push(p);
        signals.add('sensitive_path');
      }
      // Deleting or moving auth/crypto code is as security-relevant as editing it.
      if (AUTH_CRYPTO.test(p)) signals.add('auth_crypto_change');
    }
    if (f.status !== 'removed' && DEPENDENCY_MANIFESTS.test(f.path)) signals.add('new_dependency');
    const text = f.addedText ?? '';
    if (SECRET_PATTERNS.some((p) => p.re.test(text))) signals.add('secret_pattern');
  }
  const ordered = (Object.keys(WEIGHTS) as DiffSignal[]).filter((s) => signals.has(s));
  const score = Math.min(100, ordered.reduce((n, s) => n + WEIGHTS[s], 0));
  return { score, sensitiveFiles, signals: ordered };
}
