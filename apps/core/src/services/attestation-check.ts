import { commitMatches, repoMatches, unescapeMarkdown } from '@threatline/core';
import { decodeAttestation, fromB64url, fromUtf8 } from '@threatline/crypto';
import { AttestationPayloadSchema, type AttestationPayload } from '@threatline/shared';

/**
 * "Check an attestation" (the issue panel's tamper check): does a pasted merge attestation verify against this site's
 * Threatline public keys, and is it for the repository and commit given? Pure. It reads no ledger or attestation records
 * and records nothing: verifying with a public key reveals nothing the token does not already carry.
 */

/** The longest text the check reads: an attestation lists up to 200 requirements, so a real one can run to ~16 kB. */
export const MAX_CHECK_TEXT = 32_000;

const PREFIX = /^(?:threatline|redline)-att\.v1\./;

/** Fields of a verified payload, as the panel shows them. Only ever built from a payload whose signature verified. */
export interface CheckedAttestation {
  kid: string;
  issueKey: string;
  repo: string;
  commitSha: string;
  verdict: AttestationPayload['verdict'];
  issuedAt: string;
  expiresAt: string;
  requirements: { verified: number; total: number };
  override?: NonNullable<AttestationPayload['override']>;
  partial?: true;
}

export type AttestationCheckReason = 'malformed' | 'bad_signature' | 'no_keys' | 'schema' | 'expired' | 'not_yet_valid' | 'lifetime' | 'other_repo' | 'other_commit';
export type AttestationCheck =
  | { valid: true; message: string; attestation: CheckedAttestation }
  /** `attestation` is present only when the signature verified (expired, not yet valid, too long-lived, other repo or commit). */
  | { valid: false; reason: AttestationCheckReason; message: string; attestation?: CheckedAttestation };

const utcMinute = (sec: number) => `${new Date(sec * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
const shortSha = (sha: string) => sha.slice(0, 12);

/**
 * The attestation in the pasted text: the text itself, or the last whitespace-separated word that starts like one (the
 * PR description snippet puts a line of prose before the token). Bitbucket's Markdown escapes are undone first, as the
 * merge gate does.
 */
function tokenIn(text: string): string | null {
  const words = unescapeMarkdown(text).trim().split(/\s+/);
  return words.filter((w) => PREFIX.test(w)).at(-1) ?? null;
}

/** Shaped like an attestation: the prefix, then exactly two non-empty dot-separated segments. */
const wellFormed = (token: string) => {
  const parts = token.replace(PREFIX, '').split('.');
  return parts.length === 2 && parts.every((s) => s.length > 0);
};

/** The payload's JSON, unverified: used only to choose which failure message to show, never shown itself. */
function peekKid(token: string): string | undefined {
  const bytes = fromB64url(token.replace(PREFIX, '').split('.')[0] ?? '');
  if (!bytes) return undefined;
  try {
    const kid = (JSON.parse(fromUtf8(bytes)) as { kid?: unknown }).kid;
    return typeof kid === 'string' ? kid : undefined;
  } catch {
    return undefined;
  }
}

/** The payload of a token decodeAttestation already verified (signature and schema), for the time-based failures. */
function verifiedPayload(token: string): AttestationPayload | null {
  const bytes = fromB64url(token.replace(PREFIX, '').split('.')[0] ?? '');
  if (!bytes) return null;
  try {
    const p = AttestationPayloadSchema.safeParse(JSON.parse(fromUtf8(bytes)));
    return p.success ? p.data : null;
  } catch {
    return null;
  }
}

const toChecked = (p: AttestationPayload): CheckedAttestation => ({
  kid: p.kid,
  issueKey: p.issueKey,
  repo: p.repo,
  commitSha: p.commitSha,
  verdict: p.verdict,
  issuedAt: new Date(p.iat * 1000).toISOString(),
  expiresAt: new Date(p.exp * 1000).toISOString(),
  requirements: { verified: p.requirements.filter((r) => r.status === 'Verified').length, total: p.requirements.length },
  ...(p.override ? { override: p.override } : {}),
  ...(p.partial ? { partial: true as const } : {}),
});

const MSG = {
  malformed:
    'Malformed — this is not a complete Threatline attestation. An attestation starts with threatline-att.v1. and has a payload and a signature separated by a dot. Copy it again from the Threatline panel.',
  tampered: 'Signature invalid — the token was changed after signing.',
  untrusted: 'Signature invalid — it is not signed with this site’s Threatline key: the token was changed after signing, it comes from another Threatline site, or its key has been retired.',
  no_keys: 'This site has not issued any attestations yet (it has no Threatline signing key), so this one cannot be from this site.',
  schema: 'Not a valid attestation — it is signed, but its content is not in the format Threatline issues.',
  lifetime: 'Refused — it is valid for longer than Threatline ever issues (7 days).',
};

/**
 * Checks pasted text against `publicKeys` (kid → key: the site's active key and, during the grace period after a
 * rotation, the previous one). `expect.repo` and `expect.commitSha` are matched as the merge gate matches a pull request:
 * the repository ignoring case, the commit as the full 40-character hash.
 */
export function checkAttestation(text: string, publicKeys: Record<string, string>, nowSec: number, expect: { repo?: string; commitSha?: string } = {}): AttestationCheck {
  const token = tokenIn(text);
  if (!token || !wellFormed(token)) return { valid: false, reason: 'malformed', message: MSG.malformed };
  if (Object.keys(publicKeys).length === 0) return { valid: false, reason: 'no_keys', message: MSG.no_keys };

  const r = decodeAttestation(token, publicKeys, nowSec);
  if (!r.ok) {
    switch (r.error.code) {
      // Shaped like an attestation but unreadable (a changed character breaks the base64 or the JSON): it was changed
      // after signing, the same as a signature that does not verify.
      case 'malformed':
      case 'bad_signature': {
        const kid = peekKid(token);
        return { valid: false, reason: 'bad_signature', message: kid !== undefined && !(kid in publicKeys) ? MSG.untrusted : MSG.tampered };
      }
      case 'unknown_key':
        return { valid: false, reason: 'no_keys', message: MSG.no_keys };
      case 'schema':
        return { valid: false, reason: 'schema', message: MSG.schema };
      case 'expired':
      case 'not_yet_valid':
      case 'lifetime': {
        const p = verifiedPayload(token);
        const attestation = p ? toChecked(p) : undefined;
        const what = p ? ` for ${p.issueKey} at ${p.repo}@${shortSha(p.commitSha)}` : '';
        const message =
          r.error.code === 'expired'
            ? `Expired — the signature is genuine, but this attestation${what} expired at ${p ? utcMinute(p.exp) : 'an earlier time'}. Request a new one from the Threatline panel.`
            : r.error.code === 'not_yet_valid'
              ? `Not valid yet — this attestation${what} was issued in the future (the issuing clock is ahead). Try again in a few minutes.`
              : MSG.lifetime;
        return { valid: false, reason: r.error.code, message, ...(attestation ? { attestation } : {}) };
      }
    }
  }
  const p = r.value;
  const attestation = toChecked(p);
  if (expect.repo && !repoMatches(p.repo, expect.repo))
    return { valid: false, reason: 'other_repo', attestation, message: `For a different repository — the signature is genuine, but it is for ${p.repo}, not ${expect.repo}. Request an attestation for this repository.` };
  if (expect.commitSha && !commitMatches(p.commitSha, expect.commitSha))
    return {
      valid: false,
      reason: 'other_commit',
      attestation,
      message: `For a different commit — the signature is genuine, but it is for commit ${shortSha(p.commitSha)}, not ${shortSha(expect.commitSha.toLowerCase())}. Request a new attestation for the latest commit.`,
    };
  const lenient = p.override === 'break_glass' ? ' Issued under a break-glass override.' : p.override === 'warn_only' ? ' Issued under warn-only mode.' : '';
  const partial = p.partial ? ' Reviewed with partial context.' : '';
  return {
    valid: true,
    attestation,
    message: `Valid — signed by Threatline key ${p.kid} for ${p.issueKey} at ${p.repo}@${shortSha(p.commitSha)}, verdict ${p.verdict}, expires ${utcMinute(p.exp)}.${lenient}${partial}`,
  };
}
