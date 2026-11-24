import type { AttestationCheck, CheckedAttestation } from './bridge.js';

/**
 * Fixture-bridge attestations for the local preview: shaped like real ones (`threatline-att.v1.<payload>.<seal>`, the
 * payload base64url JSON), but sealed with a keyless checksum instead of an Ed25519 signature. Not a signature: anyone
 * can compute it. It only lets the preview tell a token it issued from one with a character changed, so "Check an
 * attestation" shows both outcomes without a key. The real check is apps/core/src/services/attestation-check.ts.
 */

/** A made-up key id, shaped like a real one (the first 16 hex characters of the public key's SHA-256). */
export const MOCK_KID = '7c41e0b95a3d2f18';
const PREFIX = 'threatline-att.v1.';

export interface MockAttestationPayload {
  v: 1;
  kid: string;
  issueKey: string;
  repo: string;
  commitSha: string;
  verdict: 'pass';
  requirements: { id: string; status: string }[];
  iat: number;
  exp: number;
  nonce: string;
}

const toB64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function fromB64url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return null;
  try {
    return Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** 64 bytes (a signature's length) of FNV-1a over the payload segment, one 32-bit round per seed. */
function seal(body: string): string {
  const out = new Uint8Array(64);
  for (let round = 0; round < 16; round++) {
    let h = (0x811c9dc5 ^ Math.imul(round + 1, 0x9e3779b1)) >>> 0;
    for (let i = 0; i < body.length; i++) h = Math.imul(h ^ body.charCodeAt(i), 0x01000193) >>> 0;
    out.set([h >>> 24, (h >>> 16) & 255, (h >>> 8) & 255, h & 255], round * 4);
  }
  return toB64url(out);
}

export function mockAttestationToken(p: MockAttestationPayload): string {
  const body = toB64url(new TextEncoder().encode(JSON.stringify(p)));
  return `${PREFIX}${body}.${seal(body)}`;
}

const utcMinute = (sec: number) => `${new Date(sec * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
const shortSha = (sha: string) => sha.slice(0, 12);
const TAMPERED = 'Signature invalid — the token was changed after signing.';

/** The same outcomes and messages as the real check, for the tokens mockAttestationToken seals. */
export function checkMockAttestation(text: string, expect: { repo?: string; commitSha?: string } = {}, nowSec = Math.floor(Date.now() / 1000)): AttestationCheck {
  const token = text.trim().split(/\s+/).filter((w) => w.startsWith(PREFIX)).at(-1);
  const parts = token?.slice(PREFIX.length).split('.') ?? [];
  if (parts.length !== 2 || !parts.every(Boolean))
    return { valid: false, reason: 'malformed', message: 'Malformed — this is not a complete Threatline attestation. An attestation starts with threatline-att.v1. and has a payload and a signature separated by a dot. Copy it again from the Threatline panel.' };
  const [body, sig] = parts as [string, string];
  const bytes = fromB64url(body);
  if (sig !== seal(body) || !bytes) return { valid: false, reason: 'bad_signature', message: TAMPERED };
  let p: MockAttestationPayload;
  try {
    p = JSON.parse(new TextDecoder().decode(bytes)) as MockAttestationPayload;
  } catch {
    return { valid: false, reason: 'bad_signature', message: TAMPERED };
  }
  const attestation: CheckedAttestation = {
    kid: p.kid,
    issueKey: p.issueKey,
    repo: p.repo,
    commitSha: p.commitSha,
    verdict: p.verdict,
    issuedAt: new Date(p.iat * 1000).toISOString(),
    expiresAt: new Date(p.exp * 1000).toISOString(),
    requirements: { verified: p.requirements.filter((r) => r.status === 'Verified').length, total: p.requirements.length },
  };
  const what = `for ${p.issueKey} at ${p.repo}@${shortSha(p.commitSha)}`;
  if (p.exp < nowSec) return { valid: false, reason: 'expired', attestation, message: `Expired — the signature is genuine, but this attestation ${what} expired at ${utcMinute(p.exp)}. Request a new one from the Threatline panel.` };
  if (expect.repo && expect.repo.toLowerCase() !== p.repo.toLowerCase())
    return { valid: false, reason: 'other_repo', attestation, message: `For a different repository — the signature is genuine, but it is for ${p.repo}, not ${expect.repo}. Request an attestation for this repository.` };
  if (expect.commitSha && expect.commitSha.toLowerCase() !== p.commitSha)
    return { valid: false, reason: 'other_commit', attestation, message: `For a different commit — the signature is genuine, but it is for commit ${shortSha(p.commitSha)}, not ${shortSha(expect.commitSha.toLowerCase())}. Request a new attestation for the latest commit.` };
  return { valid: true, attestation, message: `Valid — signed by Threatline key ${p.kid} ${what}, verdict ${p.verdict}, expires ${utcMinute(p.exp)}.` };
}
