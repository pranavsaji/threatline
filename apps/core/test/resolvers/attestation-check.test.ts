import { describe, expect, it } from 'vitest';
import { ok } from '@threatline/shared';
import { attestationCheck, attestationCopy, keysRotate } from '../../src/resolvers/attestations.js';
import { checkAttestation } from '../../src/services/attestation-check.js';
import { ADMIN, DEV, ISSUE, reviewed } from '../support/reviewed.js';

const SHA = 'ab'.repeat(20);
const REPO = 'acme/payments';
const VIEWER = 'acc-viewer';
const HOUR = 3_600_000;

/** PAY-7 passing, one attestation issued for acme/payments@SHA; `check` calls the resolver as a viewer of PAY-7. */
async function issued() {
  const { t } = await reviewed({ allVerified: true });
  const r = await attestationCopy(t.deps, { accountId: DEV, issueId: ISSUE }, { repo: REPO, commitSha: SHA });
  if (!('token' in r)) throw new Error(`expected a token: ${JSON.stringify(r)}`);
  const check = (payload: Record<string, unknown>) => attestationCheck(t.deps, { accountId: VIEWER, issueId: ISSUE }, payload);
  return { t, token: r.token, snippet: r.prDescriptionSnippet, check };
}

/** One character changed at `i`, to another base64url character. */
const changeAt = (token: string, i: number) => `${token.slice(0, i)}${token[i] === 'A' ? 'B' : 'A'}${token.slice(i + 1)}`;

describe('attestation.check', () => {
  it('a valid attestation: signed by this site’s key, for this work item, repository and commit', async () => {
    const { t, token, check } = await issued();
    const ledgerBefore = ((await t.deps.ledger.all()) as { ok: true; value: unknown[] }).value.length;
    const r = await check({ token, repo: 'ACME/Payments', commitSha: SHA.toUpperCase() });
    const keys = (await t.deps.keys.publicKeys()) as { ok: true; value: Record<string, string> };
    const kid = Object.keys(keys.value)[0]!;
    expect(r).toEqual({
      valid: true,
      message: `Valid — signed by Threatline key ${kid} for PAY-7 at acme/payments@${SHA.slice(0, 12)}, verdict pass, expires 2026-11-16 12:00 UTC.`,
      attestation: {
        kid,
        issueKey: 'PAY-7',
        repo: REPO,
        commitSha: SHA,
        verdict: 'pass',
        issuedAt: '2026-11-15T12:00:00.000Z',
        expiresAt: '2026-11-16T12:00:00.000Z',
        requirements: { verified: expect.any(Number), total: expect.any(Number) },
      },
    });
    // Checking records nothing: no ledger entry, no attestation row.
    expect(((await t.deps.ledger.all()) as { ok: true; value: unknown[] }).value).toHaveLength(ledgerBefore);
    expect(((await t.deps.attestations.forIssue('PAY-7')) as { ok: true; value: unknown[] }).value).toHaveLength(1);
  });

  it('reads the token out of the pasted pull request snippet, and without a repository or commit', async () => {
    const { snippet, check } = await issued();
    expect(await check({ token: snippet, repo: '', commitSha: '' })).toMatchObject({ valid: true });
  });

  it('one changed character anywhere in the payload or signature fails as a changed signature', async () => {
    const { token, check } = await issued();
    const start = 'threatline-att.v1.'.length;
    const dot = token.lastIndexOf('.');
    const positions = [start, start + 5, Math.floor((start + dot) / 2), dot - 1, dot + 1, Math.floor((dot + token.length) / 2), token.length - 1];
    for (const i of positions) {
      const r = await check({ token: changeAt(token, i) });
      expect(r, `changed at ${i}`).toMatchObject({ valid: false, reason: 'bad_signature', message: expect.stringMatching(/^Signature invalid — /) });
      expect(r).not.toHaveProperty('attestation');
    }
    expect(await check({ token: changeAt(token, dot + 1) })).toMatchObject({ message: 'Signature invalid — the token was changed after signing.' });
  });

  it('an expired attestation: genuine signature, says when it expired', async () => {
    const { t, token, check } = await issued();
    t.clock.advance(25 * HOUR);
    expect(await check({ token })).toMatchObject({
      valid: false,
      reason: 'expired',
      message: expect.stringMatching(/^Expired — the signature is genuine, but this attestation for PAY-7 at acme\/payments@abababababab expired at 2026-11-16 12:00 UTC/),
      attestation: { issueKey: 'PAY-7', expiresAt: '2026-11-16T12:00:00.000Z' },
    });
  });

  it('for a different commit, or a different repository', async () => {
    const { token, check } = await issued();
    expect(await check({ token, repo: REPO, commitSha: 'c'.repeat(40) })).toMatchObject({
      valid: false,
      reason: 'other_commit',
      message: expect.stringMatching(/^For a different commit — the signature is genuine, but it is for commit abababababab, not cccccccccccc/),
      attestation: { commitSha: SHA },
    });
    expect(await check({ token, repo: 'acme/other', commitSha: SHA })).toMatchObject({ valid: false, reason: 'other_repo', message: expect.stringContaining('it is for acme/payments, not acme/other') });
  });

  it('malformed text: not an attestation, or missing its signature', async () => {
    const { token, check } = await issued();
    for (const text of ['hello', 'threatline-att.v1.', token.slice(0, token.lastIndexOf('.')), `${token}.extra`, 'threatline-att.v1..sig']) {
      expect(await check({ token: text }), text.slice(0, 30)).toMatchObject({ valid: false, reason: 'malformed', message: expect.stringMatching(/^Malformed — /) });
    }
  });

  it('a token signed by a key this site does not trust is a signature failure that says so', async () => {
    const { t, token, check } = await issued();
    await keysRotate(t.deps, { accountId: ADMIN });
    expect(await check({ token })).toMatchObject({ valid: true }); // the previous key is trusted during the grace period
    t.clock.advance(8 * 24 * HOUR);
    expect(await check({ token })).toMatchObject({ valid: false, reason: 'bad_signature', message: expect.stringContaining('not signed with this site’s Threatline key') });
  });

  it('refuses a viewer who cannot browse the work item, before reading the token', async () => {
    const { t, token, check } = await issued();
    t.jira.canBrowse = async () => ok(false);
    expect(await check({ token })).toEqual({ error: 'not_found' });
    expect(await attestationCheck(t.deps, { accountId: '', issueId: ISSUE }, { token })).toEqual({ error: 'not_found' });
    expect(await attestationCheck(t.deps, { accountId: VIEWER, issueId: 'PAY-7' }, { token })).toEqual({ error: 'not_found' });
  });

  it('validates its inputs', async () => {
    const { token, check } = await issued();
    expect(await check({})).toMatchObject({ error: 'validation' });
    expect(await check({ token: 'x'.repeat(40_000) })).toMatchObject({ error: 'validation' });
    expect(await check({ token, repo: 'not a repo' })).toMatchObject({ error: 'validation', message: expect.stringContaining('repo') });
    expect(await check({ token, commitSha: 'abc123' })).toMatchObject({ error: 'validation', message: expect.stringContaining('commitSha') });
  });
});

describe('checkAttestation', () => {
  it('with no trusted keys nothing verifies', () => {
    expect(checkAttestation('threatline-att.v1.e30.c2ln', {}, 0)).toMatchObject({ valid: false, reason: 'no_keys' });
  });
});
