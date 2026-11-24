// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { AdminPage } from '../src/admin/AdminPage.js';
import { mockAdminApi, mockApi } from '../src/mock-bridge.js';
import { FIXTURES } from '../src/fixtures.js';
import type { PanelApi } from '../src/bridge.js';
import type { PanelDto } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });
const SHA = 'a'.repeat(40);

function api(roles: PanelDto['roles'], over: Partial<PanelApi> = {}): PanelApi {
  const dto: PanelDto = { ...structuredClone(FIXTURES.ready!), roles };
  return { ...mockApi('ready'), get: async () => structuredClone(dto), ...over };
}
async function openRequirements(a: PanelApi) {
  render(<IssuePanel api={a} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
}
// paste, not type: one input event instead of forty keystrokes keeps the test fast on a loaded machine
async function fill(form: HTMLElement, repo: string, sha: string) {
  await userEvent.click(within(form).getByRole('textbox', { name: 'Repository' }));
  await userEvent.paste(repo);
  await userEvent.click(within(form).getByRole('textbox', { name: 'Commit hash' }));
  await userEvent.paste(sha);
  await userEvent.click(within(form).getByRole('button', { name: 'Get attestation' }));
}

describe('Copy merge attestation (AT-1)', () => {
  it('returns the text to paste into the pull request, with a copy button', async () => {
    const attestation = vi.fn(async () => ({ token: 'threatline-att.v1.x.y', expiresAt: '2026-11-17T12:00:00.000Z', prDescriptionSnippet: 'Threatline attestation for PAY-6 (expires 2026-11-17 12:00 UTC):\nthreatline-att.v1.x.y' }));
    await openRequirements(api(['viewer', 'developer'], { attestation }));
    const form = screen.getByRole('form', { name: 'Merge attestation' });
    await fill(form, 'acme/payments', SHA);
    expect(attestation).toHaveBeenCalledWith('acme/payments', SHA);
    const out = (await screen.findByRole('textbox', { name: 'Paste into the pull request description' })) as HTMLTextAreaElement;
    expect(out.value).toContain('threatline-att.v1.x.y');
    expect(out.readOnly).toBe(true);
    expect(screen.getByRole('button', { name: 'Copy attestation' })).toBeTruthy();
  });

  it('lists what blocks when the work item is not ready', async () => {
    const attestation = vi.fn(async () => ({ blocking: [{ code: 'open_requirement' as const, message: '2 open security requirements at High or above.' }] }));
    await openRequirements(api(['viewer', 'developer'], { attestation }));
    const form = screen.getByRole('form', { name: 'Merge attestation' });
    await fill(form, 'acme/payments', SHA);
    expect(await within(form).findByText(/Threatline blocks this merge/)).toBeTruthy();
    expect(within(form).getByText('2 open security requirements at High or above.')).toBeTruthy();
  });

  it('checks the inputs before asking the server', async () => {
    const attestation = vi.fn();
    await openRequirements(api(['viewer', 'developer'], { attestation }));
    const form = screen.getByRole('form', { name: 'Merge attestation' });
    await fill(form, 'payments', 'abc');
    expect(within(form).getByRole('alert').textContent).toMatch(/workspace\/repository/);
    expect(attestation).not.toHaveBeenCalled();
  });

  it('is hidden from viewers who cannot edit', async () => {
    await openRequirements(api(['viewer']));
    expect(screen.queryByRole('form', { name: 'Merge attestation' })).toBeNull();
  });
});

describe('Admin: signing keys (AT-3)', () => {
  const keys = { active: { kid: 'k2', publicKey: 'PUBKEY2' }, previous: { kid: 'k1', publicKey: 'PUBKEY1', retireAt: '2026-11-23T12:00:00.000Z' } };

  it('shows the active and previous public keys; copying ticks the Bitbucket step', async () => {
    const keyCopied = vi.fn(async () => ({ ok: true as const }));
    const write = vi.spyOn(navigator.clipboard, 'writeText');
    render(<AdminPage api={{ ...mockAdminApi(), publicKeys: async () => keys, keyCopied }} />);
    const section = await screen.findByRole('region', { name: 'Signing keys' });
    expect(await within(section).findByText('PUBKEY2')).toBeTruthy();
    expect(within(section).getByText(/k1.*trusted until 2026-11-23/)).toBeTruthy();
    await userEvent.click(within(section).getByRole('button', { name: 'Copy public key' }));
    expect(write).toHaveBeenCalledWith('PUBKEY2');
    expect(keyCopied).toHaveBeenCalled();
  });

  it('rotation asks for confirmation first', async () => {
    const rotateKey = vi.fn(async () => ({ kid: 'k3' }));
    render(<AdminPage api={{ ...mockAdminApi(), publicKeys: async () => keys, rotateKey }} />);
    const section = await screen.findByRole('region', { name: 'Signing keys' });
    await userEvent.click(await within(section).findByRole('button', { name: 'Rotate key' }));
    expect(rotateKey).not.toHaveBeenCalled();
    await userEvent.click(within(section).getByRole('button', { name: 'Confirm rotation' }));
    expect(rotateKey).toHaveBeenCalled();
    expect(await within(section).findByText(/New key k3 is active/)).toBeTruthy();
    // Bug 4c: merge gates trust a pasted key until it is removed or retired, so say so.
    expect(within(section).getByText(/New key k3 is active/).textContent).toMatch(/remove the old key, or add until=.* after it/);
  });

  it.each(['light', 'dark'])('has no axe violations (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = render(<AdminPage api={{ ...mockAdminApi(), publicKeys: async () => keys }} />);
    await screen.findByText('PUBKEY2');
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});

describe('Check an attestation', () => {
  const valid = {
    valid: true as const,
    message: 'Valid — signed by Threatline key 0123456789abcdef for PAY-6 at acme/payments@aaaaaaaaaaaa, verdict pass, expires 2026-11-17 12:00 UTC.',
    attestation: { kid: '0123456789abcdef', issueKey: 'PAY-6', repo: 'acme/payments', commitSha: SHA, verdict: 'pass' as const, issuedAt: '2026-11-16T12:00:00.000Z', expiresAt: '2026-11-17T12:00:00.000Z', requirements: { verified: 3, total: 3 } },
  };
  async function openChecker(a: PanelApi) {
    await openRequirements(a);
    await userEvent.click(screen.getByText('Check an attestation', { selector: 'summary' }));
    return screen.getByRole('form', { name: 'Check an attestation' });
  }
  async function check(form: HTMLElement, text: string, sha = '') {
    await userEvent.click(within(form).getByRole('textbox', { name: 'Attestation' }));
    await userEvent.paste(text);
    if (sha) {
      await userEvent.click(within(form).getByRole('textbox', { name: 'Commit hash (optional)' }));
      await userEvent.paste(sha);
    }
    await userEvent.click(within(form).getByRole('button', { name: 'Check' }));
  }

  it('is open to viewers who cannot edit, collapsed under the Requirements tab', async () => {
    const checkAttestation = vi.fn(async () => valid);
    await openRequirements(api(['viewer'], { checkAttestation }));
    const details = screen.getByText('Check an attestation', { selector: 'summary' }).closest('details') as HTMLDetailsElement;
    expect(details.open).toBe(false);
    expect(screen.queryByRole('form', { name: 'Merge attestation' })).toBeNull();
    await userEvent.click(screen.getByText('Check an attestation', { selector: 'summary' }));
    const form = screen.getByRole('form', { name: 'Check an attestation' });
    await check(form, 'threatline-att.v1.x.y', SHA);
    expect(checkAttestation).toHaveBeenCalledWith('threatline-att.v1.x.y', { repo: undefined, commitSha: SHA });
    const status = within(form).getByRole('status');
    await within(status).findByText('Valid');
    expect(status.textContent).toContain(valid.message);
    expect(status.textContent).toContain('3 of 3 requirements verified');
  });

  it('says exactly why a changed token fails', async () => {
    const checkAttestation = vi.fn(async () => ({ valid: false as const, reason: 'bad_signature' as const, message: 'Signature invalid — the token was changed after signing.' }));
    const form = await openChecker(api(['viewer'], { checkAttestation }));
    await check(form, 'threatline-att.v1.x.z');
    const status = within(form).getByRole('status');
    await within(status).findByText('Not valid');
    expect(status.textContent).toContain('Signature invalid — the token was changed after signing.');
  });

  it('checks the inputs before asking the server', async () => {
    const checkAttestation = vi.fn();
    const form = await openChecker(api(['viewer'], { checkAttestation }));
    await userEvent.click(within(form).getByRole('button', { name: 'Check' }));
    expect(within(form).getByRole('alert').textContent).toMatch(/Paste an attestation/);
    await check(form, 'threatline-att.v1.x.y', 'abc');
    expect(within(form).getByRole('alert').textContent).toMatch(/40-character/);
    expect(checkAttestation).not.toHaveBeenCalled();
  });

  it('the fixture bridge verifies its own tokens and fails a changed one', async () => {
    const mock = mockApi('ready');
    const out = await mock.attestation('acme/payments', SHA);
    if (!('token' in out)) throw new Error('expected a token');
    expect(await mock.checkAttestation(out.token)).toMatchObject({ valid: true });
    expect(await mock.checkAttestation(out.token.replace('mock', 'mocK'))).toMatchObject({ valid: false, reason: 'bad_signature' });
  });

  it('has no axe violations with a result shown', async () => {
    const form = await openChecker(api(['viewer'], { checkAttestation: async () => valid }));
    await check(form, 'threatline-att.v1.x.y');
    await within(form).findByText('Valid');
    const results = await axe.run(form.closest('details')!, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});
