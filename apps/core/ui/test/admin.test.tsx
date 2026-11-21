// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { AdminPage } from '../src/admin/AdminPage.js';
import { mockAdminApi } from '../src/mock-bridge.js';
import type { AdminApi } from '../src/bridge.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

describe('Admin: demo data (Task 24)', () => {
  it('loads the demo into the given project and space and lists what it created', async () => {
    const seed = vi.fn(async () => ({ epicKey: 'PAY-100', storyKeys: ['PAY-101', 'PAY-102'], designPageUrl: 'https://x/wiki/pages/500', incidentKeys: ['PAY-103', 'PAY-104'] }));
    render(<AdminPage api={{ ...mockAdminApi(), seed }} />);
    const form = await screen.findByRole('form', { name: 'Load demo data' });
    await userEvent.clear(within(form).getByRole('textbox', { name: 'Jira project key' }));
    await userEvent.type(within(form).getByRole('textbox', { name: 'Jira project key' }), 'pay');
    await userEvent.type(within(form).getByRole('textbox', { name: 'Confluence space key' }), 'PAY');
    await userEvent.click(within(form).getByRole('button', { name: 'Load demo data' }));
    expect(seed).toHaveBeenCalledWith('PAY', 'PAY');
    expect(await screen.findByText(/Epic PAY-100, stories PAY-101, PAY-102, incidents PAY-103, PAY-104/)).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Open the design page' }).getAttribute('href')).toBe('https://x/wiki/pages/500');
  });

  it('shows the server’s error', async () => {
    const seed = vi.fn(async () => ({ error: 'validation' as const, message: 'Project NOPE was not found.' }));
    render(<AdminPage api={{ ...mockAdminApi(), seed }} />);
    const form = await screen.findByRole('form', { name: 'Load demo data' });
    await userEvent.type(within(form).getByRole('textbox', { name: 'Confluence space key' }), 'X');
    await userEvent.click(within(form).getByRole('button', { name: 'Load demo data' }));
    expect(await screen.findByText('Project NOPE was not found.')).toBeTruthy();
  });
});

describe('Admin: setup checklist (Task 24)', () => {
  it('shows each step as done or to do, in words', async () => {
    const api: AdminApi = {
      ...mockAdminApi(),
      setupStatus: async () => ({ keys: true, sqlVersion: 3, validatorSeenOn: ['PAY'], automationRuleSeen: false, mcpEnabledHint: 'Allow MCP clients in Rovo settings.', bitbucketKeyCopied: false }),
    };
    render(<AdminPage api={api} />);
    const list = await screen.findByRole('list', { name: 'Setup checklist' });
    expect(within(list).getByText(/Signing keys created/).closest('li')!.textContent).toMatch(/Done/);
    expect(within(list).getByText(/Done gate seen on PAY/)).toBeTruthy();
    expect(within(list).getByText(/No Automation agent run in the last 7 days/).closest('li')!.textContent).toMatch(/To do/);
    // Security: unlocked review runs are a to-do item.
    expect((await within(list).findByText(/lock them to the Automation rule owner/)).closest('li')!.textContent).toMatch(/To do/);
    // Feature: the item points sites without Rovo to rule-based review.
    expect(within(list).getByText(/No Rovo on this site\? Choose rule-based checks under Review mode/)).toBeTruthy();
    expect(within(list).getByText('Allow MCP clients in Rovo settings.')).toBeTruthy();
  });

  it('feature: in rule-based mode, the agent-run item is done and says no Rovo is needed', async () => {
    const base = mockAdminApi();
    const dto = await base.getPolicy();
    if ('error' in dto) throw new Error('fixture');
    const api: AdminApi = {
      ...base,
      getPolicy: async () => ({ ...dto, policy: { ...dto.policy, reviewMode: 'rules_only' } }),
      setupStatus: async () => ({ keys: true, sqlVersion: 3, validatorSeenOn: ['PAY'], automationRuleSeen: false, mcpEnabledHint: 'x', bitbucketKeyCopied: false }),
    };
    render(<AdminPage api={api} />);
    const list = await screen.findByRole('list', { name: 'Setup checklist' });
    expect((await within(list).findByText(/Rule-based checks only: no Rovo or Automation rule needed/)).closest('li')!.textContent).toMatch(/Done/);
  });

  it('feature: when the gate has not been seen, one click adds it to the workflow and says where', async () => {
    const installGate = vi.fn(async () => ({ projects: [{ projectKey: 'PAY', added: ['Software workflow for project PAY: Done'], already: [], readOnly: [] }] }));
    const api: AdminApi = {
      ...mockAdminApi(),
      installGate,
      setupStatus: async () => ({ keys: true, sqlVersion: 4, validatorSeenOn: [], automationRuleSeen: false, mcpEnabledHint: 'x', bitbucketKeyCopied: false }),
    };
    render(<AdminPage api={api} />);
    const list = await screen.findByRole('list', { name: 'Setup checklist' });
    await userEvent.click(within(list).getByRole('button', { name: 'Add the gate for me' }));
    expect(installGate).toHaveBeenCalledOnce();
    expect(await within(list).findByText('Added the gate to Software workflow for project PAY: Done.')).toBeTruthy();
  });

  it('a non-admin sees a plain message', async () => {
    render(<AdminPage api={{ ...mockAdminApi(), setupStatus: async () => ({ error: 'forbidden' as const, message: 'Only a Jira administrator can do this.' }) }} />);
    expect(await screen.findByText('Only a Jira administrator can do this.')).toBeTruthy();
  });

  it.each(['light', 'dark'])('has no axe violations (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = render(<AdminPage api={mockAdminApi()} />);
    await screen.findByRole('list', { name: 'Setup checklist' });
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});

describe('Admin: first-run wizard (Task 30)', () => {
  it('shows until a policy is saved: enable a project, pick the guarded transition, set groups, save', async () => {
    const api = mockAdminApi('first');
    const setPolicy = vi.fn(api.setPolicy);
    const projectStatuses = vi.fn(api.projectStatuses);
    render(<AdminPage api={{ ...api, setPolicy, projectStatuses }} />);
    const form = await screen.findByRole('form', { name: 'First-run setup' });
    await userEvent.type(within(form).getByRole('textbox', { name: 'Jira project key' }), 'pay');
    await userEvent.click(within(form).getByRole('button', { name: 'Load statuses' }));
    expect(projectStatuses).toHaveBeenCalledWith('PAY');
    await userEvent.selectOptions(await within(form).findByRole('combobox', { name: 'Guarded transition' }), 'In Review');
    await userEvent.clear(within(form).getByRole('textbox', { name: 'Security champions group' }));
    await userEvent.type(within(form).getByRole('textbox', { name: 'Security champions group' }), 'appsec');
    await userEvent.click(within(form).getByRole('button', { name: 'Save and continue' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ enabledProjects: ['PAY'], guardedTransitions: ['In Review'], championGroup: 'appsec' }));
    expect(await screen.findByText(/Threatline is on for PAY/)).toBeTruthy();
    expect(screen.getByText(/add "Threatline security gate" to the In Review transition/)).toBeTruthy();
  });

  it('is not shown once a policy has been saved', async () => {
    render(<AdminPage api={mockAdminApi()} />);
    await screen.findByRole('form', { name: 'Severity policy' });
    expect(screen.queryByRole('form', { name: 'First-run setup' })).toBeNull();
  });
});

describe('Admin: policy sections (Task 30)', () => {
  it('severity policy: saves the block level, sensitive paths and attestation lifetime', async () => {
    const api = mockAdminApi();
    const setPolicy = vi.fn(api.setPolicy);
    render(<AdminPage api={{ ...api, setPolicy }} />);
    const form = await screen.findByRole('form', { name: 'Severity policy' });
    await userEvent.selectOptions(within(form).getByRole('combobox', { name: 'Block at or above' }), 'Critical');
    const paths = within(form).getByRole('textbox', { name: 'Sensitive paths (one per line)' });
    await userEvent.clear(paths);
    await userEvent.type(paths, 'src/auth/**{enter}{enter}infra/**');
    await userEvent.click(within(form).getByRole('button', { name: 'Save severity policy' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ blockAtOrAbove: 'Critical', sensitivePaths: ['src/auth/**', 'infra/**'], attestationTtlHours: 24 }));
    expect(await within(form).findByText('Saved. Threatline rechecks verdicts against the new policy.')).toBeTruthy();
  });

  it('projects: saves the enabled projects, work types and guarded transitions, and shows the server’s error', async () => {
    const api = mockAdminApi();
    const setPolicy = vi.fn(async () => ({ error: 'validation' as const, message: 'Jira project NOPE was not found.' }));
    render(<AdminPage api={{ ...api, setPolicy }} />);
    const form = await screen.findByRole('form', { name: 'Projects and transitions' });
    const projects = within(form).getByRole('textbox', { name: 'Enabled projects' });
    await userEvent.clear(projects);
    await userEvent.type(projects, 'pay, nope');
    await userEvent.click(within(form).getByRole('button', { name: 'Save projects' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ enabledProjects: ['PAY', 'NOPE'], reviewIssueTypes: ['Epic', 'Story'], guardedTransitions: ['Done'] }));
    expect((await within(form).findByRole('alert')).textContent).toBe('Jira project NOPE was not found.');
  });

  it('roles: saves the groups and the tech lead acceptance cap', async () => {
    const api = mockAdminApi();
    const setPolicy = vi.fn(api.setPolicy);
    render(<AdminPage api={{ ...api, setPolicy }} />);
    const form = await screen.findByRole('form', { name: 'Roles' });
    await userEvent.selectOptions(within(form).getByRole('combobox', { name: 'Tech leads may accept risk up to' }), 'Low');
    await userEvent.click(within(form).getByRole('button', { name: 'Save roles' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ techLeadMaxSeverity: 'Low', championGroup: 'threatline-security-champions', techLeadGroup: 'threatline-tech-leads' }));
  });

  it('roles: the tech lead cap offers only Low and Medium (High and above always need a security champion)', async () => {
    render(<AdminPage api={mockAdminApi()} />);
    const form = await screen.findByRole('form', { name: 'Roles' });
    const cap = within(form).getByRole('combobox', { name: 'Tech leads may accept risk up to' }) as HTMLSelectElement;
    expect([...cap.options].map((o) => o.value)).toEqual(['Low', 'Medium']);
    expect(screen.getByText(/High and Critical always need a security champion/)).toBeTruthy();
  });

  it('a non-admin sees a plain message instead of the policy', async () => {
    render(<AdminPage api={{ ...mockAdminApi(), getPolicy: async () => ({ error: 'forbidden' as const, message: 'Only a Jira administrator can do this.' }) }} />);
    expect((await screen.findAllByText('Only a Jira administrator can do this.')).length).toBeGreaterThan(0);
    expect(screen.queryByRole('form', { name: 'Severity policy' })).toBeNull();
  });
});

describe('Admin: budgets (Task 30)', () => {
  it('shows this month’s use against the budget, and saves new caps', async () => {
    const api = mockAdminApi();
    const setPolicy = vi.fn(api.setPolicy);
    render(<AdminPage api={{ ...api, setPolicy }} />);
    expect(await screen.findByText('42 of 500 reviews this month (2026-11), 118 agent runs.')).toBeTruthy();
    const form = screen.getByRole('form', { name: 'Budgets' });
    const reviews = within(form).getByRole('spinbutton', { name: 'Reviews per month' });
    await userEvent.clear(reviews);
    await userEvent.type(reviews, '800');
    await userEvent.selectOptions(within(form).getByRole('combobox', { name: 'Agent samples per review' }), '5');
    await userEvent.click(within(form).getByRole('button', { name: 'Save budgets' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ budget: expect.objectContaining({ reviewsPerMonth: 800 }), agentSamples: 5 }));
  });

  it('feature: an admin can switch to rule-based checks only, for a site without Rovo', async () => {
    const api = mockAdminApi();
    const setPolicy = vi.fn(api.setPolicy);
    render(<AdminPage api={{ ...api, setPolicy }} />);
    const form = await screen.findByRole('form', { name: 'Review mode' });
    await userEvent.click(within(form).getByRole('radio', { name: /Rule-based checks only/ }));
    await userEvent.click(within(form).getByRole('button', { name: 'Save review mode' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ reviewMode: 'rules_only' }));
  });

  it('feature: an admin chooses Threatline Engine; the checklist then needs no Rovo, Automation rule or review authors', async () => {
    const api = mockAdminApi();
    const setPolicy = vi.fn(api.setPolicy);
    const dto = await api.getPolicy();
    if ('error' in dto) throw new Error('fixture');
    render(<AdminPage api={{ ...api, setPolicy, getPolicy: async () => ({ ...dto, policy: { ...dto.policy, reviewMode: 'engine' } }) }} />);
    const list = await screen.findByRole('list', { name: 'Setup checklist' });
    expect((await within(list).findByText(/Threatline Engine runs every review itself/)).closest('li')!.textContent).toMatch(/Done/);
    expect(within(list).getByText(/Threatline Engine writes reviews itself/).closest('li')!.textContent).toMatch(/Done/);
    const form = screen.getByRole('form', { name: 'Review mode' });
    expect((within(form).getByRole('radio', { name: /Threatline Engine \(recommended\)/ }) as HTMLInputElement).checked).toBe(true);
    await userEvent.click(within(form).getByRole('button', { name: 'Save review mode' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ reviewMode: 'engine', budget: expect.objectContaining({ tokensInPerReview: 400000, tokensOutPerReview: 60000 }) }));
  });

  it('security: an admin locks AI review runs to the account that runs the Automation rule', async () => {
    const api = mockAdminApi();
    const setPolicy = vi.fn(api.setPolicy);
    render(<AdminPage api={{ ...api, setPolicy }} />);
    const form = await screen.findByRole('form', { name: 'Review authors' });
    expect(within(form).getByText(/712020:automation-owner/)).toBeTruthy();
    await userEvent.click(within(form).getByRole('radio', { name: /Only these accounts/ }));
    await userEvent.click(within(form).getByRole('button', { name: 'Use 712020:automation-owner' }));
    expect((within(form).getByRole('textbox', { name: 'Account IDs, one per line' }) as HTMLTextAreaElement).value).toBe('712020:automation-owner');
    await userEvent.click(within(form).getByRole('button', { name: 'Save review authors' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ reviewAuthors: ['712020:automation-owner'] }));
  });

  it('says when reviews are paused, and why', async () => {
    const api = mockAdminApi();
    render(<AdminPage api={{ ...api, usage: async () => ({ ...(await api.usage() as Exclude<Awaited<ReturnType<AdminApi['usage']>>, { error: string }>), paused: { budget: false, credits: true } }) }} />);
    expect(await screen.findByText(/Reviews are paused: the last three agent runs came back empty/)).toBeTruthy();
  });

  it('final review C3: an admin can resume reviews after an out-of-credits pause', async () => {
    const api = mockAdminApi();
    const resumeReviews = vi.fn(async () => ({ resumed: true as const, entryHash: 'a'.repeat(64) }));
    let credits = true;
    const usage = async () => ({ ...(await api.usage() as Exclude<Awaited<ReturnType<AdminApi['usage']>>, { error: string }>), paused: { budget: false, credits } });
    render(<AdminPage api={{ ...api, usage, resumeReviews: async () => ((credits = false), resumeReviews()) }} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Resume reviews' }));
    expect(await screen.findByText('Reviews are running.')).toBeTruthy();
    expect(resumeReviews).toHaveBeenCalledOnce();
  });
});

describe('Admin: warn-only (Task 30)', () => {
  it('rejects 20 days without calling the server', async () => {
    const api = mockAdminApi();
    const warnOnly = vi.fn(api.warnOnly);
    render(<AdminPage api={{ ...api, warnOnly }} />);
    const form = await screen.findByRole('form', { name: 'Warn-only for PAY' });
    const days = within(form).getByRole('spinbutton', { name: 'Days (1 to 14)' });
    await userEvent.clear(days);
    await userEvent.type(days, '20');
    await userEvent.click(within(form).getByRole('button', { name: 'Switch PAY to warn-only' }));
    expect(warnOnly).not.toHaveBeenCalled();
    expect(within(form).getByRole('alert').textContent).toBe('Warn-only lasts 1 to 14 days.');
  });

  it('switches a project to warn-only, shows until when, and ending it needs a second click', async () => {
    const api = mockAdminApi();
    const warnOnly = vi.fn(api.warnOnly);
    const endWarnOnly = vi.fn(api.endWarnOnly);
    render(<AdminPage api={{ ...api, warnOnly, endWarnOnly }} />);
    const form = await screen.findByRole('form', { name: 'Warn-only for PAY' });
    await userEvent.click(within(form).getByRole('button', { name: 'Switch PAY to warn-only' }));
    expect(warnOnly).toHaveBeenCalledWith('PAY', 7);
    const list = screen.getByRole('list', { name: 'Warn-only by project' });
    expect(await within(list).findByText(/PAY: warn-only until/)).toBeTruthy();
    await userEvent.click(within(list).getByRole('button', { name: 'End warn-only for PAY' }));
    expect(endWarnOnly).not.toHaveBeenCalled();
    await userEvent.click(within(list).getByRole('button', { name: 'Confirm: end warn-only for PAY' }));
    expect(endWarnOnly).toHaveBeenCalledWith('PAY');
    expect(await within(list).findByText('PAY: blocking')).toBeTruthy();
  });
});

describe('Admin: notifications (Task 30)', () => {
  it('saves the ops alerts work item and the digest space; empty turns one off', async () => {
    const api = mockAdminApi();
    const setNotifications = vi.fn(api.setNotifications);
    render(<AdminPage api={{ ...api, setNotifications }} />);
    const form = await screen.findByRole('form', { name: 'Notifications' });
    await userEvent.type(within(form).getByRole('textbox', { name: 'Ops alerts work item' }), 'ops-12');
    await userEvent.type(within(form).getByRole('textbox', { name: 'People to mention (account IDs, comma-separated)' }), 'acc-1, acc-2');
    await userEvent.click(within(form).getByRole('button', { name: 'Save notifications' }));
    expect(setNotifications).toHaveBeenCalledWith({ ops: { issueKey: 'OPS-12', accountIds: ['acc-1', 'acc-2'] }, digest: null });
  });
});

describe('Admin: recent runs (Task 30)', () => {
  it('lists the last runs with status, duration and failure, and shows the stage timings on request', async () => {
    render(<AdminPage api={mockAdminApi()} />);
    const table = await screen.findByRole('table', { name: 'Last 50 runs' });
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(4);
    expect(rows[1]!.textContent).toMatch(/PAY-9.*Timed out.*15 min.*1 of 3/);
    expect(rows[3]!.textContent).toMatch(/PAY-12.*Failed.*Budget reached/);
    await userEvent.click(within(table).getByRole('button', { name: 'Show stages for PAY-9 revision 1' }));
    const stages = screen.getByRole('list', { name: 'Stages of PAY-9 revision 1' });
    expect(within(stages).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['Gather context: done, 0 s', 'Agent run 1: done, 1 min', 'Agent runs: failed (timed out), 14 min']);
  });
});

describe('Admin page layout (Task 30)', () => {
  it('has a section index linking to every section', async () => {
    render(<AdminPage api={mockAdminApi()} />);
    const nav = await screen.findByRole('navigation', { name: 'Admin sections' });
    expect(within(nav).getAllByRole('link').map((a) => a.textContent)).toEqual([
      'Setup checklist', 'Projects and transitions', 'Severity policy', 'Roles', 'Review mode', 'Budgets', 'Warn-only mode', 'Notifications', 'Suppressions', 'Recent runs', 'Signing keys', 'Risk ledger', 'Data retention', 'Demo data',
    ]);
  });

  it.each(['light', 'dark'])('the full page has no axe violations (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = render(<AdminPage api={mockAdminApi()} />);
    await screen.findByRole('table', { name: 'Last 50 runs' });
    await screen.findByRole('form', { name: 'Severity policy' });
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});

describe('Admin: transparency log (R5)', () => {
  it('shows the current signed tree head and whether it is published', async () => {
    render(<AdminPage api={mockAdminApi()} />);
    const head = await screen.findByRole('group', { name: 'Signed tree head' });
    expect(head.textContent).toMatch(/12 entries/);
    expect(head.textContent).toMatch(/Root 3a03ebd5cbaa…/);
    expect(head.textContent).toMatch(/key k-mock/);
    expect(head.textContent).toMatch(/Not published to Confluence yet/);
  });

  it('downloads an inclusion proof for one entry, to check offline', async () => {
    const api = mockAdminApi();
    const ledgerProof = vi.fn(api.ledgerProof);
    render(<AdminPage api={{ ...api, ledgerProof }} />);
    const form = await screen.findByRole('form', { name: 'Inclusion proof' });
    await userEvent.type(within(form).getByRole('spinbutton', { name: 'Ledger entry number' }), '3');
    await userEvent.click(within(form).getByRole('button', { name: 'Get proof' }));
    expect(ledgerProof).toHaveBeenCalledWith(3);
    const link = await within(form).findByRole('link', { name: 'Download proof for entry 3' });
    expect(link.getAttribute('download')).toBe('threatline-ledger-proof-3.json');
    expect(decodeURIComponent(link.getAttribute('href')!)).toContain('"format": "threatline-ledger-proof-v1"');
    expect(within(form).getByText(/node scripts\/verify-ledger-proof.mjs/)).toBeTruthy();
  });

  it('rejects an entry number below 1 without calling the server', async () => {
    const api = mockAdminApi();
    const ledgerProof = vi.fn(api.ledgerProof);
    render(<AdminPage api={{ ...api, ledgerProof }} />);
    const form = await screen.findByRole('form', { name: 'Inclusion proof' });
    await userEvent.type(within(form).getByRole('spinbutton', { name: 'Ledger entry number' }), '0');
    await userEvent.click(within(form).getByRole('button', { name: 'Get proof' }));
    expect(ledgerProof).not.toHaveBeenCalled();
    expect(within(form).getByRole('alert').textContent).toBe('Give a ledger entry number (1 or more).');
  });
});

describe('Admin: data retention (privacy purge)', () => {
  it('purges a project only after its key is typed again, and says what was deleted and what was kept', async () => {
    const api = mockAdminApi();
    const purgeProject = vi.fn(api.purgeProject);
    render(<AdminPage api={{ ...api, purgeProject }} />);
    const form = await screen.findByRole('form', { name: 'Purge a project' });
    await userEvent.type(within(form).getByRole('textbox', { name: 'Project key' }), 'old');
    await userEvent.type(within(form).getByRole('textbox', { name: 'Type the key again to confirm' }), 'OL');
    await userEvent.click(within(form).getByRole('button', { name: 'Purge reviews' }));
    expect(purgeProject).not.toHaveBeenCalled();
    expect(within(form).getByRole('alert').textContent).toBe('Type OLD to confirm. This cannot be undone.');
    await userEvent.type(within(form).getByRole('textbox', { name: 'Type the key again to confirm' }), 'D');
    await userEvent.click(within(form).getByRole('button', { name: 'Purge reviews' }));
    expect(purgeProject).toHaveBeenCalledWith('OLD', 'OLD');
    expect((await within(form).findByRole('status')).textContent).toBe('Purged OLD: 3 reviews and 2 requirements deleted. The risk ledger is kept.');
  });

  it('shows the server’s reason when the project is still reviewed', async () => {
    const api = mockAdminApi();
    render(<AdminPage api={api} />);
    const form = await screen.findByRole('form', { name: 'Purge a project' });
    await userEvent.type(within(form).getByRole('textbox', { name: 'Project key' }), 'PAY');
    await userEvent.type(within(form).getByRole('textbox', { name: 'Type the key again to confirm' }), 'PAY');
    await userEvent.click(within(form).getByRole('button', { name: 'Purge reviews' }));
    expect((await within(form).findByRole('alert')).textContent).toBe('Threatline still reviews PAY. Turn it off under Projects and transitions first, then purge.');
  });
});
