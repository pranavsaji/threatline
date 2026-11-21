import { describe, expect, it } from 'vitest';
import { ok } from '@threatline/shared';
import { COMPLIANCE_DISCLAIMER } from '@threatline/frameworks';
import { complianceExport, postureControlDrill, postureControls } from '../../src/resolvers/compliance.js';
import { acceptanceDecide, acceptanceRequest } from '../../src/resolvers/acceptances.js';
import { panelGet } from '../../src/resolvers/panel.js';
import { panelResolver } from '../../src/resolvers/index.js';
import { jiraIssue } from '../support/core-deps.js';
import { ADMIN, CHAMP, DEV, ISSUE, reviewed } from '../support/reviewed.js';

const ME = { accountId: 'acc-plain' };
const PAY7 = jiraIssue({ id: ISSUE, key: 'PAY-7' });
const SITE = 'https://one-atlas-mefc.atlassian.net';
const RANGE = { projectKey: 'PAY', from: '2026-11-01', to: '2026-11-30' };

/** PAY-7 reviewed: one High password/authentication requirement open (V6.3.1, V6.2.1), the baseline ones verified. */
async function scoped() {
  const r = await reviewed();
  r.t.jira.search = async () => ok([PAY7]);
  return r;
}

type Control = { id: string; state: string; counts: { open: number; verified: number; acceptedRisk: number; notApplicable: number }; acceptances?: Array<{ expiresAt: string; state: string }>; evidence?: unknown[] };
type Summary = { frameworks: ReadonlyArray<{ framework: string; controls: readonly Control[] }> };
const control = (s: Summary, fw: string, id: string) => s.frameworks.find((f) => f.framework === fw)?.controls.find((c) => c.id === id);

describe('compliance.export: the controls summary (indicative)', () => {
  it('Jira administrators only, and the request is validated like the evidence pack', async () => {
    const { t } = await scoped();
    expect(await complianceExport(t.deps, { accountId: DEV }, RANGE)).toMatchObject({ error: 'forbidden' });
    expect(await complianceExport(t.deps, { accountId: ADMIN }, { ...RANGE, from: '2026-12-31', to: '2026-12-01' })).toMatchObject({ error: 'validation' });
    expect(await complianceExport(t.deps, { accountId: ADMIN }, { ...RANGE, projectKey: 'pay; drop' })).toMatchObject({ error: 'validation' });
  });

  it('per framework and control: requirements by status, evidence and acceptances with expiry, as CSV and JSON', async () => {
    const { t, req } = await scoped();
    const asked = await acceptanceRequest(t.deps, { accountId: DEV, issueId: ISSUE }, { requirementId: req.id, reason: 'Behind the flag until the lockout ships.', controls: 'Feature flag off', expiryDays: 14 });
    if ('error' in asked) throw new Error('request failed');
    await acceptanceDecide(t.deps, { accountId: CHAMP, issueId: ISSUE }, { acceptanceId: asked.acceptanceId, decision: 'approve' });

    const pack = await complianceExport(t.deps, { accountId: ADMIN }, RANGE);
    if ('error' in pack) throw new Error(pack.error);
    const json = JSON.parse(pack.json) as Summary & { disclaimer: string; projectKey: string; from: string; to: string; requirementsCounted: number; truncated: boolean };
    expect(json).toMatchObject({ disclaimer: COMPLIANCE_DISCLAIMER, projectKey: 'PAY', from: '2026-11-01', to: '2026-11-30', requirementsCounted: 4, truncated: false });
    expect(json.frameworks.map((f) => f.framework)).toEqual(['SOC2', 'ISO27001', 'PCIDSS']);
    // The accepted authentication requirement: 8.3.4 is amber, with the acceptance and its expiry.
    const lockout = control(json, 'PCIDSS', '8.3.4')!;
    expect(lockout).toMatchObject({ state: 'accepted', counts: { open: 0, verified: 0, acceptedRisk: 1, notApplicable: 0 } });
    expect(lockout.acceptances).toEqual([expect.objectContaining({ state: 'active', expiresAt: '2026-11-29T12:00:00.000Z' })]);
    // Authorization (V8.2.1) was verified with evidence: 7.2.1 is green with the evidence link.
    expect(control(json, 'PCIDSS', '7.2.1')).toMatchObject({ state: 'verified', evidence: [expect.objectContaining({ ref: 'checked', kind: 'manual' })] });

    const lines = pack.csv.trim().split('\n');
    expect(lines[0]).toBe('framework,control_id,control_title,state,open,verified,accepted_risk,not_applicable,requirements,latest_evidence,acceptances,basis');
    expect(lines.find((l) => l.startsWith('PCIDSS,8.3.4,'))).toContain(',accepted,0,0,1,0,');
  });

  it('only work items the admin can browse are counted', async () => {
    const { t } = await scoped();
    t.jira.browsable = async () => ok([]);
    const pack = await complianceExport(t.deps, { accountId: ADMIN }, RANGE);
    if ('error' in pack) throw new Error(pack.error);
    expect(JSON.parse(pack.json)).toMatchObject({ requirementsCounted: 0, frameworks: [{ controls: [] }, { controls: [] }, { controls: [] }] });
  });
});

describe('posture.controls (dashboard Controls view)', () => {
  it('per framework, controls coloured by open (red), accepted (amber) and verified (green), with no requirement text', async () => {
    const { t } = await scoped();
    const p = await postureControls(t.deps, ME, {});
    if ('error' in p) throw new Error(p.error);
    expect(p.disclaimer).toBe(COMPLIANCE_DISCLAIMER);
    expect(p).toMatchObject({ projects: ['PAY'], issuesCounted: 1, truncated: false });
    expect(control(p, 'PCIDSS', '8.3.4')).toMatchObject({ state: 'open', counts: { open: 1 }, issues: 1 });
    expect(control(p, 'PCIDSS', '7.2.1')).toMatchObject({ state: 'verified' });
    expect(JSON.stringify(p)).not.toMatch(/req_/);
  });

  it('respects browse scope: nothing the viewer cannot see is counted', async () => {
    const { t } = await scoped();
    t.jira.browsable = async () => ok([]);
    const p = await postureControls(t.deps, ME, {});
    expect('frameworks' in p && p.frameworks.every((f) => f.controls.length === 0)).toBe(true);
  });

  it('a project filter must be an enabled project; no signed-in caller gets not_found', async () => {
    const { t } = await scoped();
    expect(await postureControls(t.deps, ME, { project: 'OPS' })).toMatchObject({ error: 'invalid_input' });
    expect(await postureControls(t.deps, { accountId: '' }, {})).toEqual({ error: 'not_found' });
  });
});

describe('posture.controlDrill', () => {
  it('lists the work items with requirements mapped to the control, with a JQL that opens the same list', async () => {
    const { t } = await scoped();
    const d = await postureControlDrill(t.deps, ME, { framework: 'PCIDSS', control: '8.3.4' });
    expect(d).toEqual({
      jql: 'key in (PAY-7) ORDER BY key ASC',
      searchUrl: `${SITE}/issues/?jql=${encodeURIComponent('key in (PAY-7) ORDER BY key ASC')}`,
      issues: [{ key: 'PAY-7', summary: 'Refund webhook', maxOpenSeverity: 'High', url: `${SITE}/browse/PAY-7` }],
      truncated: false,
    });
  });

  it('a control no requirement maps to lists nothing; unknown frameworks and controls are refused', async () => {
    const { t } = await scoped();
    expect(await postureControlDrill(t.deps, ME, { framework: 'PCIDSS', control: '4.2.1' })).toEqual({ jql: null, searchUrl: null, issues: [], truncated: false });
    expect(await postureControlDrill(t.deps, ME, { framework: 'NIST', control: 'AC-2' })).toMatchObject({ error: 'invalid_input' });
    expect(await postureControlDrill(t.deps, ME, { framework: 'PCIDSS', control: '99.9.9' })).toMatchObject({ error: 'invalid_input' });
  });

  it('never lists a work item the caller cannot browse', async () => {
    const { t } = await scoped();
    t.jira.browsable = async () => ok([]);
    expect(await postureControlDrill(t.deps, ME, { framework: 'PCIDSS', control: '8.3.4' })).toEqual({ jql: null, searchUrl: null, issues: [], truncated: false });
  });
});

describe('panel: requirement controls', () => {
  it('each shown requirement carries its mapped controls with titles', async () => {
    const { t, req } = await scoped();
    const dto = await panelGet(t.deps, { accountId: DEV, issueId: ISSUE });
    if ('error' in dto) throw new Error(dto.error);
    const refs = dto.requirementControls?.[req.id] ?? [];
    expect(refs.map((c) => `${c.framework} ${c.id}`)).toEqual(expect.arrayContaining(['SOC2 CC6.1', 'ISO27001 A.8.5', 'PCIDSS 8.3.4']));
    for (const c of refs) expect(c.title.length).toBeGreaterThan(3);
    expect(Object.keys(dto.requirementControls ?? {}).sort()).toEqual(dto.requirements.map((r) => r.id).sort());
  });
});

describe('registered resolvers', () => {
  type Call = (req: { call: { functionKey: string; payload?: unknown }; context: unknown }) => Promise<unknown>;
  it('compliance.export refuses a call with no signed-in user; the posture calls give not_found', async () => {
    const call = panelResolver as unknown as Call;
    expect(await call({ call: { functionKey: 'compliance.export', payload: RANGE }, context: {} })).toMatchObject({ error: 'forbidden' });
    expect(await call({ call: { functionKey: 'posture.controls', payload: {} }, context: {} })).toEqual({ error: 'not_found' });
    expect(await call({ call: { functionKey: 'posture.controlDrill', payload: { framework: 'SOC2', control: 'CC6.1' } }, context: {} })).toEqual({ error: 'not_found' });
  });
});
