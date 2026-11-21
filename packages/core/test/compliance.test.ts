import { describe, expect, it } from 'vitest';
import { COMPLIANCE_DISCLAIMER } from '@threatline/frameworks';
import { controlsCell, controlsPosture, controlsSummary, controlsSummaryCsv, csvCell, requirementControls, requirementsForControl } from '../src/index.js';
import { acceptance, requirement } from './fixtures/verdict.js';

// V6.2.1 (password length) → SOC2 CC6.1, ISO A.5.17 + A.8.5, PCI 8.3.1 + 8.3.2 + 8.3.6.
// V8.2.1 (authorization) → SOC2 CC6.1 + CC6.3, ISO A.5.15 + A.8.3, PCI 6.2.4 + 7.2.1 + 7.2.2.
const pw = requirement({ id: 'req_pw', issueKey: 'PAY-1', asvsIds: ['V6.2.1'], status: 'Open', createdAt: '2026-11-02T00:00:00.000Z' });
const authz = requirement({
  id: 'req_authz', issueKey: 'PAY-2', asvsIds: ['V8.2.1'], status: 'Verified', createdAt: '2026-11-02T00:00:00.000Z', verifiedAt: '2026-11-05T00:00:00.000Z',
  evidence: { kind: 'pr', ref: 'https://bitbucket.org/acme/pay/pull-requests/7', attester: 'acc-dev' },
});
const accepted = requirement({ id: 'req_acc', issueKey: 'PAY-3', asvsIds: ['V8.3.1'], status: 'AcceptedRisk', createdAt: '2026-11-03T00:00:00.000Z' });
const later = requirement({ id: 'req_later', issueKey: 'PAY-4', asvsIds: ['V6.2.2'], status: 'Open', createdAt: '2026-12-15T00:00:00.000Z' });
const none = requirement({ id: 'req_none', issueKey: 'PAY-5', asvsIds: [], status: 'Open' });
const acc = acceptance({ id: 'acc_1', requirementId: 'req_acc', state: 'active', createdAt: '2026-11-04T00:00:00.000Z', expiresAt: '2026-12-04T00:00:00.000Z' });

const row = (s: ReturnType<typeof controlsSummary>, fw: string, id: string) => s.frameworks.find((f) => f.framework === fw)!.controls.find((c) => c.id === id);

describe('requirement controls (indicative)', () => {
  it('maps a requirement through its ASVS ids', () => {
    expect(requirementControls(pw).map((c) => `${c.framework} ${c.id}`)).toEqual(['SOC2 CC6.1', 'ISO27001 A.5.17', 'ISO27001 A.8.5', 'PCIDSS 8.3.1', 'PCIDSS 8.3.2', 'PCIDSS 8.3.6']);
    expect(requirementControls(none)).toEqual([]);
  });
  it('controlsCell joins framework and id for a CSV cell', () => {
    expect(controlsCell(requirementControls(pw))).toBe('SOC2 CC6.1; ISO27001 A.5.17; ISO27001 A.8.5; PCIDSS 8.3.1; PCIDSS 8.3.2; PCIDSS 8.3.6');
    expect(controlsCell([])).toBe('');
  });
  it('csvCell quotes and neutralises spreadsheet formulas', () => {
    expect(csvCell('=SUM(A1)')).toBe("'=SUM(A1)");
    expect(csvCell('a,"b"')).toBe('"a,""b"""');
    expect(csvCell('plain')).toBe('plain');
  });
});

describe('controlsSummary', () => {
  const s = controlsSummary({ requirements: [pw, authz, accepted, later, none], acceptances: [acc], from: '2026-11-01', to: '2026-11-30' });

  it('is marked indicative and lists the three frameworks in order', () => {
    expect(s.disclaimer).toBe(COMPLIANCE_DISCLAIMER);
    expect(s.frameworks.map((f) => f.framework)).toEqual(['SOC2', 'ISO27001', 'PCIDSS']);
    expect(s.frameworks[0]!.name).toMatch(/SOC 2/);
  });

  it('counts requirements per control by status, and colours the control by the worst one', () => {
    // CC6.1: pw (Open), authz (Verified), accepted (AcceptedRisk).
    expect(row(s, 'SOC2', 'CC6.1')).toMatchObject({ state: 'open', counts: { open: 1, verified: 1, acceptedRisk: 1, notApplicable: 0 } });
    // CC6.3: authz (Verified) and accepted (AcceptedRisk), nothing open.
    expect(row(s, 'SOC2', 'CC6.3')).toMatchObject({ state: 'accepted', counts: { open: 0, verified: 1, acceptedRisk: 1 } });
    // 8.3.6: only pw (Open). The requirement created after the range is left out.
    expect(row(s, 'PCIDSS', '8.3.6')).toMatchObject({ state: 'open', counts: { open: 1, verified: 0, acceptedRisk: 0 } });
    expect(row(s, 'PCIDSS', '8.3.6')!.requirements.map((r) => r.id)).toEqual(['req_pw']);
  });

  it('a control whose requirements are all verified is green; controls with no requirement are not listed', () => {
    const only = controlsSummary({ requirements: [authz], acceptances: [] });
    expect(row(only, 'PCIDSS', '7.2.1')).toMatchObject({ state: 'verified', counts: { open: 0, verified: 1, acceptedRisk: 0, notApplicable: 0 } });
    expect(row(only, 'PCIDSS', '8.3.6')).toBeUndefined();
  });

  it('lists the latest evidence links and the acceptances with their expiry', () => {
    expect(row(s, 'PCIDSS', '7.2.1')!.evidence).toEqual([{ requirementId: 'req_authz', issueKey: 'PAY-2', kind: 'pr', ref: 'https://bitbucket.org/acme/pay/pull-requests/7', verifiedAt: '2026-11-05T00:00:00.000Z' }]);
    expect(row(s, 'SOC2', 'CC6.3')!.acceptances).toEqual([{ acceptanceId: 'acc_1', requirementId: 'req_acc', issueKey: 'PAY-3', state: 'active', severity: 'High', expiresAt: '2026-12-04T00:00:00.000Z', approvedBy: 'champ' }]);
  });

  it('evidence verified outside the range, and acceptances that do not overlap it, are left out', () => {
    const dec = controlsSummary({ requirements: [authz, accepted], acceptances: [acc], from: '2026-12-10', to: '2026-12-31' });
    expect(row(dec, 'PCIDSS', '7.2.1')!.evidence).toEqual([]);
    expect(row(dec, 'SOC2', 'CC6.3')!.acceptances).toEqual([]);
    // The requirement itself still counts: it existed in the range.
    expect(row(dec, 'PCIDSS', '7.2.1')!.counts.verified).toBe(1);
  });

  it('keeps at most five evidence links per control, newest first', () => {
    const many = Array.from({ length: 7 }, (_, i) => ({ ...authz, id: `req_${i}`, verifiedAt: `2026-11-1${i}T00:00:00.000Z`, evidence: { kind: 'test' as const, ref: `tests/authz-${i}.test.ts`, attester: 'a' } }));
    const r = row(controlsSummary({ requirements: many, acceptances: [] }), 'ISO27001', 'A.5.15')!;
    expect(r.evidence.map((e) => e.requirementId)).toEqual(['req_6', 'req_5', 'req_4', 'req_3', 'req_2']);
    expect(r.counts.verified).toBe(7);
  });

  it('counts requirements with no mapped control as unmapped', () => {
    expect(s.requirementsCounted).toBe(4);
    expect(s.unmapped).toBe(1);
  });
});

describe('controlsSummaryCsv', () => {
  it('one row per framework and control, with the indicative note on every row and formulas neutralised', () => {
    const s = controlsSummary({ requirements: [pw, { ...authz, title: '=cmd|calc' }], acceptances: [] });
    const lines = controlsSummaryCsv(s).trim().split('\n');
    expect(lines[0]).toBe('framework,control_id,control_title,state,open,verified,accepted_risk,not_applicable,requirements,latest_evidence,acceptances,basis');
    const pci = lines.find((l) => l.startsWith('PCIDSS,8.3.6,'))!;
    expect(pci).toContain(',open,1,0,0,0,');
    expect(pci).toContain('req_pw (PAY-1, sub-task PROJ-150) Open');
    expect(pci.endsWith('"indicative, not an audit opinion"')).toBe(true);
    expect(lines.length).toBe(1 + s.frameworks.reduce((n, f) => n + f.controls.length, 0));
  });
});

describe('controlsPosture and requirementsForControl', () => {
  it('strips requirement details for the dashboard and keeps the counts', () => {
    const p = controlsPosture(controlsSummary({ requirements: [pw, authz], acceptances: [] }));
    expect(p.disclaimer).toBe(COMPLIANCE_DISCLAIMER);
    const cc61 = p.frameworks[0]!.controls.find((c) => c.id === 'CC6.1')!;
    expect(cc61).toEqual({ id: 'CC6.1', title: expect.any(String), state: 'open', counts: { open: 1, verified: 1, acceptedRisk: 0, notApplicable: 0 }, issues: 2 });
    expect(JSON.stringify(p)).not.toContain('req_pw');
  });
  it('finds the requirements behind one control', () => {
    expect(requirementsForControl([pw, authz, none], 'PCIDSS', '8.3.6').map((r) => r.id)).toEqual(['req_pw']);
    expect(requirementsForControl([pw, authz], 'SOC2', 'CC6.1').map((r) => r.id)).toEqual(['req_pw', 'req_authz']);
    expect(requirementsForControl([pw], 'SOC2', 'CC9.9')).toEqual([]);
  });
});
