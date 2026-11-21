import type { ControlsPostureDto, PanelDto } from './types.js';

const NOTE = 'Indicative mapping from OWASP ASVS 5.0 to compliance controls, not an audit opinion. A mapped control shows where a requirement\'s evidence may help; it does not mean the control is met.';

/** The panel fixture's requirement controls (req_1 is V2.1.1; req_2 has no ASVS id, so no control). */
export const REQUIREMENT_CONTROLS_FIXTURE: NonNullable<PanelDto['requirementControls']> = {
  req_1: [
    { framework: 'SOC2', id: 'CC8.1', title: 'Changes to infrastructure, data, software and procedures are authorized, designed, tested, approved and implemented' },
    { framework: 'SOC2', id: 'PI1.2', title: 'System inputs are controlled for completeness and accuracy' },
    { framework: 'ISO27001', id: 'A.8.26', title: 'Application security requirements' },
    { framework: 'ISO27001', id: 'A.8.28', title: 'Secure coding' },
    { framework: 'PCIDSS', id: '6.2.4', title: 'Software engineering techniques prevent or mitigate common software attacks' },
  ],
  req_2: [],
};

const counts = (open: number, verified: number, acceptedRisk: number) => ({ open, verified, acceptedRisk, notApplicable: 0 });

/** A believable PAY controls view for the local preview and the UI tests. */
export const CONTROLS_FIXTURE: ControlsPostureDto = {
  disclaimer: NOTE,
  projects: ['PAY', 'OPS'],
  issuesCounted: 5,
  truncated: false,
  frameworks: [
    {
      framework: 'SOC2',
      name: 'SOC 2 Trust Services Criteria',
      version: '2017 (revised points of focus, 2022)',
      controls: [
        { id: 'CC6.1', title: 'Logical access security software, infrastructure and architectures protect information assets', state: 'open', counts: counts(3, 4, 1), issues: 4 },
        { id: 'CC6.3', title: 'Access is authorized, changed and removed by role, least privilege and segregation of duties', state: 'accepted', counts: counts(0, 2, 1), issues: 2 },
        { id: 'CC8.1', title: 'Changes to infrastructure, data, software and procedures are authorized, designed, tested, approved and implemented', state: 'verified', counts: counts(0, 5, 0), issues: 3 },
      ],
    },
    {
      framework: 'ISO27001',
      name: 'ISO/IEC 27001:2022 Annex A',
      version: '2022',
      controls: [
        { id: 'A.8.5', title: 'Secure authentication', state: 'open', counts: counts(2, 1, 0), issues: 2 },
        { id: 'A.8.28', title: 'Secure coding', state: 'verified', counts: counts(0, 5, 0), issues: 3 },
      ],
    },
    {
      framework: 'PCIDSS',
      name: 'PCI DSS',
      version: '4.0 (numbering unchanged in 4.0.1)',
      controls: [
        { id: '6.2.4', title: 'Software engineering techniques prevent or mitigate common software attacks', state: 'verified', counts: counts(0, 5, 0), issues: 3 },
        { id: '8.3.4', title: 'Invalid authentication attempts are limited', state: 'accepted', counts: counts(0, 0, 1), issues: 1 },
      ],
    },
  ],
};
