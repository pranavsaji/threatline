import { describe, expect, it } from 'vitest';
import { EvidenceSchema, explicitIssueKeys, isRequirementId, namedIssueKeys, requirementIdsIn } from '../src/index.js';

const A = 'req_1a2b3c4d5e6f7a8b';
const B = 'req_0000ffff0000ffff';

describe('requirementIdsIn (feature: verification from CI)', () => {
  it('finds requirement ids in test names as the skeletons write them (TypeScript, pytest, JUnit)', () => {
    expect(requirementIdsIn(`PAY-101 Mitigate: Forged refund webhooks [${A}] > rejects a bad signature`)).toEqual([A]);
    expect(requirementIdsIn(`tests.test_webhooks test_${A}_the_request_is_rejected`)).toEqual([A]);
    expect(requirementIdsIn(`com.acme.Pay101SecurityTest ${A}_theRequestIsRejected()`)).toEqual([A]);
    expect(requirementIdsIn(`${A} and ${B}, ${A} again`)).toEqual([A, B]);
  });

  it('is strict: exactly req_ and 16 lowercase hex digits, not glued to other letters or digits', () => {
    for (const name of ['req_1a2b3c4d5e6f7a8', 'req_1A2B3C4D5E6F7A8B', `x${A}`, `${A}0`, `${A}f`, `9${A}`, 'req_1a2b3c4d5e6f7a8bz', 'requirement 1a2b3c4d5e6f7a8b', ''])
      expect(requirementIdsIn(name), name).toEqual([]);
    expect(requirementIdsIn(`(${A})`)).toEqual([A]);
    expect(requirementIdsIn(`a/${A}.test.ts`)).toEqual([A]);
  });

  it('isRequirementId accepts only the generated format', () => {
    expect(isRequirementId(A)).toBe(true);
    expect(isRequirementId('req_1')).toBe(false);
    expect(isRequirementId(`${A} `)).toBe(false);
  });
});

describe('Evidence: the ci kind (additive)', () => {
  it('parses CI evidence with the run link, commit and repository; older evidence still parses', () => {
    const ci = { kind: 'ci', ref: 'https://github.com/acme/pay/actions/runs/1', commitSha: 'a'.repeat(40), repo: 'acme/pay', attester: 'ci:0123456789abcdef' };
    expect(EvidenceSchema.parse(ci)).toEqual(ci);
    expect(EvidenceSchema.parse({ kind: 'pr', ref: 'https://x/pr/1', attester: 'u' }).kind).toBe('pr');
    expect(EvidenceSchema.safeParse({ ...ci, commitSha: 'abc' }).success).toBe(false);
    expect(EvidenceSchema.safeParse({ ...ci, repo: 'x'.repeat(300) }).success).toBe(false);
  });
});

describe('namedIssueKeys: an algorithm name or a full CVE id is never a work item', () => {
  it('SHA-256, CVE-2025-1234, UTF-8 and the like name no key, uppercase or not', () => {
    expect(namedIssueKeys('PAY-7 switch to SHA-256')).toEqual(['PAY-7']);
    expect(namedIssueKeys('Fix CVE-2025-1234 in PAY-7')).toEqual(['PAY-7']);
    expect(namedIssueKeys('UTF-8 bodies, AES-256, SHA3-512, HMAC-256, X-509, RSA-2048, P-256', 'fix/sha-256-cve-2024-12345')).toEqual([]);
    expect(namedIssueKeys('Harden auth', 'feature/PAY-7_SHA-256')).toEqual(['PAY-7']);
  });
  it('real project keys are never excluded: RFC, ISO, CWE, and CVE or SHA with another shape', () => {
    expect(namedIssueKeys('RFC-1234 rotate signing key')).toEqual(['RFC-1234']);
    expect(namedIssueKeys('PAY-6 + RFC-1234')).toEqual(['PAY-6', 'RFC-1234']);
    expect(namedIssueKeys('ISO-27001 evidence', 'CWE-79 fix')).toEqual(['ISO-27001', 'CWE-79']);
    expect(namedIssueKeys('SHA-12 rotate keys')).toEqual(['SHA-12']);
    expect(namedIssueKeys('CVE-7 triage', 'cve-7-fix')).toEqual(['CVE-7']);
    expect(namedIssueKeys('CVE-2025 tracking ticket')).toEqual(['CVE-2025']);
    expect(namedIssueKeys('PAY-256 and SHA-256')).toEqual(['PAY-256']);
  });
  it('keys given explicitly are never excluded', () => {
    expect(explicitIssueKeys('SHA-256')).toEqual(['SHA-256']);
  });
});
