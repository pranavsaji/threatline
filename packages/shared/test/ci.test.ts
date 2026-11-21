import { describe, expect, it } from 'vitest';
import { EvidenceSchema, isRequirementId, requirementIdsIn } from '../src/index.js';

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
