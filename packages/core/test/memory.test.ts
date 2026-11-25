import { describe, expect, it } from 'vitest';
import type { Mapping, Stride } from '@threatline/shared';
import { cwesOf, matchIncident, matchPastThreat, memoryStem, memoryWords, pullRequestNumber, type MemoryIncident, type MemoryThreat } from '../src/index.js';

const threat = (title: string, plainLanguage: string, o: { stride?: Stride; component?: string; cwe?: string[] } = {}): MemoryThreat => ({
  id: 'thr_x',
  stride: o.stride ?? 'InformationDisclosure',
  title,
  plainLanguage,
  component: o.component ?? 'order lookup',
  mappings: (o.cwe ?? []).map((refId): Mapping => ({ framework: 'CWE', refId })),
});
const incident = (summary: string, description: string, o: Partial<MemoryIncident> = {}): MemoryIncident => ({
  id: '20001', key: 'INC-7', summary, description, components: [], linked: false, ...o,
});

const WEBHOOK_INC = incident(
  'Duplicate refunds after webhook retries',
  'The payment provider retried the refund webhook five times and each retry issued another refund. Webhook events were not deduplicated by event id.',
  { components: ['payments'] },
);
const DUPLICATE_REFUND = threat('Replayed refund webhooks issue duplicate refunds', 'Someone who resends a refund webhook gets the refund paid again.', { stride: 'Tampering', component: 'webhook endpoint' });

describe('Seen before: words', () => {
  it('stems plurals and verb endings the same way on both sides, and drops generic words', () => {
    expect(memoryStem('addresses')).toBe('address');
    expect(memoryStem('refunds')).toBe('refund');
    expect(memoryStem('returned')).toBe(memoryStem('returns').replace(/s$/, ''));
    expect(memoryStem('status')).toBe('status');
    expect([...memoryWords('An attacker could access the data of another user')]).toEqual(['access']);
    expect(memoryWords('Customer’s 1,400 refunds')).toEqual(new Set(['customer', 'refund']));
  });

  it('a CWE beyond the STRIDE default counts as specific; the default one does not', () => {
    expect(cwesOf({ stride: 'InformationDisclosure', mappings: [{ framework: 'CWE', refId: 'CWE-200' }, { framework: 'CWE', refId: 'cwe-639' }, { framework: 'ASVS5', refId: 'V8.2.1' }] })).toEqual({ all: ['CWE-200', 'CWE-639'], specific: ['CWE-639'] });
  });

  it('reads the pull request number from Bitbucket, GitHub and GitLab links', () => {
    expect(pullRequestNumber('https://bitbucket.org/acme/payments/pull-requests/41')).toBe('41');
    expect(pullRequestNumber('https://github.com/acme/payments/pull/7/files')).toBe('7');
    expect(pullRequestNumber('https://gitlab.com/acme/payments/-/merge_requests/12')).toBe('12');
    expect(pullRequestNumber('https://bitbucket.org/acme/payments/commits/abc')).toBeNull();
  });
});

describe('Seen before: incidents', () => {
  it('matches an incident on the same component that describes the same failure, and says why', () => {
    const m = matchIncident(DUPLICATE_REFUND, ['payments'], WEBHOOK_INC);
    expect(m).not.toBeNull();
    expect(m!.reason).toBe('same component payments; shared words: duplicate, refund, webhook');
  });

  it('an incident linked to the work item counts as nearby', () => {
    expect(matchIncident(DUPLICATE_REFUND, [], { ...WEBHOOK_INC, components: [], linked: true })!.reason).toMatch(/^linked to this work item; shared words/);
  });

  it('the same words anywhere else on the site are not enough: an unrelated component needs more in common', () => {
    expect(matchIncident(DUPLICATE_REFUND, ['checkout'], WEBHOOK_INC)).toBeNull();
    const close = incident('Refund webhook replayed: duplicate refunds issued', 'An attacker resent a captured refund webhook and the refund was paid again, twice.', { components: ['billing'] });
    expect(matchIncident(DUPLICATE_REFUND, ['checkout'], close)?.reason).toBe('shared words: duplicate, paid, refund, replay…');
  });

  it('an incident that names one of the threat’s CWEs matches even in other words', () => {
    const t = threat('Order lookup ignores who is asking', 'Typing a different order number shows that order.', { cwe: ['CWE-200', 'CWE-639'] });
    const inc = incident('Postmortem: authorisation bypass', 'Root cause CWE-639 in the invoices API.', { components: ['billing'] });
    expect(matchIncident(t, ['support-agent'], inc)!.reason).toBe('names CWE-639');
  });

  it('noise: the same component and two shared words do not make a match', () => {
    const outage = incident('Refund webhook endpoint down for an hour', 'The load balancer health check failed after a deploy.', { components: ['payments'] });
    const forged = threat('Forged refund webhooks', 'A fake refund event triggers a refund.', { stride: 'Spoofing' });
    expect(matchIncident(forged, ['payments'], outage)).toBeNull();
  });

  it('noise: a refund-spike incident does not match an order-disclosure threat on the same component', () => {
    const spike = incident('Spike of refund requests from one IP through the chat widget', 'Bots flooded the public chat endpoint from one IP address asking for refunds. No per-IP rate limit.', { components: ['support-agent'] });
    const idor = threat('Agent returns another customer’s order details for any order number', 'Typing someone else’s order number shows their delivery address.', {});
    expect(matchIncident(idor, ['support-agent'], spike)).toBeNull();
  });

  it('noise: generic wording alone never matches', () => {
    const vague = threat('An attacker could access data of another user', 'Someone could see information they should not.', {});
    const inc = incident('User data accessed by another user', 'An attacker could access the data of other users in the system.', { components: ['support-agent'] });
    expect(matchIncident(vague, ['support-agent'], inc)).toBeNull();
  });

  it('a threat with no distinctive words matches nothing', () => {
    expect(matchIncident(threat('The data', 'It could.'), ['payments'], WEBHOOK_INC)).toBeNull();
  });
});

describe('Seen before: the same threat on another work item', () => {
  it('same STRIDE category and asset with similar wording', () => {
    const a = threat('Forged refund webhooks', 'A fake refund event posted to the webhook triggers a refund.', { stride: 'Spoofing', component: 'webhook endpoint' });
    const b = threat('Forged refund webhook events', 'Anyone can post a fake refund event to the webhook.', { stride: 'Spoofing', component: 'Webhook endpoint' });
    expect(matchPastThreat(a, b)!.reason).toBe('same STRIDE category (Spoofing); same asset (Webhook endpoint); shared words: event, fake, forg, post…');
  });

  it('a shared specific CWE with similar wording, across STRIDE categories', () => {
    const a = threat('Order lookup returns another customer’s order', 'Typing any order number shows that customer’s address.', { stride: 'InformationDisclosure', cwe: ['CWE-200', 'CWE-639'] });
    const b = threat('Refund tool accepts any order number', 'Any order number can be refunded by any customer.', { stride: 'ElevationOfPrivilege', component: 'refund tool', cwe: ['CWE-269', 'CWE-639'] });
    expect(matchPastThreat(a, b)!.reason).toBe('same CWE-639; shared words: customer, number, order');
  });

  it('noise: only the STRIDE-default CWE in common, with different wording, is no match', () => {
    const a = threat('Customer email exposed in webhook logs', 'Logs keep the email address in plain text.', { cwe: ['CWE-200'], component: 'logging' });
    const b = threat('Agent reveals another customer’s delivery address', 'Typing an order number shows the address.', { cwe: ['CWE-200'], component: 'chat agent' });
    expect(matchPastThreat(a, b)).toBeNull();
  });

  it('noise: the same STRIDE category with a little overlap is no match', () => {
    const a = threat('Forged refund webhooks', 'A fake refund event triggers a refund.', { stride: 'Spoofing', component: 'webhook endpoint' });
    const b = threat('Forged password reset links', 'A fake reset link signs someone in.', { stride: 'Spoofing', component: 'reset api' });
    expect(matchPastThreat(a, b)).toBeNull();
  });

  it('noise: similar words in a different STRIDE category, with no specific CWE in common, are no match', () => {
    const a = threat('Refund webhook flooded with requests', 'Thousands of refund webhook requests stall payouts.', { stride: 'DenialOfService', component: 'webhook endpoint' });
    const b = threat('Refund webhook requests forged', 'A forged refund webhook request pays out.', { stride: 'Spoofing', component: 'webhook endpoint' });
    expect(matchPastThreat(a, b)).toBeNull();
  });
});
