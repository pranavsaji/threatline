import { describe, expect, it } from 'vitest';
import { XMLValidator } from 'fast-xml-parser';
import type { Acceptance, Requirement, Review, Threat } from '@threatline/shared';
import { DEFAULT_OWNER_NOTES, extractOwnerNotes, renderThreatModel, type ThreatModelDto } from '../src/render/threat-model-storage.js';
import { layoutDiagram } from '../src/diagram.js';

const review: Review = {
  id: 'rev_10042_2', issueId: '10042', issueKey: 'PAY-7', revision: 2, status: 'ready', contextHash: 'h', riskScore: 72, partial: false,
  promptVersion: 'v1.1.0', modelIds: [], samplesExpected: 3, samplesReceived: 3, tokensIn: 0, tokensOut: 0, createdAt: '2026-11-16T05:30:00.000Z', updatedAt: '2026-11-16T05:31:00.000Z',
};
const threat = (i: number, over: Partial<Threat> = {}): Threat => ({
  id: `thr_${i}`, reviewId: review.id, stride: 'Spoofing', title: `Forged refund webhooks ${i}`, scenario: 'An attacker posts a fake refund event.', component: 'webhook endpoint',
  likelihood: 4, impact: 4, severity: 'High', votes: 3, samples: 3, grounding: 'supported', confidence: 0.9, state: 'accepted', origin: 'agent',
  citations: [{ factId: 'f1', quote: 'Public webhook that receives refund events' }], mappings: [{ framework: 'ASVS5', refId: 'V2.1.1' }, { framework: 'CWE', refId: 'CWE-345' }],
  plainLanguage: `Someone could fake a refund ${i}.`, ...over,
});
const requirement = (i: number, over: Partial<Requirement> = {}): Requirement => ({
  id: `req_${i}`, threatId: `thr_${i}`, issueId: '10042', issueKey: 'PAY-7', title: `Verify webhook signatures ${i}`,
  criteria: [{ given: 'a webhook', when: 'the signature is wrong', then: 'it is rejected' }], asvsIds: ['V2.1.1'], severity: 'High', status: 'Open', subtaskKey: `PAY-${100 + i}`, ...over,
});
const acceptance: Acceptance = {
  id: 'acc_1', requirementId: 'req_2', issueId: '10042', severity: 'Medium', reason: 'Legacy client', controls: 'IP allow-list', acceptedBy: 'acc-dev', approvedBy: 'acc-champ',
  createdAt: '2026-11-16T00:00:00.000Z', expiresAt: '2027-01-16T00:00:00.000Z', state: 'active',
};

const dto = (over: Partial<ThreatModelDto> = {}): ThreatModelDto => ({
  issueKey: 'PAY-7',
  summary: 'Add AI support agent that can issue refunds',
  review,
  latestRevision: 2,
  verdict: { state: 'block', message: 'Threatline blocks Done: 1 open security requirement at High or above: PAY-101.' },
  threats: [threat(1), threat(2, { severity: 'Medium', state: 'dismissed', dismissReason: 'false_positive' })],
  requirements: [requirement(1), requirement(2, { status: 'AcceptedRisk', severity: 'Medium' })],
  acceptances: [acceptance],
  history: [
    { revision: 1, createdAt: '2026-11-15T05:30:00.000Z', riskScore: 80, status: 'ready' },
    { revision: 2, createdAt: '2026-11-16T05:30:00.000Z', riskScore: 72, status: 'ready' },
  ],
  panelUrl: 'https://example.atlassian.net/browse/PAY-7',
  ownerNotes: DEFAULT_OWNER_NOTES,
  redactedThreatIds: [],
  ...over,
});

const valid = (xml: string) => XMLValidator.validate(`<root>${xml}</root>`);

describe('renderThreatModel (RQ-5)', () => {
  it('is well-formed XHTML with every section', () => {
    const out = renderThreatModel(dto());
    expect(valid(out)).toBe(true);
    for (const h of ['Summary', 'Threats', 'Security requirements', 'Risk acceptances', 'Revision history', 'Owner notes']) expect(out).toContain(`<h2>${h}</h2>`);
    expect(out).toContain('72');
    expect(out).toContain('PAY-101');
    expect(out).toContain('IP allow-list');
    expect(out).toContain('https://example.atlassian.net/browse/PAY-7');
  });

  it('escapes markup from titles, scenarios and summaries (no script reaches the page)', () => {
    const evil = '<script>alert(1)</script> & "x"';
    const out = renderThreatModel(dto({ summary: evil, threats: [threat(1, { title: evil, scenario: evil, plainLanguage: evil })], requirements: [requirement(1, { title: evil })] }));
    expect(out).not.toContain('<script>');
    expect(out).toContain('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;x&quot;');
    expect(valid(out)).toBe(true);
  });

  it('a redacted threat (cites sources this page’s readers may not open) shows only category and severity, and its requirement only its key', () => {
    const out = renderThreatModel(dto({ redactedThreatIds: ['thr_1'] }));
    expect(out).not.toContain('Forged refund webhooks 1');
    expect(out).not.toContain('Verify webhook signatures 1');
    expect(out).not.toContain('Someone could fake a refund 1.');
    expect(out).toContain('Someone could fake a refund 2.');
    expect(out).toContain('PAY-101');
    expect(out).toMatch(/details in the Threatline panel/i);
  });

  it('an acceptance of a redacted threat’s requirement shows no reason or controls (as in the panel)', () => {
    const out = renderThreatModel(dto({ redactedThreatIds: ['thr_2'] }));
    expect(out).not.toContain('Legacy client');
    expect(out).not.toContain('IP allow-list');
    expect(out).toContain('PAY-102');
    expect(valid(out)).toBe(true);
  });

  it('an acceptance whose requirement is not on the page (another revision) shows no reason or controls', () => {
    const out = renderThreatModel(dto({ requirements: [requirement(1)] }));
    expect(out).not.toContain('Legacy client');
    expect(out).not.toContain('IP allow-list');
  });

  it('a page older than the latest revision gets a "stale" info macro', () => {
    expect(renderThreatModel(dto())).not.toContain('ac:name="info"');
    const stale = renderThreatModel(dto({ latestRevision: 3 }));
    expect(stale).toContain('ac:name="info"');
    expect(stale).toMatch(/revision 3/);
  });

  it('includes the architecture sketch when there is one', () => {
    const out = renderThreatModel(
      dto({ sketch: { components: ['refund agent'], dataStores: ['orders db'], externalServices: ['Stripe'], trustBoundaries: ['internet'], flows: [{ from: 'agent', to: 'Stripe', data: 'refund <amount>' }], dataClasses: ['payment'], exposure: 'public', llmFeatures: true, injectionSuspected: false } }),
    );
    expect(out).toContain('<h2>Architecture sketch</h2>');
    expect(out).toContain('refund &lt;amount&gt;');
    expect(valid(out)).toBe(true);
  });
});

describe('renderThreatModel: data-flow diagram as tables (no inline SVG, no attachment)', () => {
  const diagram = layoutDiagram({
    sketch: {
      externalServices: ['Customer <browser>'],
      components: ['Refund API'],
      dataStores: ['Orders DB'],
      trustBoundaries: ['Public internet to Refund API', 'Partner VPN'],
      flows: [
        { from: 'Customer <browser>', to: 'Refund API', data: 'refund "request" & card' },
        { from: 'Refund API', to: 'Orders DB', data: 'order lookup' },
      ],
    },
    threats: [{ id: 'thr_1', title: 'Forged refund webhooks 1', component: 'refund api', severity: 'High', state: 'accepted' }],
  });

  it('lists elements, data flows (crossing a boundary or not) and trust boundaries, escaped and well-formed', () => {
    const out = renderThreatModel(dto({ diagram }));
    expect(valid(out)).toBe(true);
    expect(out).toContain('<h2>Data-flow diagram</h2>');
    expect(out).toContain('<h3>Data flows</h3>');
    expect(out).toContain('<h3>Trust boundaries</h3>');
    expect(out).toContain('Customer &lt;browser&gt;');
    expect(out).toContain('refund &quot;request&quot; &amp; card');
    expect(out).not.toContain('<svg');
    expect(out).not.toContain('<browser>');
    // From, to, data, crosses: the first flow crosses into the boundary, the second leaves it.
    expect(out).toMatch(/<td>1<\/td><td>Customer &lt;browser&gt;<\/td><td>Refund API<\/td><td>refund &quot;request&quot; &amp; card<\/td><td>Yes<\/td>/);
    expect(out).toContain('<td>Partner VPN</td><td>Not tied to an element</td>');
    expect(out).toMatch(/<td>Refund API<\/td><td>Process<\/td><td>Public internet to Refund API<\/td><td>1<\/td><td>High<\/td>/);
    // The section sits before the threats and the owner notes survive it.
    expect(out.indexOf('Data-flow diagram')).toBeLessThan(out.indexOf('<h2>Threats</h2>'));
    expect(extractOwnerNotes(out)).toBe(DEFAULT_OWNER_NOTES);
  });

  it('says when parts of the architecture were left out for this page’s readers, and is skipped when there is nothing to draw', () => {
    expect(renderThreatModel(dto({ diagram, diagramPartial: true }))).toMatch(/not everyone who can read this page can open/);
    expect(renderThreatModel(dto({ diagram: layoutDiagram({ threats: [] }) }))).not.toContain('Data-flow diagram');
    expect(renderThreatModel(dto())).not.toContain('Data-flow diagram');
  });
});

describe('extractOwnerNotes (RQ-6)', () => {
  it('owner notes survive a regenerate', () => {
    const notes = '<p>We use mTLS between the agent and Stripe. <strong>Do not remove.</strong></p><ul><li>Reviewed by AppSec</li></ul>';
    const first = renderThreatModel(dto({ ownerNotes: notes }));
    const kept = extractOwnerNotes(first);
    expect(kept).toBe(notes);
    const second = renderThreatModel(dto({ ownerNotes: kept, latestRevision: 3 }));
    expect(extractOwnerNotes(second)).toBe(notes);
  });

  it('takes everything up to the next <h2> or the end; missing section → default text', () => {
    expect(extractOwnerNotes('<h2>Owner notes</h2><p>a</p><h2>Other</h2><p>b</p>')).toBe('<p>a</p>');
    expect(extractOwnerNotes('<h2>Owner notes</h2>\n<p>a</p>\n')).toBe('<p>a</p>');
    expect(extractOwnerNotes('<p>no section</p>')).toBe(DEFAULT_OWNER_NOTES);
    expect(extractOwnerNotes('<h2>Owner notes</h2>')).toBe(DEFAULT_OWNER_NOTES);
  });

  it('notes that are not well-formed fall back to the default (a broken page body never propagates)', () => {
    expect(extractOwnerNotes('<h2>Owner notes</h2><p>unclosed')).toBe(DEFAULT_OWNER_NOTES);
  });
});
