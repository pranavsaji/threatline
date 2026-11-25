import { describe, expect, it } from 'vitest';
import { matchIncident, type MemoryIncident, type MemoryThreat } from '@threatline/core';
import { DEMO_COMPONENT, INCIDENTS } from '../../src/seeder/content/demo.js';

/**
 * The demo data must show "Seen before" on its own: the two seeded incidents have to match the kind of threats a review
 * of the demo epic and stories raises (wording taken from recorded Engine runs on the same design, evals/results ai-01).
 * The epic has no component, so for it the incidents count as "anywhere on the site" (the stricter rule).
 */
const [leak, spike] = INCIDENTS.map((i, n): MemoryIncident => ({ id: `2000${n}`, key: `PAY-${10 + n}`, summary: i.summary, description: i.description, components: [DEMO_COMPONENT], linked: false }));
const t = (title: string, plainLanguage: string, stride: MemoryThreat['stride']): MemoryThreat => ({ id: 'thr', stride, title, plainLanguage, component: 'agent service', mappings: [] });

const IDOR = t('Agent returns another customer’s order details for any order number', 'Typing someone else’s order number shows their delivery address and card digits.', 'InformationDisclosure');
const DISCLOSE = t('Agent discloses other customers’ emails and shipping addresses', 'The chatbot could be asked for other customers’ email and home addresses and just answer.', 'InformationDisclosure');
const FLOOD = t('No rate limit on the public chat endpoint lets bots flood it with refund requests', 'Anyone can script the open chat to ask for thousands of refunds.', 'DenialOfService');
const HIJACK = t('Customer talks the agent into issuing a refund it should not (goal hijack)', 'A customer could persuade the chatbot to refund money it was never supposed to refund.', 'Tampering');
const SECRET = t('Agent holds broad payment provider credentials rather than a narrow refund permission', 'If the bot holds a full payment key, tricking it could do far more than refund.', 'ElevationOfPrivilege');

describe('demo incidents match the demo’s threats (Seen before has something to show)', () => {
  it('on the epic (no component: the stricter rule), each incident matches the threat it describes', () => {
    expect(matchIncident(IDOR, [], leak!)?.reason).toMatch(/^shared words: /);
    expect(matchIncident(FLOOD, [], spike!)?.reason).toMatch(/^shared words: /);
  });

  it('on the stories (component support-agent), the disclosure threat matches too, and the reason names the component', () => {
    expect(matchIncident(DISCLOSE, [DEMO_COMPONENT], leak!)?.reason).toMatch(/^same component support-agent; shared words: /);
    expect(matchIncident(IDOR, [DEMO_COMPONENT], leak!)?.reason).toMatch(/^same component support-agent/);
  });

  it('and not the wrong way round, nor threats the incidents are not about', () => {
    expect(matchIncident(IDOR, [DEMO_COMPONENT], spike!)).toBeNull();
    expect(matchIncident(FLOOD, [DEMO_COMPONENT], leak!)).toBeNull();
    for (const other of [HIJACK, SECRET])
      for (const components of [[], [DEMO_COMPONENT]]) {
        expect(matchIncident(other, components, leak!)).toBeNull();
        expect(matchIncident(other, components, spike!)).toBeNull();
      }
  });
});
