import { describe, expect, it } from 'vitest';
import type { Threat } from '@threatline/shared';
import { firstLookThreats } from '../src/first-look.js';

const t = (id: string, over: Partial<Threat>): Threat => ({
  id, reviewId: 'rev', stride: 'Spoofing', title: id, scenario: 's', component: 'c', likelihood: 3, impact: 3, severity: 'Medium', votes: 3, samples: 3,
  grounding: 'supported', confidence: 1, state: 'accepted', origin: 'baseline', citations: [{ factId: 'f', quote: 'q' }], mappings: [], plainLanguage: 'p', ...over,
});

describe('firstLookThreats: the rule-based floor shown while the AI review runs', () => {
  it('keeps only live rule-based threats, most severe first (then by title)', () => {
    const out = firstLookThreats([
      t('b-medium', {}),
      t('a-high', { severity: 'High' }),
      t('ai', { origin: 'agent', severity: 'Critical' }),
      t('hidden', { state: 'suppressed', severity: 'Critical' }),
      t('dismissed', { state: 'dismissed', severity: 'Critical' }),
      t('covered', { state: 'covered', severity: 'Critical' }),
      t('champion', { state: 'needs_human', severity: 'Low' }),
      t('a-medium', {}),
    ]);
    expect(out.map((x) => x.id)).toEqual(['a-high', 'a-medium', 'b-medium', 'champion']);
  });

  it('nothing found is an empty first look, not an error', () => {
    expect(firstLookThreats([])).toEqual([]);
  });
});
