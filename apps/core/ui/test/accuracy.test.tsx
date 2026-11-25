// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import axe from 'axe-core';
import { PostureDashboard } from '../src/posture/PostureDashboard.js';
import { ACCURACY_DOCS_URL, AccuracyCard } from '../src/posture/AccuracyCard.js';
import { mockPostureApi } from '../src/mock-bridge.js';
import { ACCURACY_EMPTY, ACCURACY_FIXTURE } from '../src/posture/fixtures.js';
import type { Accuracy } from '../src/types.js';

afterEach(cleanup);

const few = (n: number) => ({ n, share: null, low: null, high: null, enough: false });

describe('Accuracy here (posture page)', () => {
  it('shows each figure with its counts, the 95% interval for small samples, and a link to the definitions', async () => {
    render(<PostureDashboard api={mockPostureApi('ready', 'ready')} />);
    const card = await screen.findByRole('region', { name: 'Accuracy here' });
    expect(within(card).getByText(/How often Threatline was right when people decided its calls, over the last 90 days, on work items you can see/)).toBeTruthy();
    expect(within(card).getByRole('link', { name: 'How this is measured' }).getAttribute('href')).toBe(ACCURACY_DOCS_URL);
    const figures = within(card).getByRole('list', { name: 'Accuracy figures' });
    const [champion, blocking, verifier] = within(figures).getAllByRole('listitem');
    expect(champion!.textContent).toContain('Champion agreement82%');
    expect(champion!.textContent).toContain('14 of 17 threats sent to a champion were confirmed as real; 3 dismissed as not real.');
    expect(champion!.textContent).toContain('95% interval 59%–94%');
    expect(blocking!.textContent).toContain('Blocking calls that held up91%');
    expect(blocking!.textContent).toContain('31 of 34 closed blocking requirements: 24 fixed, 7 risk accepted, 3 dismissed as wrong.');
    expect(blocking!.textContent).toContain('Fixed in a median of 2 days.');
    // 136 decisions: the interval is narrow, so it is left out.
    expect(verifier!.textContent).toBe('Verifier keep rate87%118 of 136 AI threats kept by the verifier.');
  });

  it('breaks the figures down per project, and says when a project has too few decisions for a percentage', async () => {
    render(<PostureDashboard api={mockPostureApi('ready', 'ready')} />);
    const table = await screen.findByRole('table', { name: 'Accuracy by project' });
    const ops = within(table).getByRole('row', { name: /OPS/ });
    expect(within(ops).getAllByRole('cell').map((c) => c.textContent)).toEqual(['3 so far', '4 so far', '82% (14 of 17)']);
    const pay = within(table).getByRole('row', { name: /PAY/ });
    expect(within(pay).getAllByRole('cell').map((c) => c.textContent)).toEqual(['86% (12 of 14)', '93% (28 of 30)', '87% (104 of 119)']);
  });

  it('below 5 decisions: says there are not enough decisions yet instead of a percentage', () => {
    const a: Accuracy = { ...ACCURACY_EMPTY, champion: { confirmed: 2, dismissed: 0, notCounted: 0, rate: few(2) } };
    render(<AccuracyCard accuracy={a} />);
    const [champion] = within(screen.getByRole('list', { name: 'Accuracy figures' })).getAllByRole('listitem');
    expect(champion!.textContent).toContain('Not enough decisions yet (n < 5)');
    expect(champion!.textContent).toContain('2 of 2 threats sent to a champion');
    expect(champion!.textContent).not.toContain('100%');
    expect(screen.queryByRole('table', { name: 'Accuracy by project' })).toBeNull();
  });

  it('empty state: no decisions yet in the window', async () => {
    render(<PostureDashboard api={mockPostureApi('ready', 'empty')} />);
    const card = await screen.findByRole('region', { name: 'Accuracy here' });
    expect(within(card).getByText(/No decisions yet\. Once security champions confirm or dismiss the threats sent to them/)).toBeTruthy();
    expect(within(card).queryByRole('list', { name: 'Accuracy figures' })).toBeNull();
    expect(within(card).getByRole('link', { name: 'How this is measured' })).toBeTruthy();
  });

  it('unavailable: says so, and the rest of the page still shows', async () => {
    render(<PostureDashboard api={mockPostureApi('ready', 'unavailable')} />);
    const card = await screen.findByRole('region', { name: 'Accuracy here' });
    expect(within(card).getByText(/Accuracy figures are not available right now/)).toBeTruthy();
    expect(screen.getByRole('list', { name: 'Key numbers' })).toBeTruthy();
  });

  it('the gadget shows one line', async () => {
    render(<PostureDashboard api={mockPostureApi('ready', 'ready')} compact />);
    const line = await screen.findByLabelText('Accuracy here');
    expect(line.textContent).toBe('Accuracy here (90 days): champions agreed 82% (14 of 17) · blocking calls held up 91% (31 of 34).');
    expect(screen.queryByRole('region', { name: 'Accuracy here' })).toBeNull();
  });

  it('the gadget line with too few or no decisions, or no figures', () => {
    const { rerender } = render(<AccuracyCard compact accuracy={{ ...ACCURACY_FIXTURE, blocking: { ...ACCURACY_FIXTURE.blocking, rate: few(3) } }} />);
    expect(screen.getByLabelText('Accuracy here').textContent).toBe('Accuracy here (90 days): champions agreed 82% (14 of 17) · blocking calls held up: not enough decisions yet.');
    rerender(<AccuracyCard compact accuracy={ACCURACY_EMPTY} />);
    expect(screen.getByLabelText('Accuracy here').textContent).toBe('Accuracy here (90 days): no decisions yet.');
    rerender(<AccuracyCard compact accuracy={null} />);
    expect(screen.getByLabelText('Accuracy here').textContent).toBe('Accuracy here: not available right now.');
  });

  it.each(['light', 'dark'])('has no axe violations (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = render(<AccuracyCard accuracy={ACCURACY_FIXTURE} />);
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});
