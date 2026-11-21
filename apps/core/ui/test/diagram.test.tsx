// @vitest-environment jsdom
import './setup-dom.js';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { DiagramTab } from '../src/panel/DiagramTab.js';
import { FIXTURES } from '../src/fixtures.js';
import { DIAGRAM_FIXTURE } from '../src/diagram-fixture.js';
import { mockApi } from '../src/mock-bridge.js';
import type { PanelApi } from '../src/bridge.js';
import type { DiagramDto, PanelDto } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

const withDto = (patch: (d: PanelDto) => void): PanelApi => ({
  ...mockApi('ready'),
  get: async () => {
    const d = structuredClone(FIXTURES.ready!);
    patch(d);
    return d;
  },
});
const openDiagram = async (api: PanelApi = mockApi('ready')) => {
  const r = render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  await userEvent.click(screen.getByRole('tab', { name: 'Diagram' }));
  return r;
};
const violations = async (container: HTMLElement) => {
  const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
};
const threatList = () => within(screen.getByRole('region', { name: 'Threats on the diagram' }));
const node = (name: string) => screen.getByRole('button', { name: new RegExp(`^${name.replace(/[()]/g, '\\$&')},`) });

describe('Diagram tab', () => {
  it('draws the data-flow diagram as one image with a spoken summary and DFD shapes', async () => {
    const { container } = await openDiagram();
    const img = screen.getByRole('img', { name: DIAGRAM_FIXTURE.summary });
    expect(img.tagName.toLowerCase()).toBe('svg');
    expect(DIAGRAM_FIXTURE.summary).toMatch(/^Data-flow diagram: 3 external entities, 4 processes, 3 data stores, 10 data flows/);
    // Rounded external entities, rectangle processes, open-ended stores, dashed trust boundaries.
    expect(container.querySelector('[data-kind="external"] rect')!.getAttribute('rx')).toBe('16');
    expect(container.querySelector('[data-kind="process"] rect')!.getAttribute('rx')).toBe('2');
    expect(container.querySelector('[data-kind="store"] path')!.getAttribute('d')).toMatch(/^M[\d.]+ [\d.]+ H[\d.]+ V[\d.]+ H[\d.]+$/);
    expect(container.querySelector('[data-boundary] rect')!.getAttribute('stroke-dasharray')).toBe('6 4');
    expect(container.querySelectorAll('[data-edge]')).toHaveLength(DIAGRAM_FIXTURE.edges.length);
    // A truncated name keeps its full name in the element's <title>.
    const provider = DIAGRAM_FIXTURE.nodes.find((n) => n.name === 'Email provider (SendGrid)')!;
    expect(provider.label).not.toBe(provider.name);
    expect(container.querySelector(`[data-node="${provider.id}"] title`)!.textContent).toContain('Email provider (SendGrid)');
  });

  it('captions sit on an opaque surface-coloured halo drawn above every line, and the canvas is never cut short', async () => {
    await openDiagram();
    const svg = screen.getByRole('img', { name: DIAGRAM_FIXTURE.summary });
    const captions = [...svg.querySelectorAll('[data-caption]')];
    expect(captions).toHaveLength(DIAGRAM_FIXTURE.edges.length);
    const lastEdge = [...svg.querySelectorAll('[data-edge]')].pop()!;
    for (const c of captions) {
      // Halo first, then text; and after every edge in document order (painted on top).
      expect(c.firstElementChild!.tagName.toLowerCase()).toBe('rect');
      expect(c.firstElementChild!.getAttribute('fill')).toMatch(/--ds-surface\)/);
      expect(c.lastElementChild!.tagName.toLowerCase()).toBe('text');
      expect(lastEdge.compareDocumentPosition(c) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
    expect(svg.getAttribute('height')).toBe(String(DIAGRAM_FIXTURE.height));
    const scroller = svg.parentElement!.parentElement as HTMLElement;
    expect(scroller.style.maxHeight).toBe('');
    // The fixture's model keeps every boundary inside the canvas, with room below the last one.
    for (const b of DIAGRAM_FIXTURE.boundaries) expect(b.y + b.h).toBeLessThanOrEqual(DIAGRAM_FIXTURE.height - 8);
  });

  it('colour is never the only signal: each element says its open threats and highest severity', async () => {
    await openDiagram();
    expect(node('Account settings').getAttribute('aria-label')).toMatch(/1 open threat · Critical$/);
    expect(node('Customer browser').getAttribute('aria-label')).toMatch(/No threats$/);
  });

  it('a click on an element filters the threat list to it; "Show all threats" clears it', async () => {
    await openDiagram();
    expect(threatList().getByText(/^4 threats on the diagram$/)).toBeTruthy();
    await userEvent.click(node('Reset API'));
    expect(threatList().getByText('2 threats on Reset API')).toBeTruthy();
    const list = threatList().getByRole('list', { name: 'Threats on Reset API' });
    expect(within(list).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      expect.stringContaining('Reset page reveals which emails have accounts'),
      expect.stringContaining('Reset endpoint can be flooded'),
    ]);
    expect(node('Reset API').getAttribute('aria-pressed')).toBe('true');
    await userEvent.click(screen.getByRole('button', { name: 'Show all threats' }));
    expect(threatList().getByText(/^4 threats on the diagram$/)).toBeTruthy();
  });

  it('keyboard: Tab focus on an element filters the list; Escape shows every threat again', async () => {
    await openDiagram();
    node('Customer browser').focus();
    await userEvent.tab();
    expect(document.activeElement).toBe(node('Email provider (SendGrid)'));
    expect(threatList().getByText('0 threats on Email provider (SendGrid)')).toBeTruthy();
    expect(threatList().getByText('No threats name this element.')).toBeTruthy();
    // The focused element gets a visible focus ring in the drawing.
    expect(document.querySelector('[data-node="n2"] rect[stroke-width="2"][x="36"]')).toBeTruthy();
    await userEvent.keyboard('{Escape}');
    expect(threatList().getByText(/^4 threats on the diagram$/)).toBeTruthy();
  });

  it('offers the diagram as tables: elements, flows, boundaries and threats', async () => {
    await openDiagram();
    await userEvent.click(screen.getByRole('button', { name: /Show the diagram as tables/ }));
    const flows = screen.getByRole('table', { name: 'Data flows' });
    expect(within(flows).getAllByRole('row')).toHaveLength(DIAGRAM_FIXTURE.edges.length + 1);
    expect(within(flows).getAllByRole('row')[1]!.textContent).toBe('1Customer browserReset APIemail addressYes');
    const elements = screen.getByRole('table', { name: 'Elements' });
    expect(within(elements).getByText('Email provider (SendGrid)')).toBeTruthy();
    expect(screen.getByRole('table', { name: 'Trust boundaries' }).textContent).toContain('Not tied to an element');
    expect(screen.getByRole('table', { name: 'Threats by element' }).textContent).toContain('Account takeover by changing the email after sign-in');
  });

  it('escapes every text from the model (no markup is injected) and never uses dangerouslySetInnerHTML', () => {
    const evil = '<img src=x onerror="alert(1)">';
    const d: DiagramDto = structuredClone(DIAGRAM_FIXTURE);
    d.nodes[0]!.name = evil;
    d.nodes[0]!.label = evil;
    d.edges[0]!.label = evil;
    d.threats[0]!.title = evil;
    const { container } = render(<DiagramTab diagram={d} />);
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain(evil);
    const source = readFileSync('apps/core/ui/src/panel/DiagramTab.tsx', 'utf8');
    expect(source).not.toMatch(/dangerouslySetInnerHTML|innerHTML/);
  });

  it('viewer scope: says when the architecture was left out, and handles an empty diagram', () => {
    render(<DiagramTab diagram={{ ...structuredClone(DIAGRAM_FIXTURE), sketchHidden: true }} />);
    expect(screen.getByText(/Parts of the architecture come from sources you cannot open/)).toBeTruthy();
    cleanup();
    render(<DiagramTab diagram={undefined} />);
    expect(screen.getByText(/No architecture to draw yet/)).toBeTruthy();
    cleanup();
    render(<DiagramTab diagram={{ ...structuredClone(DIAGRAM_FIXTURE), nodes: [], edges: [], boundaries: [], threats: [], sketchHidden: true }} />);
    expect(screen.getByText(/comes from sources you cannot open, so there is nothing to draw/)).toBeTruthy();
  });

  it('a panel without a diagram (older backend) still opens the tab', async () => {
    await openDiagram(withDto((d) => delete d.diagram));
    expect(screen.getByText(/No architecture to draw yet/)).toBeTruthy();
  });

  it.each(['light', 'dark'])('has no axe violations, with an element selected and the tables open (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = await openDiagram();
    expect(await violations(container)).toEqual([]);
    await userEvent.click(node('Reset API'));
    await userEvent.click(screen.getByRole('button', { name: /Show the diagram as tables/ }));
    expect(await violations(container)).toEqual([]);
    for (const el of container.querySelectorAll<HTMLElement>('button, [role=tab]')) expect((el.getAttribute('aria-label') || el.textContent || '').trim()).not.toBe('');
  });
});
