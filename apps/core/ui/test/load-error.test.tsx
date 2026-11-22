// @vitest-environment jsdom
import './setup-dom.js';
import { describe, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import { LOAD_ERROR, showLoadError } from '../src/load-error.js';
import { createdNotice } from '../src/panel/RequirementsTab.js';

// Start-up fails at its first bridge call: the page must say so instead of staying blank.
vi.mock('../src/theme.js', () => ({ enableTheme: () => Promise.reject(new Error('bridge did not answer')) }));

describe('start-up failure', () => {
  it('main shows the load error when start() rejects', async () => {
    document.body.innerHTML = '<div id="root"></div>';
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await import('../src/main.js');
    await waitFor(() => expect(document.querySelector('[role="alert"]')?.textContent).toBe(LOAD_ERROR));
    expect(LOAD_ERROR).toBe('Threatline could not load. Reload the page; if it keeps happening, check Threatline admin → Recent runs.');
    quiet.mockRestore();
  });

  it('replaces whatever was in the root, and falls back to the body without one', () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    document.body.innerHTML = '<div id="root"><span>half-rendered</span></div>';
    showLoadError(document.getElementById('root'), new Error('x'));
    expect(document.getElementById('root')!.textContent).toBe(LOAD_ERROR);
    document.body.innerHTML = '';
    showLoadError(null, 'x');
    expect(document.body.textContent).toBe(LOAD_ERROR);
    quiet.mockRestore();
  });
});

describe('requirement creation notice', () => {
  it('names the new keys, and says why any could not be created (an epic without Task or Story; a Jira refusal)', () => {
    expect(createdNotice({ created: [{ subtaskKey: 'PAY-1' }], skipped: [] })).toBe('Created PAY-1.');
    expect(createdNotice({ created: [], skipped: [{ reason: 'exists' }] })).toBe('No new sub-tasks were needed.');
    const noType = createdNotice({ created: [], skipped: [{ reason: 'no_child_type' }, { reason: 'no_child_type' }] });
    expect(noType).toMatch(/^Nothing was created\. 2 could not be created: Jira allows no sub-tasks under an epic/);
    expect(noType).not.toMatch(/try again\.$/);
    const failed = createdNotice({ created: [{ subtaskKey: 'PAY-2' }], skipped: [{ reason: 'failed' }] });
    expect(failed).toMatch(/^Created PAY-2\. Jira did not create 1: .*sub-task work type \(on an epic: Task or Story\)/);
  });
});
