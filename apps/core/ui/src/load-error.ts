export const LOAD_ERROR = 'Threatline could not load. Reload the page; if it keeps happening, check Threatline admin → Recent runs.';

/**
 * Shown when start-up fails (the Forge bridge or its context did not answer): plain DOM, not React, so it renders
 * even when what failed was rendering itself. Without it the iframe would stay blank.
 */
export function showLoadError(root: HTMLElement | null, cause?: unknown): void {
  console.error('threatline.ui.start_failed', cause instanceof Error ? cause.message : String(cause));
  const host = root ?? document.body;
  const p = document.createElement('p');
  p.setAttribute('role', 'alert');
  p.style.margin = '8px';
  p.style.font = '14px/20px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
  p.textContent = LOAD_ERROR;
  host.replaceChildren(p);
}
