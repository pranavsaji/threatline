import { useLayoutEffect } from 'react';

/**
 * Lets the context-column frame shrink to the status label. A Custom UI frame is sized to its document, and
 * @atlaskit/css-reset sets `html, body { height: 100% }`, so the document is never shorter than the frame itself: the
 * frame keeps whatever height Jira first gave it and shows blank space under the label. While the status view is
 * mounted, html and body take their content's height instead. The panel and admin pages keep the reset's full height.
 */
export function useFitFrameToContent(): void {
  useLayoutEffect(() => {
    const els = [document.documentElement, document.body];
    const before = els.map((el) => [el.style.height, el.style.minHeight] as const);
    for (const el of els) {
      el.style.height = 'auto';
      el.style.minHeight = '0';
    }
    return () =>
      els.forEach((el, i) => {
        el.style.height = before[i]![0];
        el.style.minHeight = before[i]![1];
      });
  }, []);
}
