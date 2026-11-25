import { useId, useState } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';

/**
 * How a Threatline Engine review was made, on request. It used to be a banner on every work item; the method does not
 * change from one work item to the next, so it waits behind a quiet button at the foot of the panel.
 */
export function HowReviewed({ modelIds }: { modelIds: readonly string[] }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <div style={{ display: 'grid', gap: 6 }}>
      <div>
        <Button appearance="subtle" spacing="compact" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
          How this review works
        </Button>
      </div>
      {open && (
        <div id={id} style={{ display: 'grid', gap: 6, padding: 10, borderRadius: 6, background: token('color.background.neutral.subtle'), border: `1px solid ${token('color.border')}` }}>
          <p style={{ margin: 0 }}>
            Threatline Engine ran independent analyses of this work item and its linked pages. A threat stays only when the analyses agree and quote their
            evidence word for word, and a verifier then checks each threat against those quotes. Code, not the model, decides whether Done and merge are blocked.
          </p>
          <p style={{ margin: 0, color: token('color.text.subtle'), font: token('font.body.small') }}>Models: {modelIds.join(', ')}.</p>
        </div>
      )}
    </div>
  );
}
