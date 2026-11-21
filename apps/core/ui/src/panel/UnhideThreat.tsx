import { useState } from 'react';
import Button from '@atlaskit/button/new';
import { errorText, isError, type PanelApi } from '../bridge.js';
import type { ApiError, Threat } from '../types.js';
import { useInFlight } from '../components/in-flight.js';
import { errorText as errorStyle } from './form-styles.js';

/** Champions: show a team rule's hidden threats on this work item again (ledgered; later reviews keep them shown). */
export function UnhideThreat({ threat, api, onDone }: { threat: Threat; api: PanelApi; onDone: () => void }) {
  const { busy, run } = useInFlight();
  const [error, setError] = useState<string | null>(null);
  const ruleId = threat.suppression?.ruleId;
  if (threat.state !== 'suppressed' || !ruleId) return null;
  return (
    <div style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
      <Button
        spacing="compact"
        isDisabled={busy}
        aria-label={`Unhide here: ${threat.title}`}
        onClick={() =>
          void run(async () => {
            const r = await api.unhide(ruleId).catch((): ApiError => ({ error: 'unavailable' }));
            if (isError(r)) return setError(errorText(r));
            setError(null);
            onDone();
          })
        }
      >
        Unhide here
      </Button>
      {error && (
        <p role="alert" style={errorStyle}>
          {error}
        </p>
      )}
    </div>
  );
}
