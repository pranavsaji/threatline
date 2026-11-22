import { useState } from 'react';
import Button from '@atlaskit/button/new';
import { errorText, isError, type AdminApi, type GateInstallDto } from '../bridge.js';
import type { ApiError } from '../types.js';
import { useInFlight } from '../components/in-flight.js';

const summary = (r: GateInstallDto): string => {
  const added = r.projects.flatMap((p) => p.added);
  const already = r.projects.flatMap((p) => p.already);
  const readOnly = r.projects.flatMap((p) => p.readOnly);
  const parts = [
    added.length ? `Added the gate to ${added.join('; ')}.` : '',
    already.length ? `Already on ${already.join('; ')}.` : '',
    readOnly.length ? `Jira does not let anyone edit ${readOnly.join('; ')}: copy that workflow first, then add the gate.` : '',
    r.failed?.length ? `Could not change ${r.failed.map((f) => `${f.projectKey} (${f.message})`).join('; ')}. The other projects were changed; try these again.` : '',
  ].filter(Boolean);
  return parts.length ? parts.join(' ') : 'No transition into the guarded status was found in these projects’ workflows.';
};

/**
 * One click instead of the workflow editor: adds "Threatline security gate" to the guarded transition in every enabled
 * project. Needed for team-managed projects, whose workflow editor does not list app validators.
 */
export function AddGate({ api }: { api: AdminApi }) {
  const flight = useInFlight();
  const busy = flight.busy;
  const [message, setMessage] = useState<string | null>(null);
  const run = () =>
    flight.run(async () => {
      const r = await api.installGate().catch((): ApiError => ({ error: 'unavailable' }));
      setMessage(isError(r) ? errorText(r) : summary(r));
    });
  return (
    <span style={{ display: 'inline-flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      <Button appearance="primary" isDisabled={busy} onClick={() => void run()}>
        {busy ? 'Adding the gate…' : 'Add the gate for me'}
      </Button>
      {message && <span role="status">{message}</span>}
    </span>
  );
}
