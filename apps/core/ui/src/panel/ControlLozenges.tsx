import Lozenge from '@atlaskit/lozenge';
import Tooltip from '@atlaskit/tooltip';
import { token } from '@atlaskit/tokens';
import type { PanelDto } from '../types.js';

type ControlRef = NonNullable<PanelDto['requirementControls']>[string][number];

const FRAMEWORK: Record<string, string> = { SOC2: 'SOC 2', ISO27001: 'ISO/IEC 27001:2022', PCIDSS: 'PCI DSS v4.0' };

/** The compliance controls a requirement's ASVS ids map to, as small lozenges; hover for the title. Indicative only. */
export function ControlLozenges({ controls }: { controls: readonly ControlRef[] | undefined }) {
  if (!controls || controls.length === 0) return null;
  return (
    <ul aria-label="Compliance controls (indicative)" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
      {controls.map((c) => {
        const text = `${FRAMEWORK[c.framework] ?? c.framework} ${c.id}: ${c.title} (indicative, not an audit opinion)`;
        return (
          <li key={`${c.framework} ${c.id}`} style={{ margin: 0, font: token('font.body.small') }}>
            <Tooltip content={text} position="top">
              {(props) => (
                <span {...props} role="img" aria-label={text}>
                  <Lozenge>{c.id}</Lozenge>
                </span>
              )}
            </Tooltip>
          </li>
        );
      })}
    </ul>
  );
}
