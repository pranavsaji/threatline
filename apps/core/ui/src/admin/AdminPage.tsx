import { useEffect, useState, type ReactNode } from 'react';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type AdminApi } from '../bridge.js';
import type { AdminPolicyDto, ApiError, SitePolicy } from '../types.js';
import { DemoData } from './DemoData.js';
import { LedgerVerify } from './LedgerVerify.js';
import { Keys } from './Keys.js';
import { CiVerification } from './CiVerification.js';
import { SetupChecklist } from './SetupChecklist.js';
import { FirstRun } from './FirstRun.js';
import { Projects } from './Projects.js';
import { SeverityPolicy } from './SeverityPolicy.js';
import { Roles } from './Roles.js';
import { Budgets } from './Budgets.js';
import { Incidents } from './Incidents.js';
import { ReviewMode } from './ReviewMode.js';
import { WarnOnly } from './WarnOnly.js';
import { Notifications } from './Notifications.js';
import { Runs } from './Runs.js';
import { DataRetention } from './DataRetention.js';
import { Suppressions } from './Suppressions.js';
import { LicenseBanner } from '../components/LicenseBanner.js';

/** Section order on the page; `group` sorts the index into what an admin looks for: setting up, the rules, the records. */
const SECTIONS = [
  { id: 'setup', title: 'Setup checklist', needsPolicy: false, group: 'start' },
  { id: 'projects', title: 'Projects and transitions', needsPolicy: true, group: 'start' },
  { id: 'severity', title: 'Severity policy', needsPolicy: true, group: 'rules' },
  { id: 'roles', title: 'Roles', needsPolicy: true, group: 'rules' },
  { id: 'review-mode', title: 'Review mode', needsPolicy: true, group: 'rules' },
  { id: 'budgets', title: 'Budgets', needsPolicy: true, group: 'rules' },
  { id: 'incidents', title: 'Incidents', needsPolicy: true, group: 'rules' },
  { id: 'warn-only', title: 'Warn-only mode', needsPolicy: true, group: 'rules' },
  { id: 'notifications', title: 'Notifications', needsPolicy: true, group: 'rules' },
  { id: 'suppressions', title: 'Suppressions', needsPolicy: false, group: 'rules' },
  { id: 'runs', title: 'Recent runs', needsPolicy: false, group: 'records' },
  { id: 'keys', title: 'Signing keys', needsPolicy: false, group: 'records' },
  { id: 'ci', title: 'CI verification', needsPolicy: false, group: 'records' },
  { id: 'ledger', title: 'Risk ledger', needsPolicy: false, group: 'records' },
  { id: 'retention', title: 'Data retention', needsPolicy: false, group: 'records' },
  { id: 'demo', title: 'Demo data', needsPolicy: false, group: 'start' },
] as const;
const GROUPS = [
  { id: 'start', label: 'Get started' },
  { id: 'rules', label: 'Rules' },
  { id: 'records', label: 'Records and keys' },
] as const;
const anchor = (id: string) => `threatline-admin-${id}`;

/** Threatline's Jira admin page: first-run wizard, policy sections, observability, keys, ledger and demo data. */
export function AdminPage({ api }: { api: AdminApi }) {
  const [dto, setDto] = useState<AdminPolicyDto | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  /** The wizard stays up after it saves, so its next steps remain on screen. */
  const [wizard, setWizard] = useState(false);

  useEffect(() => {
    void api
      .getPolicy()
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => {
        if (isError(r)) return setPolicyError(errorText(r));
        setDto(r);
        setWizard(!r.saved);
      });
  }, [api]);

  const onSaved = (policy: SitePolicy) => setDto((d) => (d ? { ...d, policy, saved: true } : d));
  const p = dto ? { api, policy: dto.policy, onSaved } : null;
  const shown = SECTIONS.filter((s) => !s.needsPolicy || p);
  const at = (id: (typeof SECTIONS)[number]['id'], node: ReactNode) => (
    <div id={anchor(id)} style={{ scrollMarginTop: 16 }}>
      {node}
    </div>
  );

  return (
    <main style={{ display: 'grid', gap: 28, padding: 16, maxWidth: 880, minWidth: 0, color: token('color.text') }}>
      <nav aria-label="Admin sections" style={{ display: 'grid', gap: 4, font: token('font.body.small') }}>
        {GROUPS.map((g) => {
          const links = shown.filter((s) => s.group === g.id);
          if (links.length === 0) return null;
          return (
            <div key={g.id} style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 16px', alignItems: 'baseline' }}>
              <span id={`threatline-admin-nav-${g.id}`} style={{ color: token('color.text.subtle'), fontWeight: 600, minWidth: 120 }}>
                {g.label}
              </span>
              <ul aria-labelledby={`threatline-admin-nav-${g.id}`} style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: '4px 16px' }}>
                {links.map((s) => (
                  <li key={s.id} style={{ margin: 0 }}>
                    <a href={`#${anchor(s.id)}`} style={{ color: token('color.link') }}>
                      {s.title}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </nav>
      {dto?.licenseInactive && <LicenseBanner />}
      {dto && wizard && <FirstRun api={api} policy={dto.policy} onSaved={onSaved} />}
      {at('setup', <SetupChecklist api={api} reviewAuthors={dto?.policy.reviewAuthors?.length ?? 0} {...(dto?.policy.reviewMode ? { reviewMode: dto.policy.reviewMode } : {})} />)}
      {policyError && (
        <p role="alert" style={{ margin: 0 }}>
          {policyError}
        </p>
      )}
      {p && (
        <>
          {at('projects', <Projects key={`p-${dto!.saved}`} {...p} />)}
          {at('severity', <SeverityPolicy {...p} />)}
          {at('roles', <Roles key={`r-${dto!.saved}`} {...p} />)}
          {at('review-mode', <ReviewMode {...p} recentAuthors={dto?.recentReviewAuthors ?? []} />)}
          {at('budgets', <Budgets {...p} />)}
          {at('incidents', <Incidents key={`i-${dto!.saved}`} {...p} />)}
          {at('warn-only', <WarnOnly api={api} policy={p.policy} onChanged={onSaved} />)}
          {at('notifications', <Notifications api={api} ops={dto!.ops} digest={dto!.digest} />)}
        </>
      )}
      {at('suppressions', <Suppressions api={api} />)}
      {at('runs', <Runs api={api} />)}
      {at('keys', <Keys api={api} />)}
      {at('ci', <CiVerification api={api.ci} />)}
      {at('ledger', <LedgerVerify api={api} />)}
      {at('retention', <DataRetention api={api} />)}
      {at('demo', <DemoData api={api} />)}
    </main>
  );
}
