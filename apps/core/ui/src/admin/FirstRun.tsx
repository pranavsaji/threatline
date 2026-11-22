import { useId, useState } from 'react';
import Button from '@atlaskit/button/new';
import SectionMessage from '@atlaskit/section-message';
import { errorText, isError, type AdminApi } from '../bridge.js';
import type { ApiError, SitePolicy } from '../types.js';
import { box, errorText as errorStyle, field } from '../panel/form-styles.js';
import { hint, h2, Labeled, sectionStyle } from './policy-editor.js';
import { AddGate } from './AddGate.js';
import { useInFlight } from '../components/in-flight.js';

const PROJECT_KEY = /^[A-Z][A-Z0-9_]{0,254}$/;

/**
 * Shown until an administrator saves a policy: turn Threatline on for a project, pick the transition its gate guards,
 * name the groups. The later steps (demo data, public key, checklist) are the sections below.
 */
export function FirstRun({ api, policy, onSaved }: { api: AdminApi; policy: SitePolicy; onSaved: (p: SitePolicy) => void }) {
  const id = useId();
  const [project, setProject] = useState(policy.enabledProjects[0] ?? '');
  const [statuses, setStatuses] = useState<string[]>(policy.guardedTransitions);
  const [transition, setTransition] = useState(policy.guardedTransitions[0] ?? 'Done');
  const [champions, setChampions] = useState(policy.championGroup);
  const [leads, setLeads] = useState(policy.techLeadGroup);
  const { busy, run } = useInFlight();
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ project: string; transition: string } | null>(null);
  const key = project.trim().toUpperCase();

  const loadStatuses = async () => {
    if (!PROJECT_KEY.test(key)) return setError('Give a Jira project key (like PAY).');
    const r = await api.projectStatuses(key).catch((): ApiError => ({ error: 'unavailable' }));
    if (isError(r)) return setError(errorText(r));
    setError(null);
    setStatuses(r.statuses.length ? r.statuses : ['Done']);
    setTransition(r.statuses.includes(transition) ? transition : (r.statuses.find((s) => /^done$/i.test(s)) ?? r.statuses.at(-1) ?? 'Done'));
  };

  const save = async () => {
    if (!PROJECT_KEY.test(key)) return setError('Give a Jira project key (like PAY).');
    if (!champions.trim() || !leads.trim()) return setError('Name both groups.');
    await run(async () => {
      const enabledProjects = [...new Set([...policy.enabledProjects, key])];
      const r = await api.setPolicy({ ...policy, enabledProjects, guardedTransitions: [transition], championGroup: champions.trim(), techLeadGroup: leads.trim() }).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setError(errorText(r));
      setError(null);
      setDone({ project: key, transition });
      onSaved(r.policy);
    });
  };

  return (
    <section aria-labelledby={`${id}-h`} style={sectionStyle}>
      <h2 id={`${id}-h`} style={h2}>
        Set up Threatline
      </h2>
      {done ? (
        <SectionMessage appearance="success" title="Threatline is set up">
          <div style={{ display: 'grid', gap: 8 }}>
            <p style={{ margin: 0 }}>{`Threatline is on for ${done.project}. Next, add "Threatline security gate" to the ${done.transition} transition of ${done.project}'s workflow (or add it yourself in the workflow editor, under Marketplace rules). Then load demo data, copy the public key for Bitbucket, and check the setup checklist below.`}</p>
            <div>
              <AddGate api={api} />
            </div>
          </div>
        </SectionMessage>
      ) : (
        <form
          aria-label="First-run setup"
          noValidate
          style={box}
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <ol style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 12 }}>
            <li style={{ margin: 0 }}>
              <div style={{ display: 'grid', gap: 6 }}>
              <strong>Turn Threatline on for a project</strong>
              <Labeled text="Jira project key">{(fid) => <input id={fid} value={project} onChange={(e) => setProject(e.target.value)} placeholder="PAY" style={field} />}</Labeled>
              </div>
            </li>
            <li style={{ margin: 0 }}>
              <div style={{ display: 'grid', gap: 6 }}>
              <strong>Pick the transition Threatline guards</strong>
              <div style={{ display: 'flex', gap: 8, alignItems: 'end', flexWrap: 'wrap' }}>
                <Labeled text="Guarded transition">
                  {(fid) => (
                    <select id={fid} value={transition} onChange={(e) => setTransition(e.target.value)} style={field}>
                      {statuses.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  )}
                </Labeled>
                <Button onClick={() => void loadStatuses()}>Load statuses</Button>
              </div>
              <p style={hint}>Load the project’s statuses, then pick the one work moves into when it ships (usually Done).</p>
              </div>
            </li>
            <li style={{ margin: 0 }}>
              <div style={{ display: 'grid', gap: 6 }}>
              <strong>Name the groups</strong>
              <Labeled text="Security champions group">{(fid) => <input id={fid} value={champions} onChange={(e) => setChampions(e.target.value)} style={field} />}</Labeled>
              <Labeled text="Tech leads group">{(fid) => <input id={fid} value={leads} onChange={(e) => setLeads(e.target.value)} style={field} />}</Labeled>
              <p style={hint}>
                Threatline does not create these groups. Create them (or name existing ones) in Atlassian Administration → Directory → Groups, and add yourself to the champions group: only its members confirm flagged threats. High and Critical risk acceptances need a second person to approve them. The setup checklist below checks the champions group.
              </p>
              </div>
            </li>
            <li style={{ margin: 0 }}>Load demo data, copy the public key and check the setup checklist (below).</li>
          </ol>
          {error && (
            <p role="alert" style={errorStyle}>
              {error}
            </p>
          )}
          <div>
            <Button type="submit" appearance="primary" isDisabled={busy}>
              Save and continue
            </Button>
          </div>
        </form>
      )}
    </section>
  );
}
