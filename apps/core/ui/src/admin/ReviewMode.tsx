import { useId } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';
import type { AdminPolicyDto } from '../types.js';
import { field, label as labelStyle } from '../panel/form-styles.js';
import {
  h2,
  hint,
  PolicyForm,
  sectionStyle,
  splitList,
  usePolicySave,
  useSynced,
  type PolicySectionProps,
} from './policy-editor.js';

type Mode = 'engine' | 'agent' | 'rules_only';
/** Per-review token caps Threatline Engine needs (one extract, three deep proposals with repairs, one verification). */
const ENGINE_BUDGET = { tokensInPerReview: 400_000, tokensOutPerReview: 60_000 };

/**
 * Review mode. Threatline Engine (Threatline runs the review itself on Forge LLMs) is recommended; AI review via the Rovo
 * agent needs Automation rules. Rule-based checks only is an
 * explicit choice for sites that want no AI model calls: every review completes at once from Threatline's deterministic checks, the
 * panel labels it, and the change is recorded in the risk ledger like any policy change.
 */
export function ReviewMode(props: PolicySectionProps & { recentAuthors?: AdminPolicyDto['recentReviewAuthors'] }) {
  const id = useId();
  const [mode, setMode] = useSynced<Mode>(props.policy.reviewMode ?? 'agent');
  const s = usePolicySave(props);
  return (
    <section aria-labelledby={`${id}-h`} style={sectionStyle}>
      <h2 id={`${id}-h`} style={h2}>
        Review mode
      </h2>
      <PolicyForm
        label="Review mode"
        submitLabel="Save review mode"
        onSubmit={() => {
          const b = props.policy.budget;
          // Threatline Engine's deep-model calls need room: lift per-review token caps below its defaults (the admin can lower them under Budgets).
          const budget =
            mode === 'engine'
              ? { ...b, tokensInPerReview: Math.max(b.tokensInPerReview, ENGINE_BUDGET.tokensInPerReview), tokensOutPerReview: Math.max(b.tokensOutPerReview, ENGINE_BUDGET.tokensOutPerReview) }
              : b;
          void s.save({ reviewMode: mode, budget });
        }}
        {...s}
      >
        <fieldset
          aria-label="How Threatline reviews work items"
          style={{ border: 0, padding: 0, margin: 0, display: 'grid', gap: 6 }}
        >
          <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
            <input type="radio" name={`${id}-mode`} checked={mode === 'engine'} onChange={() => setMode('engine')} />
            <span>
              <strong>Threatline Engine (recommended).</strong> Threatline runs every review itself on Atlassian-hosted Claude
              models: three independent analyses on the strongest model, which must agree and quote their evidence, and an
              adversarial verifier that checks each threat against its quotes. No Rovo agent or Automation rule needed, and no
              developer can write their own review.
            </span>
          </label>
          <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
            <input type="radio" name={`${id}-mode`} checked={mode === 'agent'} onChange={() => setMode('agent')} />
            <span>
              <strong>Rovo agent review.</strong> The Threatline Rovo agent proposes threats from the work item and its
              pages; Threatline keeps what a majority of runs raised and can be quoted. Needs Rovo and the Automation rules
              in the judge guide.
            </span>
          </label>
          <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
            <input
              type="radio"
              name={`${id}-mode`}
              checked={mode === 'rules_only'}
              onChange={() => setMode('rules_only')}
            />
            <span>
              <strong>Rule-based checks only.</strong> For sites that want no AI model calls at all. Every review completes at once from
              Threatline's built-in checks (authentication, personal data, payments, public endpoints, AI agents, file
              upload, secrets). No Rovo credits or model calls are used; the gates work the same.
            </span>
          </label>
        </fieldset>
        <span style={hint}>The change is recorded in the risk ledger. It applies to reviews started from now on.</span>
      </PolicyForm>
      <ReviewComments {...props} />
      <ReviewAuthors {...props} recent={props.recentAuthors ?? []} />
    </section>
  );
}

/** Whether Threatline comments the verdict on the work item when a review finishes (site policy `postReviewComments`). */
function ReviewComments(props: PolicySectionProps) {
  const [on, setOn] = useSynced(props.policy.postReviewComments !== false);
  const s = usePolicySave(props);
  return (
    <PolicyForm label="Review comments" submitLabel="Save review comments" onSubmit={() => void s.save({ postReviewComments: on })} {...s}>
      <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        <input type="checkbox" checked={on} onChange={(e) => setOn(e.target.checked)} />
        Comment on the work item when its review finishes
      </label>
      <span style={hint}>
        One comment per review: the verdict, threat counts, the top risk (only when everyone who can see the work item can open its source) and the requirements. A re-run comments only when the verdict changes.
      </span>
    </PolicyForm>
  );
}

/**
 * Who may submit AI review runs. Locking it to the Automation rule owner means a developer cannot fill their own work
 * item's review through Rovo chat; refused attempts are recorded in the risk ledger.
 */
function ReviewAuthors(props: PolicySectionProps & { recent: AdminPolicyDto['recentReviewAuthors'] }) {
  const id = useId();
  // Strings and booleans, so a policy saved elsewhere (a new object with the same list) does not reset an edit.
  const initial = (props.policy.reviewAuthors ?? []).join('\n');
  const [locked, setLocked] = useSynced(initial.length > 0);
  const [ids, setIds] = useSynced(initial);
  const s = usePolicySave(props);
  const submit = () => {
    const list = locked ? splitList(ids) : [];
    if (locked && list.length === 0)
      return s.fail('Add at least one account ID, or choose anyone who can edit the work item.');
    void s.save({ reviewAuthors: list });
  };
  return (
    <PolicyForm label="Review authors" submitLabel="Save review authors" onSubmit={submit} {...s}>
      <strong>Who can submit AI review runs</strong>
      <fieldset
        aria-label="Who can submit AI review runs"
        style={{ border: 0, padding: 0, margin: 0, display: 'grid', gap: 6 }}
      >
        <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
          <input type="radio" name={`${id}-who`} checked={!locked} onChange={() => setLocked(false)} />
          <span>
            Anyone who can edit the work item. A developer could then write their own work item's review in Rovo chat.
          </span>
        </label>
        <label style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}>
          <input type="radio" name={`${id}-who`} checked={locked} onChange={() => setLocked(true)} />
          <span>
            <strong>Only these accounts (recommended).</strong> Use the account that owns the Threatline Automation rules
            (its Use agent steps run as that account).
          </span>
        </label>
      </fieldset>
      {locked && (
        <>
          <label style={labelStyle} htmlFor={`${id}-ids`}>
            Account IDs, one per line
          </label>
          <textarea
            id={`${id}-ids`}
            value={ids}
            onChange={(e) => setIds(e.target.value)}
            rows={3}
            style={{ ...field, fontFamily: token('font.family.code') }}
          />
        </>
      )}
      {props.recent.length > 0 ? (
        <ul aria-label="Recent review authors" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 4 }}>
          {props.recent.map((a) => (
            <li key={a.accountId} style={{ font: token('font.body.small') }}>
              <code>{a.accountId}</code>: {a.runs} agent {a.runs === 1 ? 'run' : 'runs'}, last{' '}
              {a.lastAt.slice(0, 16).replace('T', ' ')} UTC{' '}
              {locked && (
                <Button
                  appearance="subtle"
                  spacing="compact"
                  onClick={() => setIds(splitList(`${ids}\n${a.accountId}`).join('\n'))}
                >
                  {`Use ${a.accountId}`}
                </Button>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <span style={hint}>
          No agent run has been saved yet. Once the Automation rule has run, the account it runs as appears here.
        </span>
      )}
      <span style={hint}>Refused submissions are recorded in the risk ledger with who tried.</span>
    </PolicyForm>
  );
}
