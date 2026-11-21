import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { gitHubClient } from './github.js';
import { parseInputs, runGitHubCheck } from './run.js';
import { actionReportConfig, runCiReport, type GitHubEventLike } from './ci-report.js';

/**
 * GitHub Actions entry point: the merge gate (unless merge-gate is false), then, when threatline-url, threatline-token
 * and junit are set, the CI verification report (docs/CI_VERIFICATION.md). The job fails if either fails.
 */
const env = process.env;
const input = (name: string) => env[`INPUT_${name.toUpperCase()}`];
// Workflow commands: %, CR and LF must be escaped, or a message could end the annotation and start another command.
const escape = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const say = (line: string) => process.stdout.write(`${line}\n`);

type Event = GitHubEventLike & { pull_request?: { number?: number }; repository?: { full_name?: string } };

async function main(): Promise<number> {
  const eventPath = env.GITHUB_EVENT_PATH ?? '';
  const event = (eventPath && existsSync(eventPath) ? JSON.parse(readFileSync(eventPath, 'utf8')) : {}) as Event;
  const gateInput = (input('merge-gate') ?? '').trim().toLowerCase() || 'true';
  if (gateInput !== 'true' && gateInput !== 'false') return finish(false, 'config_error', 'Threatline: merge-gate must be true or false.');
  const report = actionReportConfig({ url: input('threatline-url'), token: input('threatline-token'), junit: input('junit') }, env, event);
  if (!report.ok) return finish(false, 'config_error', report.message);
  if (gateInput === 'false' && !report.value) return finish(false, 'config_error', 'Threatline: merge-gate is false and no report is configured (threatline-url, threatline-token, junit), so this step does nothing.');

  let gateOk = true;
  if (gateInput === 'true') gateOk = (await mergeGate(event)) === 0;
  if (!report.value) return gateOk ? 0 : 1;

  // The token comes from a secret (already masked); masking it again costs nothing if it was passed some other way.
  say(`::add-mask::${report.value.token}`);
  const r = await runCiReport(report.value);
  say('::group::Threatline CI verification');
  for (const line of r.lines) say(line);
  say('::endgroup::');
  say(`::${!r.success ? 'error' : r.warning ? 'warning' : 'notice'} title=Threatline CI verification::${escape(r.message)}`);
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `ci-report=${!r.success ? 'failed' : r.warning ? 'warning' : 'reported'}\n`);
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `### Threatline CI verification\n\n${r.message}\n\n${r.lines.map((l) => `- ${l}`).join('\n')}\n`);
  return gateOk && r.success ? 0 : 1;
}

async function mergeGate(event: Event): Promise<number> {
  const nowSec = env.THREATLINE_NOW ? Number(env.THREATLINE_NOW) : Math.floor(Date.now() / 1000);
  const settings = parseInputs({ 'public-keys': input('public-keys'), 'sensitive-paths': input('sensitive-paths'), mode: input('mode'), 'warn-until': input('warn-until'), 'diff-score-threshold': input('diff-score-threshold') }, nowSec);
  if (!settings.ok) return finish(false, 'config_error', settings.message);
  const number = event.pull_request?.number;
  const repo = event.repository?.full_name;
  if (!number || !repo) return finish(false, 'config_error', 'Threatline: run this action on pull_request events (opened, edited, synchronize, reopened).');
  // Under pull_request, GitHub runs the workflow file from the pull request itself, so its author could change this
  // step's inputs or replace it. pull_request_target runs the base branch's workflow, which the PR cannot change.
  if (env.GITHUB_EVENT_NAME === 'pull_request')
    say(`::warning title=Threatline::${escape('Threatline: this workflow runs on pull_request, so a pull request can change its own gate. Use pull_request_target (see docs/GITHUB.md).')}`);
  const token = input('github-token') ?? env.GITHUB_TOKEN ?? '';
  const client = gitHubClient({ api: env.GITHUB_API_URL ?? 'https://api.github.com', token, repo, number });
  const r = await runGitHubCheck({ settings: settings.value, client, nowSec });
  return finish(r.success, r.outcome, r.message);
}

function finish(success: boolean, outcome: string, message: string): number {
  say(`::${success ? (outcome === 'warn' || message.startsWith('Warning') ? 'warning' : 'notice') : 'error'} title=Threatline::${escape(message)}`);
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `outcome=${outcome}\nmessage=${message.replace(/[\r\n]+/g, ' ')}\n`);
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `### Threatline merge gate: ${success ? 'pass' : 'blocked'}\n\n${message}\n`);
  return success ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    // Fail closed on any unexpected error; say what failed without dumping request details.
    say(`::error title=Threatline::${escape(`Threatline: the merge gate could not run (${e instanceof Error ? e.name : 'error'}), so the change is blocked. Re-run the job.`)}`);
    process.exit(1);
  },
);
