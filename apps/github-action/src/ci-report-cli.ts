import { cliReportConfig, runCiReport } from './ci-report.js';

/**
 * `node scripts/threatline-ci-report.mjs --junit "test-results/**\/*.xml"`: reports which requirement tests passed to
 * Threatline (docs/CI_VERIFICATION.md). Built into scripts/threatline-ci-report.mjs by build.mjs; Node 18+, no
 * dependencies. Exit 0 when reported (or Threatline was busy: nothing is verified then), 1 on a configuration error.
 */
async function main(): Promise<number> {
  const config = cliReportConfig(process.argv.slice(2), process.env);
  if (!config.ok) {
    console.error(config.message);
    return 1;
  }
  const r = await runCiReport(config.value);
  for (const line of r.lines) console.log(line);
  (r.success ? console.log : console.error)(r.warning ? `Warning: ${r.message}` : r.message);
  return r.success ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    console.error(`Threatline: the CI report could not run (${e instanceof Error ? e.name : 'error'}).`);
    process.exit(1);
  },
);
