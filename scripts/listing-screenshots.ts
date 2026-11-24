// Marketplace listing screenshots (Task 32): 5 per listing, from the mock-bridge previews, into docs/screenshots/.
//
//   pnpm --filter @threatline/core-ui dev --port 5179 & pnpm --filter @threatline/bitbucket-ui dev --port 5180 &
//   pnpm exec tsx scripts/listing-screenshots.ts [jira-7 jira-8 …]   (names: only the files starting with one of them)
//
// The Bitbucket attestation shots use a throwaway key pair generated here, so the browser really verifies a signature;
// no key is stored. The Jira "Check an attestation" shots use a token sealed like the fixture bridge's own (the mock
// checks a checksum, not a signature: apps/core/ui/src/mock-attestation.ts). Every other value shown comes from the
// fixtures in apps/core/ui/src/fixtures.ts.
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { encodeAttestation, generateKeyPair } from '../packages/crypto/src/index.js';
import { MOCK_KID, mockAttestationToken } from '../apps/core/ui/src/mock-attestation.js';
// @ts-expect-error plain ESM script without types
import { capture, launch } from './layout-audit.mjs';

const CORE = process.env.CORE_URL ?? 'http://localhost:5179/';
const BB = process.env.BB_URL ?? 'http://localhost:5180/';
const OUT = join(process.cwd(), 'docs/screenshots');

const key = generateKeyPair();
const now = Math.floor(Date.now() / 1000);
const token = encodeAttestation(
  {
    v: 1,
    kid: key.kid,
    issueKey: 'PAY-6',
    repo: 'acme/payments',
    commitSha: '3f9c2a7d1e0b4c6a8f5d2e1b0a9c8d7e6f5a4b3c',
    verdict: 'pass',
    requirements: [
      { id: 'req_1', status: 'Verified' },
      { id: 'req_2', status: 'Verified' },
    ],
    iat: now - 60,
    exp: now + 24 * 3600,
    nonce: 'listing01',
  },
  key,
);
const tampered = token.slice(0, 40) + (token[40] === 'A' ? 'B' : 'A') + token.slice(41);
const SHA = '3f9c2a7d1e0b4c6a8f5d2e1b0a9c8d7e6f5a4b3c';
const sealed = mockAttestationToken({ v: 1, kid: MOCK_KID, issueKey: 'PAY-6', repo: 'acme/payments', commitSha: SHA, verdict: 'pass', requirements: [{ id: 'req_1', status: 'Verified' }, { id: 'req_2', status: 'Verified' }], iat: now - 60, exp: now + 24 * 3600, nonce: 'listing02' });
// one character of the signature segment changed
const at = sealed.length - 20;
const sealedTampered = sealed.slice(0, at) + (sealed[at] === 'A' ? 'B' : 'A') + sealed.slice(at + 1);
const CHECK = 'form[aria-label="Check an attestation"]';
const checkSteps = (text: string) => [{ click: 'Requirements (2)' }, { click: 'Check an attestation' }, { fill: [`${CHECK} textarea`, text] }, { fill: [`${CHECK} input:nth-of-type(2)`, SHA] }, { click: 'Check' }];
const KEYS = 'form[aria-label="Threatline settings"] textarea';
const PASTE = 'form[aria-label="Test an attestation"] textarea';

const SHOTS = [
  // Threatline for Jira (Core, with Confluence)
  { file: 'jira-1-issue-panel.png', url: `${CORE}?state=ready`, theme: 'light', width: 760, maxHeight: 1100 },
  { file: 'jira-2-threat-evidence.png', url: `${CORE}?state=ready`, theme: 'dark', width: 760, maxHeight: 1100, steps: [{ click: 'Details' }, { click: 'Explain like I’m new to security' }] },
  { file: 'jira-3-accept-risk.png', url: `${CORE}?state=ready`, theme: 'light', width: 760, maxHeight: 1200, steps: [{ click: 'Requirements (2)' }, { click: 'Accept risk' }] },
  { file: 'jira-4-posture-dashboard.png', url: `${CORE}?view=posture`, theme: 'light', width: 1280, maxHeight: 900 },
  { file: 'jira-5-admin-policy.png', url: `${CORE}?view=admin`, theme: 'dark', width: 1280, maxHeight: 1300 },
  // The context column (jira:issueContext) at about its width, with the room Jira's column gives it.
  { file: 'jira-7-status-label.png', url: `${CORE}?view=status&state=ready`, theme: 'light', width: 340, steps: [{ eval: "(document.body.style.padding = '16px', true)" }], clip: 'section[aria-label="Threatline gate status"]', pad: 16 },
  { file: 'jira-8-check-attestation.png', url: `${CORE}?state=pass`, theme: 'light', width: 760, steps: checkSteps(`Threatline attestation for PAY-6:\n${sealed}`), clip: `details:has(${CHECK})`, pad: 6 },
  { file: 'jira-9-check-attestation-tampered.png', url: `${CORE}?state=pass`, theme: 'dark', width: 760, steps: checkSteps(sealedTampered), clip: `details:has(${CHECK})`, pad: 6 },
  { file: 'jira-10-setup-use-group.png', url: `${CORE}?view=admin&group=missing`, theme: 'light', width: 1100, clip: 'section:has(> ul[aria-label="Setup checklist"])' },
  // Threatline for Bitbucket
  { file: 'bitbucket-1-repo-settings.png', url: BB, theme: 'light', width: 1280, maxHeight: 900 },
  { file: 'bitbucket-2-attestation-valid.png', url: BB, theme: 'light', width: 1280, maxHeight: 1100, steps: [{ fill: [KEYS, key.publicKey] }, { fill: [PASTE, `Threatline attestation for PAY-6:\n${token}`] }, { click: 'Test' }] },
  { file: 'bitbucket-3-attestation-tampered.png', url: BB, theme: 'dark', width: 1280, maxHeight: 1100, steps: [{ fill: [KEYS, key.publicKey] }, { fill: [PASTE, tampered] }, { click: 'Test' }] },
  {
    file: 'bitbucket-4-jira-attestation.png',
    url: `${CORE}?state=pass`,
    theme: 'light',
    width: 760,
    maxHeight: 1400,
    steps: [{ click: 'Requirements (2)' }, { fill: ['form[aria-label="Merge attestation"] input', 'acme/payments'] }, { fill: ['form[aria-label="Merge attestation"] input:nth-of-type(2)', '3f9c2a7d1e0b4c6a8f5d2e1b0a9c8d7e6f5a4b3c'] }, { click: 'Get attestation' }],
  },
  { file: 'bitbucket-5-repo-settings-dark.png', url: BB, theme: 'dark', width: 1280, maxHeight: 900 },
];

async function main() {
  mkdirSync(OUT, { recursive: true });
  const b = await launch();
  await b.send('Page.enable');
  await b.send('Runtime.enable');
  try {
    const only = process.argv.slice(2);
    for (const s of SHOTS.filter((x) => only.length === 0 || only.some((o) => x.file.startsWith(`${o}-`) || x.file === o))) {
      await capture(b, { ...s, file: join(OUT, s.file) });
      console.log(`saved docs/screenshots/${s.file}`);
    }
  } finally {
    b.close();
  }
}
void main().catch((e) => {
  console.error(e);
  process.exit(1);
});
