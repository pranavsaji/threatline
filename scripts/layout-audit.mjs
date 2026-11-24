#!/usr/bin/env node
// Layout audit for the mock-bridge previews (Task 32): loads every surface at 320 px and 1280 px, light and dark, in
// headless Chromium over the DevTools protocol (Node built-ins only), fails if any page scrolls sideways, and can save
// full-page screenshots.
//
//   pnpm --filter @threatline/core-ui dev --port 5179 & pnpm --filter @threatline/bitbucket-ui dev --port 5180 &
//   node scripts/layout-audit.mjs [--shots DIR] [--only name,name] [--widths 320,1280] [--themes light,dark]
//
// CHROME may point at any Chromium binary; by default the Playwright headless shell in the user cache is used.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

const CORE = process.env.CORE_URL ?? 'http://localhost:5179/';
const BB = process.env.BB_URL ?? 'http://localhost:5180/';

/** Every surface the mock bridges can show; `click` opens a control first (by its visible text) so dialogs are audited too. */
export const SURFACES = [
  { name: 'panel-ready', url: `${CORE}?state=ready` },
  { name: 'panel-details', url: `${CORE}?state=ready`, click: ['Details'] },
  { name: 'panel-not-reviewed', url: `${CORE}?state=not_reviewed` },
  { name: 'panel-in-progress', url: `${CORE}?state=in_progress` },
  { name: 'panel-failed', url: `${CORE}?state=failed` },
  { name: 'panel-timeout', url: `${CORE}?state=timeout` },
  { name: 'panel-budget', url: `${CORE}?state=budget` },
  { name: 'panel-injection', url: `${CORE}?state=injection` },
  { name: 'panel-stale', url: `${CORE}?state=stale` },
  { name: 'panel-partial', url: `${CORE}?state=partial` },
  { name: 'panel-pass', url: `${CORE}?state=pass` },
  { name: 'panel-revised', url: `${CORE}?state=revised` },
  { name: 'panel-what-if', url: `${CORE}?state=ready`, click: ['What if…'] },
  { name: 'panel-requirements', url: `${CORE}?state=ready`, click: ['Requirements (2)'] },
  { name: 'panel-acceptances', url: `${CORE}?state=ready`, click: ['Acceptances (0)'] },
  { name: 'panel-history', url: `${CORE}?state=ready`, click: ['History'] },
  { name: 'panel-accept-modal', url: `${CORE}?state=ready`, click: ['Requirements (2)', 'Accept risk'] },
  { name: 'admin', url: `${CORE}?view=admin` },
  { name: 'admin-first-run', url: `${CORE}?view=admin&state=first` },
  { name: 'posture', url: `${CORE}?view=posture` },
  { name: 'posture-empty', url: `${CORE}?view=posture&state=empty` },
  { name: 'posture-gadget', url: `${CORE}?view=gadget` },
  { name: 'bitbucket-settings', url: BB },
];

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
}

function chromePath() {
  if (process.env.CHROME) return process.env.CHROME;
  const cache = join(homedir(), 'Library/Caches/ms-playwright');
  const dirs = existsSync(cache) ? readdirSync(cache).filter((d) => d.startsWith('chromium_headless_shell')).sort() : [];
  if (dirs.length === 0) throw new Error('No Chromium found: set CHROME to a Chromium binary.');
  const base = join(cache, dirs[dirs.length - 1]);
  const sub = readdirSync(base).find((d) => d.startsWith('chrome-headless-shell'));
  return join(base, sub, 'chrome-headless-shell');
}

export async function launch() {
  const profile = join(tmpdir(), `threatline-audit-${process.pid}`);
  const proc = spawn(chromePath(), ['--headless', '--disable-gpu', '--hide-scrollbars', '--remote-debugging-port=0', `--user-data-dir=${profile}`, ...(process.platform === 'linux' ? ['--no-sandbox'] : []), 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    let buf = '';
    proc.stderr.on('data', (d) => {
      buf += d;
      const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) resolve(m[1]);
    });
    proc.on('exit', () => reject(new Error(`Chromium exited: ${buf.slice(-400)}`)));
  });
  const port = new URL(wsUrl).port;
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const page = targets.find((t) => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r, { once: true }));
  let id = 0;
  const pending = new Map();
  ws.addEventListener('message', (e) => {
    const msg = JSON.parse(e.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message));
      else resolve(msg.result);
    }
  });
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const n = ++id;
      pending.set(n, { resolve, reject });
      ws.send(JSON.stringify({ id: n, method, params }));
    });
  return { send, close: () => (ws.close(), proc.kill()) };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Runs in the page: elements whose box ends right of the viewport (the outermost ones only). */
const OVERFLOW_PROBE = `(() => {
  const w = document.documentElement.clientWidth;
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.right <= w + 1) continue;
    let p = el.parentElement, clipped = false;
    while (p && p !== document.body) {
      const s = getComputedStyle(p);
      if (/(auto|scroll|hidden|clip)/.test(s.overflowX)) { clipped = true; break; }
      p = p.parentElement;
    }
    if (clipped) continue;
    if (el.parentElement && el.parentElement.getBoundingClientRect().right > w + 1 && out.length) continue;
    const label = el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.getAttribute('aria-label') ? '[' + el.getAttribute('aria-label') + ']' : '');
    out.push(label + ' → ' + Math.round(r.right) + 'px: ' + (el.textContent || '').trim().slice(0, 50));
    if (out.length > 6) break;
  }
  return JSON.stringify({ scrollWidth: document.documentElement.scrollWidth, width: w, offenders: out });
})()`;

export const clickByText = (text) => `(() => {
  const els = [...document.querySelectorAll('button, [role=tab], a, summary')];
  const el = els.find((e) => (e.textContent || '').trim() === ${JSON.stringify(text)});
  if (!el) return false;
  el.click();
  return true;
})()`;

/** Sets a React-controlled field's value (native setter + input event), found by CSS selector. */
export const fillField = (selector, value) => `(() => {
  const el = document.querySelector(${JSON.stringify(selector)});
  if (!el) return false;
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, ${JSON.stringify(value)});
  el.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`;

/**
 * Loads one surface, runs its steps ({ click } by visible text, { fill: [selector, value] }, or { eval } for an expression
 * that must return true) and optionally saves a PNG: the page from the top (at most maxHeight), or with `clip` (a CSS
 * selector) just that element plus `pad` px around it.
 */
export async function capture(b, { url, theme, width, steps = [], file, maxHeight = 4000, clip, pad = 12 }) {
  await b.send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 2, mobile: false });
  await b.send('Page.navigate', { url: `${url}${url.includes('?') ? '&' : '?'}theme=${theme}` });
  await sleep(1800);
  for (const step of steps) {
    const expression = step.click ? clickByText(step.click) : step.fill ? fillField(step.fill[0], step.fill[1]) : step.eval;
    const { result } = await b.send('Runtime.evaluate', { expression, returnByValue: true });
    if (!result.value) throw new Error(`${url}: step failed ${JSON.stringify(step).slice(0, 120)}`);
    await sleep(600);
  }
  if (!file) return;
  if (clip) {
    const expression = `(() => { const el = document.querySelector(${JSON.stringify(clip)}); if (!el) return null; const r = el.getBoundingClientRect(); return { x: r.left + scrollX, y: r.top + scrollY, width: r.width, height: r.height }; })()`;
    const { result } = await b.send('Runtime.evaluate', { expression, returnByValue: true });
    if (!result.value) throw new Error(`${url}: nothing matches ${clip}`);
    const r = result.value;
    const x = Math.max(0, Math.floor(r.x - pad));
    const y = Math.max(0, Math.floor(r.y - pad));
    const region = { x, y, width: Math.min(width, Math.ceil(r.x + r.width + pad)) - x, height: Math.ceil(r.y + r.height + pad) - y, scale: 1 };
    const { data } = await b.send('Page.captureScreenshot', { format: 'png', clip: region, captureBeyondViewport: true });
    writeFileSync(file, Buffer.from(data, 'base64'));
    return;
  }
  const { contentSize } = await b.send('Page.getLayoutMetrics');
  const height = Math.min(maxHeight, Math.ceil(contentSize.height));
  const { data } = await b.send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width, height, scale: 1 }, captureBeyondViewport: true });
  writeFileSync(file, Buffer.from(data, 'base64'));
}

async function main() {
  const shots = arg('shots', null);
  const only = arg('only', null)?.split(',');
  const widths = arg('widths', '320,1280').split(',').map(Number);
  const themes = arg('themes', 'light,dark').split(',');
  if (shots) mkdirSync(shots, { recursive: true });
  const b = await launch();
  await b.send('Page.enable');
  await b.send('Runtime.enable');
  const failures = [];
  try {
    for (const s of SURFACES.filter((x) => !only || only.includes(x.name))) {
      for (const theme of themes) {
        for (const width of widths) {
          await b.send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: shots ? 2 : 1, mobile: false });
          await b.send('Page.navigate', { url: `${s.url}${s.url.includes('?') ? '&' : '?'}theme=${theme}` });
          await sleep(1800);
          for (const text of s.click ?? []) {
            const { result } = await b.send('Runtime.evaluate', { expression: clickByText(text), returnByValue: true });
            if (!result.value) failures.push(`${s.name} ${theme} ${width}: no control "${text}"`);
            await sleep(700);
          }
          const { result } = await b.send('Runtime.evaluate', { expression: OVERFLOW_PROBE, returnByValue: true });
          const m = JSON.parse(result.value);
          const tag = `${s.name} ${theme} ${width}px`;
          if (m.scrollWidth > m.width + 1) failures.push(`${tag}: page is ${m.scrollWidth}px wide\n    ${m.offenders.join('\n    ')}`);
          else console.log(`ok   ${tag}`);
          if (shots) {
            const { contentSize } = await b.send('Page.getLayoutMetrics');
            const height = Math.min(4000, Math.ceil(contentSize.height));
            const { data } = await b.send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width, height, scale: 1 }, captureBeyondViewport: true });
            writeFileSync(join(shots, `${s.name}-${theme}-${width}.png`), Buffer.from(data, 'base64'));
          }
        }
      }
    }
  } finally {
    b.close();
  }
  for (const f of failures) console.log(`FAIL ${f}`);
  console.log(failures.length ? `${failures.length} layout failure(s)` : 'No surface scrolls sideways.');
  process.exit(failures.length ? 1 : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) void main();
