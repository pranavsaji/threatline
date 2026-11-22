import { spawnSync } from 'node:child_process';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { evalSubset, rematchSubset, verifyMode } from '../src/cli.js';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

describe('pnpm threatline: argument checks', () => {
  it('eval --subset is all or a positive whole number; anything else is an error, not zero cases', () => {
    expect(evalSubset('all')).toBe('all');
    expect(evalSubset('30')).toBe(30);
    for (const raw of [undefined, '', 'x', '0', '-3', '1.5', '3x', 'holdout', ' 30'])
      expect(() => evalSubset(raw), String(raw)).toThrow(/--subset takes all or a positive whole number/);
  });

  it('rematch --subset is all, 30 or holdout', () => {
    for (const raw of ['all', '30', 'holdout'] as const) expect(rematchSubset(raw)).toBe(raw);
    for (const raw of [undefined, '10', 'x']) expect(() => rematchSubset(raw), String(raw)).toThrow(/all, 30 or holdout/);
  });

  it('--verify claude-code and resume are live (they ask first); recorded is not; anything else is an error', () => {
    expect(verifyMode('recorded')).toEqual({ mode: 'recorded', live: false });
    expect(verifyMode('claude-code')).toEqual({ mode: 'claude-code', live: true });
    expect(verifyMode('resume')).toEqual({ mode: 'resume', live: true });
    expect(() => verifyMode('claude')).toThrow(/--verify takes/);
  });

  // PATH holds only node, so even a regression could not reach `claude -p`.
  const run = (args: string[], input = '') =>
    spawnSync(process.execPath, ['--import', 'tsx', cli, ...args], { cwd: root, input, encoding: 'utf8', env: { PATH: dirname(process.execPath), HOME: process.env.HOME ?? '' }, timeout: 60_000 });

  it('a live verifier with replayed reviews asks before any claude -p call, and stops on no', () => {
    const r = run(['eval', '--llm', 'recorded', '--path', 'engine', '--verify', 'claude-code', '--subset', '1'], 'n\n');
    expect(r.stdout).toMatch(/This will make 1 `claude -p` call\(s\) on claude-sonnet-4-5 \(verifier, at most one call per case\)/);
    expect(r.stdout).not.toMatch(/wrote /);
    expect(r.status).toBe(0);
  }, 60_000);

  it('a bad --subset exits with an error before anything runs', () => {
    const r = run(['eval', '--subset', 'thirty']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/--subset takes all or a positive whole number of cases, not "thirty"/);
  }, 60_000);
});
