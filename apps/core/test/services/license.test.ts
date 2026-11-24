import { describe, expect, it } from 'vitest';
import { fixedClock } from '@threatline/core/testing';
import {
  invocationLicense,
  isLicensed,
  LICENSE_SEEN_KEY,
  licenseFromContext,
  overrideOf,
  recordedOf,
  resolveLicense,
} from '../../src/services/license.js';
import { memoryKvs } from '../support/memory-kvs.js';

const clock = fixedClock('2026-11-15T12:00:00Z');

describe('licenseFromContext (Forge context.license)', () => {
  it('active true is licensed, active false is unlicensed', () => {
    expect(licenseFromContext({ active: true })).toBe('licensed');
    expect(licenseFromContext({ active: false })).toBe('unlicensed');
  });

  it('no license object (free, unlisted, development) or a malformed one is not applicable', () => {
    for (const v of [undefined, null, 'active', true, {}, { active: 'false' }, { active: 1 }]) expect(licenseFromContext(v)).toBe('not_applicable');
  });
});

describe('overrideOf (THREATLINE_LICENSE_OVERRIDE)', () => {
  it('reads active and inactive, case and spaces aside; anything else is no override', () => {
    expect(overrideOf('active')).toBe('licensed');
    expect(overrideOf(' Inactive ')).toBe('unlicensed');
    for (const v of [undefined, '', 'trial', 'true', 1]) expect(overrideOf(v)).toBeNull();
  });
});

describe('recordedOf', () => {
  it('accepts only the states Threatline writes', () => {
    expect(recordedOf({ state: 'licensed', at: 'x' })).toBe('licensed');
    expect(recordedOf({ state: 'unlicensed' })).toBe('unlicensed');
    for (const v of [undefined, null, 'unlicensed', { state: 'not_applicable' }, { state: 'nope' }]) expect(recordedOf(v)).toBeNull();
  });
});

describe('resolveLicense', () => {
  it('not applicable is treated as licensed; only unlicensed is refused', () => {
    expect(isLicensed('licensed')).toBe(true);
    expect(isLicensed('not_applicable')).toBe(true);
    expect(isLicensed('unlicensed')).toBe(false);
  });

  it('the license Forge reports wins over the record and the override (an override never buys a license)', () => {
    expect(resolveLicense({ context: { active: false }, recorded: { state: 'licensed' }, override: 'active' })).toBe('unlicensed');
    expect(resolveLicense({ context: { active: true }, recorded: { state: 'unlicensed' }, override: 'inactive' })).toBe('licensed');
  });

  it('without one, the last recorded state applies, then the override, then not applicable', () => {
    expect(resolveLicense({ context: undefined, recorded: { state: 'unlicensed' }, override: 'active' })).toBe('unlicensed');
    expect(resolveLicense({ context: undefined, recorded: undefined, override: 'inactive' })).toBe('unlicensed');
    expect(resolveLicense({ context: undefined, recorded: undefined, override: 'active' })).toBe('licensed');
    expect(resolveLicense({ context: undefined })).toBe('not_applicable');
  });

  it('a resolver (authoritative) ignores the record: no license there really is not applicable', () => {
    expect(resolveLicense({ context: undefined, recorded: { state: 'unlicensed' }, authoritative: true })).toBe('not_applicable');
    expect(resolveLicense({ context: undefined, recorded: { state: 'unlicensed' }, override: 'inactive', authoritative: true })).toBe('unlicensed');
  });
});

describe('invocationLicense', () => {
  it('records a definite license when it changes, and computes once per invocation', async () => {
    const kv = memoryKvs();
    let reads = 0;
    const get = kv.get;
    kv.get = async (k) => (reads++, get(k));
    const l = invocationLicense(kv, clock, { context: { active: false }, override: undefined, authoritative: false });
    expect(await l.state()).toBe('unlicensed');
    expect(await l.state()).toBe('unlicensed');
    expect(reads).toBe(1);
    expect(kv.data.get(LICENSE_SEEN_KEY)).toEqual({ state: 'unlicensed', at: '2026-11-15T12:00:00.000Z' });
    // Unchanged: not written again.
    kv.data.set(LICENSE_SEEN_KEY, { state: 'unlicensed', at: 'earlier' });
    await invocationLicense(kv, clock, { context: { active: false }, override: undefined, authoritative: true }).state();
    expect(kv.data.get(LICENSE_SEEN_KEY)).toEqual({ state: 'unlicensed', at: 'earlier' });
  });

  it('an invocation without a license (validator, queue) uses the recorded one', async () => {
    const kv = memoryKvs();
    await invocationLicense(kv, clock, { context: { active: false }, override: undefined, authoritative: true }).state();
    expect(await invocationLicense(kv, clock, { context: undefined, override: undefined, authoritative: false }).state()).toBe('unlicensed');
    // ... and never clears it.
    expect(kv.data.has(LICENSE_SEEN_KEY)).toBe(true);
  });

  it('a resolver without a license clears the record (a development site reinstalled without --license)', async () => {
    const kv = memoryKvs();
    kv.data.set(LICENSE_SEEN_KEY, { state: 'unlicensed', at: 'x' });
    expect(await invocationLicense(kv, clock, { context: undefined, override: undefined, authoritative: true }).state()).toBe('not_applicable');
    expect(kv.data.has(LICENSE_SEEN_KEY)).toBe(false);
    expect(await invocationLicense(kv, clock, { context: undefined, override: undefined, authoritative: false }).state()).toBe('not_applicable');
  });

  it('the override applies in development, where Forge reports no license', async () => {
    const kv = memoryKvs();
    expect(await invocationLicense(kv, clock, { context: undefined, override: 'inactive', authoritative: true }).state()).toBe('unlicensed');
    expect(await invocationLicense(kv, clock, { context: undefined, override: 'inactive', authoritative: false }).state()).toBe('unlicensed');
    // The override is not a reported license, so it is not recorded.
    expect(kv.data.has(LICENSE_SEEN_KEY)).toBe(false);
  });

  it('storage failures never fail the caller: an unreadable record is ignored and a failed write is dropped', async () => {
    const kv = memoryKvs();
    kv.get = async () => Promise.reject(new Error('kvs down'));
    kv.set = async () => Promise.reject(new Error('kvs down'));
    expect(await invocationLicense(kv, clock, { context: undefined, override: undefined, authoritative: false }).state()).toBe('not_applicable');
    expect(await invocationLicense(kv, clock, { context: { active: false }, override: undefined, authoritative: false }).state()).toBe('unlicensed');
  });
});
