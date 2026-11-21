import { describe, expect, it } from 'vitest';
import { parseJUnit } from '../src/junit.js';

const ok = (xml: string) => {
  const r = parseJUnit(xml);
  if (!r.ok) throw new Error(r.message);
  return r.cases;
};

describe('parseJUnit (feature: verification from CI)', () => {
  it('reads Maven Surefire: passed, failure, error and skipped testcases, with the class name in front', () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="com.acme.Pay101SecurityTest" tests="4" failures="1" errors="1" skipped="1">
  <properties><property name="java.version" value="21"/></properties>
  <testcase name="req_1a2b3c4d5e6f7a8b_rejectsBadSignature" classname="com.acme.Pay101SecurityTest" time="0.01"/>
  <testcase name="req_1a2b3c4d5e6f7a8b_rejectsReplay" classname="com.acme.Pay101SecurityTest"><failure message="expected 401" type="AssertionError">at line 3</failure></testcase>
  <testcase name="boom" classname="com.acme.Other"><error message="NPE"/></testcase>
  <testcase name="later" classname="com.acme.Other"><skipped/></testcase>
</testsuite>`;
    expect(ok(xml)).toEqual([
      { name: 'com.acme.Pay101SecurityTest req_1a2b3c4d5e6f7a8b_rejectsBadSignature', status: 'passed' },
      { name: 'com.acme.Pay101SecurityTest req_1a2b3c4d5e6f7a8b_rejectsReplay', status: 'failed' },
      { name: 'com.acme.Other boom', status: 'failed' },
      { name: 'com.acme.Other later', status: 'skipped' },
    ]);
  });

  it('reads vitest, jest and pytest shapes: testsuites wrappers, nested suites, single quotes, entities, CDATA and comments', () => {
    const xml = `﻿<?xml version="1.0"?>
<!-- generated -->
<testsuites name="vitest tests">
  <testsuite name='test/webhook.test.ts'>
    <testsuite name="nested">
      <testcase classname='test/webhook.test.ts' name='PAY-101 Verify &amp; sign [req_1a2b3c4d5e6f7a8b] &gt; rejects &quot;bad&quot; &#39;sig&#39; &#x41;'>
        <system-out><![CDATA[ <failure> inside CDATA is only text </testcase> ]]></system-out>
      </testcase>
    </testsuite>
  </testsuite>
  <testsuite name="pytest"><testcase classname="tests.test_webhooks" name="test_req_1a2b3c4d5e6f7a8b_the_request_is_rejected" file="tests/test_webhooks.py" line="3"
     time="0.002"></testcase></testsuite>
</testsuites>`;
    expect(ok(xml)).toEqual([
      { name: `test/webhook.test.ts PAY-101 Verify & sign [req_1a2b3c4d5e6f7a8b] > rejects "bad" 'sig' A`, status: 'passed' },
      { name: 'tests.test_webhooks test_req_1a2b3c4d5e6f7a8b_the_request_is_rejected', status: 'passed' },
    ]);
  });

  it('fails closed: an error on the suite itself, or a flaky or rerun failure, counts as a failure; failure beats skipped', () => {
    expect(ok('<testsuites><testsuite><error message="setup failed"/><testcase name="a"/><testsuite><testcase name="b"/></testsuite></testsuite><testsuite><testcase name="c"/></testsuite></testsuites>')).toEqual([
      { name: 'a', status: 'failed' },
      { name: 'b', status: 'failed' },
      { name: 'c', status: 'passed' },
    ]);
    expect(ok('<testsuite><testcase name="f"><flakyFailure/></testcase><testcase name="r"><rerunError/></testcase><testcase name="s"><skipped/><failure/></testcase></testsuite>').map((c) => c.status)).toEqual([
      'failed',
      'failed',
      'failed',
    ]);
  });

  it('a testcase with neither name nor classname is left out; a missing name uses the class name', () => {
    expect(ok('<testsuite><testcase/><testcase classname="Only"/><testcase name="n"/></testsuite>')).toEqual([
      { name: 'Only', status: 'passed' },
      { name: 'n', status: 'passed' },
    ]);
  });

  it('refuses malformed XML and DOCTYPE declarations with entities, rather than guessing', () => {
    for (const bad of [
      '<testsuite><testcase name="a"></testsuite>',
      '<testsuite><testcase name="a"/>',
      '<testsuite><testcase name="a></testsuite>',
      '</testsuite>',
      '<testsuite><!-- never closed',
      '<!DOCTYPE x [<!ENTITY a "aaaa">]><testsuite/>',
      'not xml at all',
    ])
      expect(parseJUnit(bad).ok, bad).toBe(false);
    expect(parseJUnit('').ok).toBe(false);
  });

  it('keeps an unknown entity as text, and handles a large report in one pass', () => {
    expect(ok('<testsuite><testcase name="a &nbsp; b"/></testsuite>')[0]!.name).toBe('a &nbsp; b');
    const many = `<testsuite>${Array.from({ length: 20_000 }, (_, i) => `<testcase classname="c" name="t${i}"/>`).join('')}</testsuite>`;
    const t0 = Date.now();
    expect(ok(many)).toHaveLength(20_000);
    expect(Date.now() - t0).toBeLessThan(5000);
  });
});
