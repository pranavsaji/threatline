import { expect, test } from '@playwright/test';
import { openPanel, post, tryDone, USERS, verify } from './harness.js';

/**
 * Journey A (Task 34): the review lands → Done is blocked with the reason, and the panel names the past incident the
 * top threat repeats (Seen before) → the developer turns the requirements into tasks from the header and
 * verifies every blocking requirement with evidence → Done is allowed, and the panel says so.
 */
test('Journey A: review lands, requirements verified with evidence, Done allowed', async ({ page, request }) => {
  await post(request, 'reset');
  expect(await tryDone(request)).toMatchObject({ result: false, errorMessage: expect.stringMatching(/not reviewed this work item yet/) });

  await post(request, 'review');
  const blocked = await tryDone(request);
  expect(blocked.result).toBe(false);
  expect(blocked.errorMessage).toMatch(/3 open security requirements at High or above/);

  await openPanel(page, USERS.dev);
  await expect(page.getByText('Blocks Done and merge')).toBeVisible();
  await expect(page.getByText('3 open security requirements at High or above.')).toBeVisible();

  // Seen before: the past incident on the same component, under the threat it repeats and in the headline.
  await expect(page.getByTestId('threatline-happened-before')).toHaveText('This happened before: PAY-3 — Forged refund webhook paid out to an attacker.');
  const forged = page.getByRole('article').filter({ hasText: 'Forged refund webhooks' });
  await expect(forged.getByRole('list', { name: 'Seen before' })).toContainText('PAY-3 · Incident · Forged refund webhook paid out to an attacker (payments)');
  await expect(forged.getByRole('list', { name: 'Seen before' })).toContainText('Why: same component payments; shared words:');

  // The one positive action, under the headline: every open requirement becomes a sub-task, and the keys are links.
  await page.getByRole('button', { name: 'Turn 5 requirements into tasks' }).click();
  await expect(page.locator('header').getByRole('status')).toHaveText(/^Created PAY-1\d\d(, PAY-1\d\d){4}\.$/);
  await expect(page.getByRole('button', { name: /into tasks/ })).toHaveCount(0);
  await page.getByRole('tab', { name: /^Requirements/ }).click();
  await expect(page.getByRole('button', { name: /Create sub-tasks/ })).toHaveCount(0);

  const high = ['Forged refund webhooks', 'Payment amount or recipient manipulated', 'Personal data exposed to unauthorised users'];
  for (const [i, title] of high.entries()) await verify(page, title, `https://bitbucket.org/acme/payments/pull-requests/${41 + i}`);

  expect(await tryDone(request)).toEqual({ result: true });
  await page.reload();
  await expect(page.getByText('Ready for Done')).toBeVisible();
});
