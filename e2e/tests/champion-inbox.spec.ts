import { expect, test } from '@playwright/test';
import { PANEL, post, tryDone, USERS } from './harness.js';

/**
 * Journey C: a review rests on text that reads as instructions to an AI, so its threats wait for a security champion
 * and Done is blocked → a developer sees no inbox → the champion opens the Champion inbox on the global page, confirms
 * one threat and dismisses the other with a reason, by keyboard → the inbox is empty, Done now waits only on the
 * confirmed threat's requirement, and the ledger still verifies.
 */
test('Journey C: champion inbox decides the threats waiting for a person', async ({ page, request }) => {
  await post(request, 'reset');
  await post(request, 'review', { injected: true });
  expect((await tryDone(request)).errorMessage).toMatch(/looked like instructions to the AI/);

  await page.goto(`${PANEL}/?bridge=local&as=${USERS.dev}&view=posture`);
  await expect(page.getByRole('heading', { name: 'Security posture' })).toBeVisible();
  await expect(page.getByRole('tab', { name: /Champion inbox/ })).toHaveCount(0);

  await page.goto(`${PANEL}/?bridge=local&as=${USERS.champion}&view=posture`);
  const tab = page.getByRole('tab', { name: /Champion inbox/ });
  await expect(tab.getByLabel('2 waiting')).toBeVisible();
  await tab.click();
  await expect(page.getByText('2 threats waiting for a security champion, most severe and oldest first.')).toBeVisible();
  const forged = page.getByRole('listitem').filter({ has: page.getByRole('checkbox', { name: 'Select Forged refund webhooks on PAY-7' }) });
  await expect(forged.getByRole('link', { name: 'PAY-7' })).toBeVisible();
  await expect(forged).toContainText('Refund webhook');
  await expect(forged).toContainText('looked like instructions to an AI');

  await page.keyboard.press('?');
  await expect(page.getByRole('list', { name: 'Keyboard shortcuts' })).toBeVisible();

  // c confirms the current (first, most severe) threat: it becomes a requirement.
  await page.keyboard.press('c');
  await expect(page.getByText('Confirmed 1 threat.')).toBeVisible();
  await expect(tab.getByLabel('1 waiting')).toBeVisible();

  // d opens the dismissal for the next one; it needs a reason.
  await page.keyboard.press('d');
  const form = page.getByRole('form', { name: 'Dismiss threats' });
  await form.getByRole('combobox', { name: 'Reason' }).selectOption('false_positive');
  await form.getByRole('textbox', { name: 'Note (optional)' }).fill('Payloads are not logged');
  await form.getByRole('button', { name: 'Dismiss 1 threat' }).click();
  await expect(page.getByText('Dismissed 1 threat.')).toBeVisible();
  await expect(page.getByText('Nothing is waiting for a security champion.')).toBeVisible();

  const done = await tryDone(request);
  expect(done.result).toBe(false);
  expect(done.errorMessage).not.toMatch(/instructions to the AI/);
  expect(done.errorMessage).toMatch(/open security requirements at High or above/);
  expect(await post(request, 'invoke', { key: 'ledger.verify', accountId: USERS.admin })).toMatchObject({ ok: true });
});
