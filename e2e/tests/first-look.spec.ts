import { expect, test } from '@playwright/test';
import { openPanel, PANEL, post, tryDone, USERS } from './harness.js';

/**
 * It answers where you look, in seconds: as soon as the gather finishes (before any AI run), the panel shows the first
 * look from Threatline's rules and the context column counts it, while the gate keeps blocking. When the review
 * settles, the first look is gone and Threatline comments the verdict on the work item once.
 */
test('first look while the review runs, then one verdict comment when it settles', async ({ page, request }) => {
  await post(request, 'reset');
  await post(request, 'gather');

  await openPanel(page, USERS.dev);
  const first = page.getByTestId('threatline-first-look');
  await expect(first.getByText("First look from Threatline's rules. The AI review is running and will replace this.")).toBeVisible();
  const risks = first.getByRole('list', { name: 'First look risks' }).getByRole('listitem');
  await expect(risks.first()).toBeVisible();
  expect(await risks.count()).toBeGreaterThan(0);
  await expect(first.getByText(/“.+”/).first()).toBeVisible();
  // A first look decides nothing: Done stays blocked while the review runs.
  await expect(page.getByText('Blocks Done and merge')).toBeVisible();
  expect((await tryDone(request)).result).toBe(false);

  await page.goto(`${PANEL}/?bridge=local&as=${USERS.dev}&issue=10042&view=status`);
  await expect(page.getByRole('status')).toHaveText(/^Reviewing…· first look: \d+ risks?$/);
  expect(await post(request, 'comments')).toEqual({ comments: [] });

  await post(request, 'review');
  await openPanel(page, USERS.dev);
  await expect(page.getByText('3 open security requirements at High or above.')).toBeVisible();
  await expect(page.getByTestId('threatline-first-look')).toHaveCount(0);

  const { comments } = await post<{ comments: string[][] }>(request, 'comments');
  expect(comments).toHaveLength(1);
  expect(comments[0]!.slice(0, 3)).toEqual(['Threatline security review: ✕ Blocks Done and merge', '1 thing stands between this work item and Done:', '• 3 open security requirements at High or above.']);
  expect(comments[0]).toContain('Evidence, requirements and next steps are in the Threatline panel on this work item.');
  expect(comments[0]!.some((l) => l.startsWith('Top risk (High): '))).toBe(true);
});
