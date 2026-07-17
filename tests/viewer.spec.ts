import { expect, test } from '@playwright/test';

const e2eBaseUrl = `http://127.0.0.1:${process.env.PREMIER_E2E_PORT ?? 4318}`;

test('explains a multi-agent run through lanes, filters, and causal evidence', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByLabel('Premier Trace')).toBeVisible();
  await expect(page.getByRole('button', { name: /multi-agent failure investigation/i })).toBeVisible();
  await page.getByRole('button', { name: 'Actors', exact: true }).click();
  await expect(page.getByRole('button', { name: /Focus researcher, subagent/ })).toBeVisible();
  await page.getByRole('button', { name: /Focus reviewer, subagent/ }).click();
  await expect(page).toHaveURL(/actor=reviewer/);
  await page.getByRole('button', { name: 'issues', exact: true }).click();
  await expect(page.getByRole('option', { name: /tool.error/ })).toBeVisible();
  await page.getByRole('option', { name: /tool.error/ }).click();
  await expect(page.getByRole('complementary', { name: 'Event inspector' })).toContainText('rounds_negative_credit');
  await expect(page.getByRole('complementary', { name: 'Event inspector' })).toContainText('reviewer');
});

test('connects approval request, receipt, and protected mutation', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'decisions', exact: true }).click();
  await expect(page.getByRole('option', { name: /approval.request/ })).toBeVisible();
  await page.getByRole('option', { name: /approval.decision/ }).click();
  await expect(page.getByRole('complementary', { name: 'Event inspector' })).toContainText('apr_01J');
  await expect(page.getByRole('complementary', { name: 'Event inspector' })).toContainText('approval-patch-01');
});

test('resizes the workspace and links analytics, topology, and local AI to trace evidence', async ({ page }) => {
  await page.goto('/');

  const leftSeparator = page.getByRole('separator', { name: 'Resize trace list' });
  const initialWidth = Number(await leftSeparator.getAttribute('aria-valuenow'));
  await leftSeparator.press('ArrowRight');
  await expect(leftSeparator).toHaveAttribute('aria-valuenow', String(initialWidth + 12));

  const rightSeparator = page.getByRole('separator', { name: 'Resize event inspector' });
  const initialInspectorWidth = Number(await rightSeparator.getAttribute('aria-valuenow'));
  await rightSeparator.press('ArrowLeft');
  await expect(rightSeparator).toHaveAttribute('aria-valuenow', String(initialInspectorWidth + 12));

  const timeSeparator = page.getByRole('separator', { name: 'Resize run activity' });
  const initialTimeHeight = Number(await timeSeparator.getAttribute('aria-valuenow'));
  await timeSeparator.press('ArrowDown');
  await expect(timeSeparator).toHaveAttribute('aria-valuenow', String(initialTimeHeight + 12));
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem('premier.viewer.workspace.v1') ?? '{}'))).toMatchObject({
    leftWidth: initialWidth + 12,
    rightWidth: initialInspectorWidth + 12,
    timeNavigatorHeight: initialTimeHeight + 12
  });

  await page.reload();
  await expect(page.getByRole('separator', { name: 'Resize trace list' })).toHaveAttribute('aria-valuenow', String(initialWidth + 12));
  await expect(page.getByRole('separator', { name: 'Resize event inspector' })).toHaveAttribute('aria-valuenow', String(initialInspectorWidth + 12));
  await expect(page.getByRole('separator', { name: 'Resize run activity' })).toHaveAttribute('aria-valuenow', String(initialTimeHeight + 12));

  await page.getByRole('button', { name: 'Analytics', exact: true }).click();
  await expect(page).toHaveURL(/view=analytics/);
  await expect(page.getByRole('heading', { name: 'Activity over time' })).toBeVisible();

  await page.getByRole('button', { name: 'System', exact: true }).click();
  await expect(page).toHaveURL(/view=map/);
  await expect(page.getByRole('heading', { name: 'Agent architecture' })).toBeVisible();
  const topologyTop = await page.locator('.topology').evaluate((element) => element.getBoundingClientRect().top);
  expect(topologyTop).toBeLessThan(await page.evaluate(() => window.innerHeight));
  await expect(page.getByText('Exact handoff evidence', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Hot window', exact: true }).click();
  await expect(page).toHaveURL(/from=[\d.]+&to=[\d.]+/);
  await expect(page.getByText('Only actors and links observed in this window')).toBeVisible();

  await page.getByRole('button', { name: 'Ask AI', exact: true }).click();
  const assistant = page.getByRole('dialog', { name: 'Ask your local AI' });
  await expect(assistant).toBeVisible();
  await expect(assistant.getByLabel('Local provider')).toBeVisible();
  await expect(assistant.getByText(/bounds the context/)).toBeVisible();
  await assistant.getByRole('button', { name: 'Close AI workspace' }).click();
  await expect(assistant).toBeHidden();
});

test('keeps the full system topology truthful while actor filters only focus evidence', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto('/?actor=root&view=map');
  await expect(page.getByRole('heading', { name: 'Agent topology' })).toBeVisible();
  const summary = page.locator('.topology .summary');
  await expect(summary).toContainText(/\d+ actors/);
  expect(Number((await summary.innerText()).match(/\d+/)?.[0] ?? 0)).toBeGreaterThan(1);
  await expect(page.getByText(/Filters dim evidence; they do not rewrite the topology/)).toBeVisible();
  await expect(page.locator('.topology .actor.muted').first()).toBeVisible();
  const stage = await page.locator('.topology .stage').evaluate((element) => ({ client: element.clientWidth, scroll: element.scrollWidth }));
  expect(stage.scroll).toBeLessThanOrEqual(stage.client + 1);

  const fitted = await page.locator('.topology .stage').evaluate((element) => {
    const stageRect = element.getBoundingClientRect();
    const actors = [...element.querySelectorAll<HTMLElement>('.actor')].map((actor) => actor.getBoundingClientRect());
    const bounds = {
      left: Math.min(...actors.map((actor) => actor.left)),
      right: Math.max(...actors.map((actor) => actor.right)),
      top: Math.min(...actors.map((actor) => actor.top)),
      bottom: Math.max(...actors.map((actor) => actor.bottom))
    };
    return {
      contained: actors.every((actor) => actor.left >= stageRect.left - 1
        && actor.right <= stageRect.right + 1
        && actor.top >= stageRect.top - 1
        && actor.bottom <= stageRect.bottom + 1),
      centerDeltaX: (bounds.left + bounds.right) / 2 - (stageRect.left + stageRect.right) / 2,
      centerDeltaY: (bounds.top + bounds.bottom) / 2 - (stageRect.top + stageRect.bottom) / 2,
      hasCenteredGrid: getComputedStyle(element).backgroundPosition.includes('50%')
        || getComputedStyle(element).backgroundPosition.includes('center'),
      stageRect: { left: stageRect.left, right: stageRect.right, top: stageRect.top, bottom: stageRect.bottom },
      graphTransform: getComputedStyle(element.querySelector<HTMLElement>('.graph')!).transform,
      zoom: element.getAttribute('data-zoom'),
      panX: element.getAttribute('data-pan-x'),
      panY: element.getAttribute('data-pan-y'),
      actorRects: actors.map((actor) => ({ left: actor.left, right: actor.right, top: actor.top, bottom: actor.bottom }))
    };
  });
  expect(fitted.contained, JSON.stringify(fitted)).toBe(true);
  expect(Math.abs(fitted.centerDeltaX)).toBeLessThanOrEqual(2);
  expect(Math.abs(fitted.centerDeltaY)).toBeLessThanOrEqual(2);
  expect(fitted.hasCenteredGrid).toBe(true);
});

test('rejects a missing trace link instead of substituting another execution', async ({ page }) => {
  await page.goto('/?trace=does-not-exist');
  await expect(page.getByText('Trace not found', { exact: true })).toBeVisible();
  await expect(page.getByText('does-not-exist')).toBeVisible();
  await expect(page.locator('.workspace')).toHaveCount(0);
});

test('traps and restores focus for the Ask AI dialog', async ({ page }) => {
  await page.goto('/');
  const trigger = page.getByRole('button', { name: 'Ask AI', exact: true });
  await trigger.focus();
  await trigger.click();
  const dialog = page.getByRole('dialog', { name: 'Ask your local AI' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Close AI workspace' })).toBeFocused();
  for (let index = 0; index < 12; index += 1) await page.keyboard.press('Tab');
  expect(await dialog.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test('closes the mobile inspector into the architecture workspace', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/?view=map');
  await page.getByRole('button', { name: 'Close inspector' }).click();
  await expect(page.getByRole('dialog', { name: 'Event inspector' })).toBeHidden();
  await expect(page.getByRole('heading', { name: 'Agent architecture' })).toBeVisible();
  await expect(page.locator('.trace-list')).toBeHidden();
});

test('contains the reporter and inspector across phone, tablet, and narrow desktop widths', async ({ page }) => {
  for (const [width, height] of [[320, 568], [390, 600], [680, 650], [681, 650], [768, 844], [1024, 700], [1180, 640]]) {
    await page.setViewportSize({ width, height });
    await page.goto('/?view=map&event=4');
    await page.locator('.inspector').waitFor({ state: 'visible' });
    const layout = await page.evaluate(() => {
      const inspector = document.querySelector('.inspector')?.getBoundingClientRect();
      const app = document.querySelector('#app')?.getBoundingClientRect();
      const workspace = document.querySelector('.workspace')?.getBoundingClientRect();
      const runShell = document.querySelector('.run-shell')?.getBoundingClientRect();
      return {
        viewport: window.innerWidth,
        documentWidth: document.documentElement.scrollWidth,
        appLeft: app?.left ?? -1,
        appRight: app?.right ?? -1,
        inspectorLeft: inspector?.left ?? -1,
        inspectorRight: inspector?.right ?? -1,
        inspectorWidth: inspector?.width ?? 0,
        workspaceHeight: workspace?.height ?? 0,
        runShellBottom: runShell?.bottom ?? 0,
        inspectorLayer: document.elementsFromPoint(Math.floor((inspector?.left ?? 0) + Math.min((inspector?.width ?? 0) / 2, 80)), Math.min(190, window.innerHeight - 1)).findIndex((element) => element.classList.contains('inspector')),
        clockLayer: document.elementsFromPoint(Math.floor((inspector?.left ?? 0) + Math.min((inspector?.width ?? 0) / 2, 80)), Math.min(190, window.innerHeight - 1)).findIndex((element) => element.classList.contains('density-bars'))
      };
    });
    expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewport);
    expect(layout.appLeft).toBeGreaterThanOrEqual(0);
    expect(layout.appRight).toBeLessThanOrEqual(layout.viewport + 1);
    expect(layout.inspectorWidth).toBeGreaterThan(0);
    expect(layout.inspectorLeft).toBeGreaterThanOrEqual(0);
    expect(layout.inspectorRight).toBeLessThanOrEqual(layout.viewport + 1);
    expect(layout.workspaceHeight).toBeGreaterThan(80);
    expect(layout.runShellBottom).toBeLessThanOrEqual(height + 1);
    expect(layout.inspectorLayer).toBeGreaterThanOrEqual(0);
    expect(layout.clockLayer === -1 || layout.inspectorLayer < layout.clockLayer).toBe(true);
  }
});

test('reserves at least half of a short phone for the active investigation', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 600 });
  await page.goto('/');
  const close = page.getByRole('button', { name: 'Close inspector' });
  if (await close.isVisible()) await close.click();
  const budget = await page.evaluate(() => {
    const workspace = document.querySelector('.workspace')?.getBoundingClientRect();
    const eventScroll = document.querySelector('.timeline-scroll')?.getBoundingClientRect();
    const tabbableDensityMarks = [...document.querySelectorAll('.density-bars button')]
      .filter((element) => (element as HTMLElement).tabIndex >= 0).length;
    return { workspace: workspace?.height ?? 0, events: eventScroll?.height ?? 0, tabbableDensityMarks };
  });
  expect(budget.workspace).toBeGreaterThanOrEqual(350);
  // Keep at least two full event rows visible below the compact investigation summary.
  expect(budget.events).toBeGreaterThanOrEqual(150);
  expect(budget.tabbableDensityMarks).toBe(0);
});

test('keeps mobile run chrome separate and puts the system canvas in the first viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 600 });
  await page.goto('/?view=map');
  const close = page.getByRole('button', { name: 'Close inspector' });
  if (await close.isVisible()) await close.click();
  await expect(page.getByRole('button', { name: 'Actors', exact: true })).toHaveAttribute('aria-pressed', 'false');
  await expect(page.getByLabel('Actor activity ribbons')).toHaveCount(0);
  const geometry = await page.evaluate(() => {
    const rect = (selector: string) => document.querySelector(selector)?.getBoundingClientRect();
    const brand = rect('.brand');
    const context = rect('.trace-context');
    const actions = rect('.app-actions');
    const connection = rect('.connection');
    const topology = rect('.topology .stage');
    const scope = rect('.architecture-scope');
    const overlaps = (a?: DOMRect, b?: DOMRect) => Boolean(a && b && a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top);
    return {
      headerOverlaps: [overlaps(brand, context), overlaps(context, actions), overlaps(actions, connection)],
      topologyTop: topology?.top ?? Infinity,
      scopeHeight: scope?.height ?? Infinity,
      documentWidth: document.documentElement.scrollWidth
    };
  });
  expect(geometry.headerOverlaps).toEqual([false, false, false]);
  expect(geometry.topologyTop).toBeLessThan(600);
  expect(geometry.scopeHeight).toBeLessThanOrEqual(62);
  expect(geometry.documentWidth).toBeLessThanOrEqual(390);
});

test('keeps the compact tablet header contained and readable from 681 through 863 pixels', async ({ page }) => {
  for (const width of [681, 768, 863]) {
    await page.setViewportSize({ width, height: 800 });
    await page.goto('/?view=analytics');
    await expect(page.locator('.trace-identity strong')).toBeVisible();

    const header = await page.evaluate(() => {
      const box = (selector: string) => document.querySelector(selector)?.getBoundingClientRect();
      const bar = box('.app-bar');
      const brand = box('.brand');
      const context = box('.trace-context');
      const actions = box('.app-actions');
      const connection = box('.connection');
      const title = box('.trace-identity strong');
      const stats = document.querySelector<HTMLElement>('.run-stats');
      const contained = (rect?: DOMRect) => Boolean(rect && bar
        && rect.left >= bar.left - 1 && rect.right <= bar.right + 1
        && rect.top >= bar.top - 1 && rect.bottom <= bar.bottom + 1);
      const overlaps = (left?: DOMRect, right?: DOMRect) => Boolean(left && right
        && left.left < right.right && left.right > right.left
        && left.top < right.bottom && left.bottom > right.top);
      return {
        barHeight: bar?.height ?? 0,
        contained: [brand, context, actions, connection].map(contained),
        overlaps: [overlaps(brand, context), overlaps(context, actions), overlaps(actions, connection)],
        titleHeight: title?.height ?? Infinity,
        statsDisplay: stats ? getComputedStyle(stats).display : 'missing',
        documentWidth: document.documentElement.scrollWidth
      };
    });

    expect(header.barHeight).toBe(80);
    expect(header.contained).toEqual([true, true, true, true]);
    expect(header.overlaps).toEqual([false, false, false]);
    expect(header.titleHeight).toBeLessThanOrEqual(20);
    expect(header.statsDisplay).toBe('none');
    expect(header.documentWidth).toBeLessThanOrEqual(width);
    await expect(page.getByRole('button', { name: 'Ask AI', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'More', exact: true })).toBeVisible();
  }
});

test('compacts desktop panes into functional rails without overlaying the workspace', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto('/');
  await page.getByRole('button', { name: 'Collapse trace list' }).click();
  await page.getByRole('button', { name: 'Collapse event inspector' }).click();
  await expect(page.getByRole('button', { name: 'Expand runs' })).toBeVisible();
  await expect(page.getByLabel('Compact event inspector')).toBeVisible();
  const rails = await page.evaluate(() => {
    const runs = document.querySelector('.trace-list')?.getBoundingClientRect();
    const inspector = document.querySelector('.inspector')?.getBoundingClientRect();
    const evidence = document.querySelector('.evidence-main')?.getBoundingClientRect();
    return { runs: runs?.width, inspector: inspector?.width, evidenceLeft: evidence?.left, evidenceRight: evidence?.right, viewport: innerWidth };
  });
  expect(rails.runs).toBe(48);
  expect(rails.inspector).toBe(52);
  expect(rails.evidenceLeft).toBe(48);
  expect(rails.evidenceRight).toBe(rails.viewport - 52);
  await page.getByRole('button', { name: 'Open Data' }).click();
  await expect(page.getByRole('tab', { name: /Data/ })).toHaveAttribute('aria-selected', 'true');
});

test('keeps the run clock visible above the event workspace with scoped filters', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto('/?kind=error&event=4&actor=reviewer');

  await expect(page.getByRole('button', { name: 'Events', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByText('Run activity', { exact: true })).toBeVisible();
  const fittedView = await page.evaluate(() => {
    const strip = document.querySelector('.architecture-view')?.getBoundingClientRect();
    const content = document.querySelector('.mode-content')?.getBoundingClientRect();
    return { stripBottom: strip?.bottom ?? 0, contentTop: content?.top ?? 0, contentBottom: content?.bottom ?? 0, viewport: window.innerHeight };
  });
  expect(fittedView.stripBottom).toBeLessThanOrEqual(fittedView.contentTop);
  expect(fittedView.contentBottom).toBeLessThanOrEqual(fittedView.viewport);
  expect(fittedView.contentBottom - fittedView.contentTop).toBeGreaterThan(200);

  await page.getByRole('button', { name: 'Hot window', exact: true }).click();
  await expect(page).toHaveURL(/from=[\d.]+&to=[\d.]+/);
  await expect(page).not.toHaveURL(/view=map/);
});

test('brushes, refines, and resets a URL-backed time crop', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto('/');
  await page.getByRole('button', { name: /multi-agent failure investigation/i }).click();
  const density = page.getByRole('group', { name: /Event density time series/ });
  const countBefore = Number(await page.getByRole('button', { name: 'all events', exact: true }).locator('b').innerText());
  const box = await density.boundingBox();
  expect(box).not.toBeNull();
  await page.mouse.move(box!.x + box!.width * .22, box!.y + box!.height / 2);
  await page.mouse.down();
  await page.mouse.move(box!.x + box!.width * .68, box!.y + box!.height / 2, { steps: 8 });
  await page.mouse.up();
  await expect(page).toHaveURL(/from=[\d.]+&to=[\d.]+/);
  const range = new URL(page.url()).searchParams;
  expect(Number(range.get('from'))).toBeLessThan(Number(range.get('to')));
  expect(Number(await page.getByRole('button', { name: 'all events', exact: true }).locator('b').innerText())).toBeLessThan(countBefore);
  await expect(page.getByRole('slider', { name: 'Range start' })).toBeVisible();
  await expect(page.getByRole('slider', { name: 'Range end' })).toBeVisible();
  const before = page.url();
  await page.getByRole('slider', { name: 'Range start' }).press('Shift+ArrowRight');
  await expect.poll(() => page.url()).not.toBe(before);
  const croppedUrl = page.url();
  const croppedRange = new URL(croppedUrl).searchParams;
  await page.reload();
  await expect(page.getByRole('slider', { name: 'Range start' })).toBeVisible();
  const reloadedRange = new URL(page.url()).searchParams;
  expect(reloadedRange.get('from')).toBe(croppedRange.get('from'));
  expect(reloadedRange.get('to')).toBe(croppedRange.get('to'));
  await page.getByRole('button', { name: 'Reset range', exact: true }).click();
  await expect(page).not.toHaveURL(/from=|to=/);
});

test('uses Premier dropdowns instead of native browser selects', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto('/');
  await page.getByRole('button', { name: 'More', exact: true }).click();
  await page.getByRole('menuitem', { name: /Compare runs/ }).click();
  const dialog = page.getByRole('dialog', { name: /Compare runs/ });
  const trigger = dialog.getByRole('button', { name: 'Comparison baseline' });
  await expect(trigger).toBeVisible();
  await trigger.click();
  const listbox = page.getByRole('listbox', { name: 'Comparison baseline options' });
  await expect(listbox).toBeVisible();
  await listbox.getByRole('option').first().press('Escape');
  await expect(dialog).toBeVisible();
  await expect(listbox).toBeHidden();
  await trigger.click();
  expect(await page.locator('select').count()).toBe(0);
  const menuBox = await listbox.boundingBox();
  expect(menuBox!.x).toBeGreaterThanOrEqual(0);
  expect(menuBox!.x + menuBox!.width).toBeLessThanOrEqual(1366);
  expect(menuBox!.y).toBeGreaterThanOrEqual(0);
  expect(menuBox!.y + menuBox!.height).toBeLessThanOrEqual(768);
  await listbox.getByRole('option').first().click();
  await expect(listbox).toBeHidden();
});

test('assigns one intentional vertical scroll owner to each center view', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 640 });
  await page.goto('/');
  await page.getByRole('button', { name: /multi-agent failure investigation/i }).click();
  for (const [mode, expectedOwner] of [['Events', '.timeline-scroll'], ['Analytics', '.mode-content.analytics-mode'], ['System', '.evidence-view.system-mode']]) {
    await page.getByRole('button', { name: mode, exact: true }).click();
    const ownership = await page.evaluate(() => {
      const inspect = (selector: string) => {
        const element = document.querySelector(selector);
        if (!element) return null;
        const style = getComputedStyle(element);
        return { selector, overflowY: style.overflowY, client: element.clientHeight, scroll: element.scrollHeight };
      };
      return ['.evidence-view.system-mode', '.mode-content.analytics-mode', '.timeline-scroll', '.analytics', '.architecture-view'].map(inspect).filter(Boolean);
    });
    const owners = ownership.filter((item) => item && ['auto', 'scroll'].includes(item.overflowY) && item.scroll > item.client + 2);
    expect(owners.map((item) => item!.selector)).toEqual([expectedOwner]);
  }
});

test('uses the full analytics viewport and gives added height to the activity chart', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await page.getByRole('button', { name: /Passing smoke run/ }).click();
  await page.getByRole('button', { name: 'Analytics', exact: true }).click();

  const measure = () => page.evaluate(() => {
    const rect = (selector: string) => document.querySelector(selector)?.getBoundingClientRect();
    const analytics = rect('.analytics');
    const grid = rect('.analytics-grid');
    const activity = rect('.activity-card');
    const breakdowns = rect('.breakdowns');
    const chart = rect('.activity-chart');
    const mode = document.querySelector<HTMLElement>('.mode-content.analytics-mode');
    return {
      analyticsBottom: analytics?.bottom ?? 0,
      gridBottom: grid?.bottom ?? 0,
      activityTop: activity?.top ?? 0,
      activityBottom: activity?.bottom ?? 0,
      breakdownsTop: breakdowns?.top ?? 0,
      breakdownsBottom: breakdowns?.bottom ?? 0,
      chartHeight: chart?.height ?? 0,
      horizontalOverflow: mode ? mode.scrollWidth - mode.clientWidth : Infinity,
      verticalOverflow: mode ? mode.scrollHeight - mode.clientHeight : Infinity
    };
  });

  const regular = await measure();
  expect(Math.abs(regular.analyticsBottom - regular.gridBottom)).toBeLessThanOrEqual(2);
  expect(Math.abs(regular.gridBottom - regular.activityBottom)).toBeLessThanOrEqual(2);
  expect(Math.abs(regular.gridBottom - regular.breakdownsBottom)).toBeLessThanOrEqual(2);
  expect(regular.horizontalOverflow).toBeLessThanOrEqual(1);

  await page.setViewportSize({ width: 1440, height: 1100 });
  const tall = await measure();
  expect(Math.abs(tall.analyticsBottom - tall.gridBottom)).toBeLessThanOrEqual(2);
  expect(tall.chartHeight).toBeGreaterThan(regular.chartHeight + 100);
  expect(tall.horizontalOverflow).toBeLessThanOrEqual(1);

  await page.setViewportSize({ width: 1366, height: 768 });
  const commonDesktop = await measure();
  expect(Math.abs(commonDesktop.activityTop - commonDesktop.breakdownsTop)).toBeLessThanOrEqual(2);
  expect(commonDesktop.horizontalOverflow).toBeLessThanOrEqual(1);
  expect(commonDesktop.verticalOverflow).toBeLessThanOrEqual(1);
});

test('does not carry failure-only filters into a passing run', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Actors', exact: true }).click();
  await page.getByRole('button', { name: /Focus reviewer, subagent/ }).click();
  await page.getByRole('button', { name: 'issues', exact: true }).click();
  await expect(page.getByText(/events in focus/)).toBeVisible();

  await page.getByRole('button', { name: /Passing smoke run/ }).click();

  await expect(page).not.toHaveURL(/kind=error/);
  await expect(page).not.toHaveURL(/actor=reviewer/);
  const allCount = await page.getByRole('button', { name: 'all events', exact: true }).locator('b').innerText();
  await expect(page.locator('.filter-count small')).toHaveText(`${allCount} scoped · ${allCount} total`);
  await expect(page.getByRole('option', { name: /process.stdout/ })).toBeVisible();
  await expect(page.getByRole('button', { name: 'models' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'tools' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'decisions' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'issues', exact: true })).toBeDisabled();
});

test('password protects both API and viewer', async ({ request }) => {
  expect((await fetch(`${e2eBaseUrl}/api/health`)).status).toBe(401);
  expect((await request.get('/api/health')).status()).toBe(200);
});
