const { test, expect } = require('@playwright/test');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

let outputDirectory;
let dashboardPath;

test.beforeAll(() => {
  outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'screamless-dashboard-'));
  dashboardPath = path.join(outputDirectory, 'dashboard.html');

  const binary = process.env.SCREAMLESS_BIN;
  if (binary) {
    execFileSync(binary, [
      '--db', ':memory:', 'dashboard', '--hostname', 'drag-test.local',
      '--output', dashboardPath,
    ], { stdio: 'inherit' });
  } else {
    execFileSync('cargo', [
      'run', '--locked', '--quiet', '--', '--db', ':memory:', 'dashboard',
      '--hostname', 'drag-test.local', '--output', dashboardPath,
    ], { stdio: 'inherit' });
  }
});

test.afterAll(() => {
  if (outputDirectory) {
    fs.rmSync(outputDirectory, { recursive: true, force: true });
  }
});

test('dragging a graph node preserves its DOM element and updates its position', async ({ page }) => {
  await page.goto(pathToFileURL(dashboardPath).href);
  const node = page.locator('#graph-svg g[data-node-id]').first();
  await expect(node).toBeVisible();
  await node.scrollIntoViewIfNeeded();

  await node.evaluate(element => {
    window.__screamlessDragNode = element;
    window.__screamlessDragTransform = element.getAttribute('transform');
  });
  const bounds = await node.boundingBox();
  expect(bounds).not.toBeNull();

  const startX = bounds.x + bounds.width / 2;
  const startY = bounds.y + bounds.height / 2;
  await page.mouse.move(startX, startY);
  await page.mouse.down();
  await page.mouse.move(startX + 70, startY + 45, { steps: 5 });
  await page.mouse.up();

  const result = await node.evaluate(element => ({
    sameElement: element === window.__screamlessDragNode,
    before: window.__screamlessDragTransform,
    after: element.getAttribute('transform'),
  }));
  expect(result.sameElement).toBe(true);
  expect(result.after).not.toBe(result.before);
});
