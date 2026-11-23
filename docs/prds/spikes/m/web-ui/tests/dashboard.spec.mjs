import { expect, test } from '@playwright/test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { fixtureCode, literalText, session, snapshot } from '../fixtures/workspace.mjs';

const build = new URL('../build/', import.meta.url);
let server;
let origin;

test.beforeAll(async () => {
  const html = await readFile(new URL('200.html', build));
  const manifest = JSON.parse(await readFile(new URL('csp-manifest.json', build)));
  const csp = [
    "default-src 'none'",
    `script-src 'self' 'sha256-${manifest.inline_script_sha256}'`,
    "style-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'none'"
  ].join('; ');
  server = createServer(async (request, response) => {
    const url = request.url;
    if (/^\/dashboard\/(projects|sandboxes|threads)$/.test(url)) {
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': csp,
        'Cache-Control': 'no-store'
      }).end(html);
    } else if (/^\/_app\/immutable\/(?:[\w-]+\/)*[\w.-]+\.(js|css)$/.test(url)) {
      try {
        const asset = await readFile(new URL(url.slice(1), build));
        response.writeHead(200, {
          'Content-Type': url.endsWith('.js') ? 'text/javascript' : 'text/css'
        }).end(asset);
      } catch {
        response.writeHead(404).end();
      }
    } else response.writeHead(404).end();
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  origin = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

async function mockPrivateApi(page, { authorized = false, workspace = snapshot } = {}) {
  let generation = 1;
  await page.route(origin + '/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    expect(request.headers()['x-oc-ui']).toBe('1');
    if (path === '/api/auth/session') {
      await route.fulfill(authorized ? { json: session(generation) } : { status: 401 });
    } else if (path === '/api/auth/exchange') {
      expect(request.method()).toBe('POST');
      expect(request.postDataJSON()).toEqual({ code: fixtureCode });
      authorized = true;
      await route.fulfill({ json: session(++generation) });
    } else if (path === '/api/auth/logout') {
      expect(request.method()).toBe('POST');
      expect(request.headers()['x-oc-csrf']).toBe(session().csrf_token);
      authorized = false;
      await route.fulfill({ status: 204 });
    } else if (path === '/api/v1/workspace') {
      await route.fulfill(authorized ? { json: workspace(generation) } : { status: 403 });
    } else {
      throw new Error('Unexpected fixture API request');
    }
  });
}

test('production fallback boots in Chromium under enforcing CSP and supports keyboard selection', async ({ page }) => {
  await mockPrivateApi(page);
  await page.addInitScript(() => {
    window.fixtureCspViolations = [];
    document.addEventListener('securitypolicyviolation', (event) => {
      window.fixtureCspViolations.push(event.violatedDirective);
    });
  });
  const response = await page.goto(origin + '/dashboard/projects');
  expect(response.headers()['content-security-policy']).toContain("script-src 'self' 'sha256-");
  expect(await response.text()).not.toContain('Fixture Workshop');
  const code = page.getByLabel('One-use code');
  await expect(code).toHaveAttribute('type', 'password');
  await expect(page.locator('form')).toHaveCount(0);
  await code.fill('bad-code');
  await code.press('Enter');
  await expect(page.getByRole('status')).toHaveText('Enter a valid one-use code');
  await code.fill(fixtureCode);
  await code.press('Enter');
  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();

  const project = page.getByRole('button', { name: /Fixture Workshop/ });
  await project.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Sandboxes' })).toBeFocused();
  const announcer = page.locator('#svelte-announcer');
  await expect(announcer).toHaveText('Sandboxes · Workspace dashboard');
  const sandbox = page.getByRole('button', { name: /Local build running/ });
  await sandbox.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Threads' })).toBeFocused();
  await expect(page.getByText(literalText.replace('\n', ' '), { exact: true })).toBeVisible();
  await expect(page.locator('article a, article b')).toHaveCount(0);
  await expect(page.getByText('Synthetic worker report')).toBeVisible();
  await expect(page.getByText('Workspace ready for review')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Build thread' })).toHaveAttribute('aria-pressed', 'true');

  await page.getByRole('button', { name: 'Review thread' }).press('Enter');
  await expect(page.getByText('No messages.')).toBeVisible();
  await expect(announcer).toHaveText('Threads · Workspace dashboard');
  await expect(announcer).toHaveAttribute('aria-live', 'assertive');
  await expect(announcer).toHaveAttribute('aria-atomic', 'true');
  await expect(announcer).toHaveCSS('position', 'absolute');
  await expect(announcer).toHaveCSS('width', '1px');
  expect(await page.evaluate(() => window.fixtureCspViolations)).toEqual([]);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length, document.cookie])).toEqual([0, 0, '']);
  expect(page.url()).toBe(origin + '/dashboard/threads');
});

test('fresh deep links and reload use authenticated snapshots and history after logout stays empty', async ({ page }) => {
  await mockPrivateApi(page, { authorized: true });
  await page.goto(origin + '/dashboard/threads');
  await expect(page.getByText('Synthetic worker report')).toBeVisible();
  await page.reload();
  await expect(page.getByText('Synthetic worker report')).toBeVisible();
  expect(await page.evaluate(() => {
    const keys = Object.keys(sessionStorage).sort();
    const history = JSON.parse(sessionStorage.getItem('sveltekit:history-info') ?? '{}');
    return {
      localKeys: Object.keys(localStorage),
      keys,
      snapshotsEmpty: ['sveltekit:snapshot', 'sveltekit:navigation-snapshot'].every(
        (key) => sessionStorage.getItem(key) === '{}'
      ),
      numericHistory: Object.entries(history).every(([index, { scroll, resetIndex, ...rest }]) =>
        /^\d+$/.test(index) && Object.keys(rest).length === 0 &&
        (resetIndex === undefined || Number.isSafeInteger(resetIndex)) &&
        (scroll === undefined || (Object.keys(scroll).length === 2 &&
          Number.isFinite(scroll.x) && Number.isFinite(scroll.y)))
      )
    };
  })).toEqual({
    localKeys: [],
    keys: ['sveltekit:history-info', 'sveltekit:navigation-snapshot', 'sveltekit:snapshot'],
    snapshotsEmpty: true,
    numericHistory: true
  });
  await page.getByRole('link', { name: 'Projects', exact: true }).click();
  await page.getByRole('button', { name: /Fixture Archive/ }).click();
  await expect(page.getByRole('button', { name: /Offline review offline/ })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Open the dashboard' })).toBeVisible();
  for (const navigate of [() => page.goBack(), () => page.goForward()]) {
    await navigate();
    await expect(page.getByRole('heading', { name: 'Open the dashboard' })).toBeVisible();
    await expect(page.getByText('Synthetic worker report')).toHaveCount(0);
    await expect(page.getByText('Fixture Archive')).toHaveCount(0);
  }
});

test('invalid projection clears the view and a bounded retry recovers', async ({ page }) => {
  let malformed = true;
  await mockPrivateApi(page, {
    authorized: true,
    workspace: (generation) => {
      const valid = snapshot(generation);
      return malformed ? { ...valid, projects: 'x'.repeat(33 * 1024) } : valid;
    }
  });
  await page.goto(origin + '/dashboard/sandboxes');
  await expect(page.getByRole('status')).toHaveText('Workspace unavailable');
  await expect(page.getByText('Local build')).toHaveCount(0);
  malformed = false;
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByRole('button', { name: /Local build running/ })).toBeVisible();
});

test('pagehide clears private DOM synchronously before session revalidation', async ({ page }) => {
  await mockPrivateApi(page, { authorized: true });
  await page.goto(origin + '/dashboard/threads');
  await expect(page.getByText('Synthetic worker report')).toBeVisible();
  expect(await page.evaluate(() => {
    window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
    return document.body.innerText.includes('Synthetic worker report');
  })).toBe(false);
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await expect(page.getByText('Synthetic worker report')).toBeVisible();
});

test('ready rows clear after a wall-clock jump without hiding the page', async ({ page }) => {
  await mockPrivateApi(page, { authorized: true });
  await page.goto(origin + '/dashboard/threads');
  await expect(page.getByText('Synthetic worker report')).toBeVisible();
  await page.evaluate(() => {
    const later = Date.now() + 60_001;
    const paused = performance.now();
    Date.now = () => later;
    performance.now = () => paused;
  });
  await expect(page.getByRole('status')).toHaveText('Session expired', { timeout: 3000 });
  await expect(page.getByText('Synthetic worker report')).toHaveCount(0);
});
