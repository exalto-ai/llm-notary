import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(appRoot, '../..');
const outputDir = resolve(repoRoot, 'docs/images/local-dashboard');
const port = Number(process.env.LLM_NOTARY_DOCS_SCREENSHOT_PORT ?? 4175);
const origin = `http://127.0.0.1:${port}`;

mkdirSync(outputDir, { recursive: true });

const server = spawn(
  resolve(appRoot, 'node_modules/.bin/vite'),
  ['--mode', 'local-dashboard', '--host', '127.0.0.1', '--port', String(port), '--strictPort'],
  { cwd: appRoot, stdio: ['ignore', 'pipe', 'inherit'] }
);

async function waitForServer() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`Vite exited with status ${server.exitCode}`);
    try {
      const response = await fetch(`${origin}/local.html`);
      if (response.ok) return;
    } catch {
      // Vite is still starting.
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`Timed out waiting for ${origin}`);
}

async function fixturePage(browser, { scheme, viewport, route }) {
  const context = await browser.newContext({ viewport, deviceScaleFactor: 1 });
  await context.addInitScript((colorScheme) => {
    window.localStorage.setItem('llm-notary-dashboard-color-scheme', colorScheme);
  }, scheme);
  const page = await context.newPage();
  await page.goto(`${origin}/local.html?fixture=docs&${route}`, { waitUntil: 'networkidle' });
  await page.emulateMedia({ colorScheme: scheme === 'dark' ? 'dark' : 'light', reducedMotion: 'reduce' });
  return { context, page };
}

async function capture(browser, spec) {
  const { context, page } = await fixturePage(browser, spec);
  if (spec.prepare) await spec.prepare(page);
  await page.screenshot({ path: resolve(outputDir, spec.file), fullPage: true });
  await context.close();
  process.stdout.write(`Captured docs/images/local-dashboard/${spec.file}\n`);
}

try {
  await waitForServer();
  const browser = await chromium.launch({ headless: true });
  try {
    const desktop = { width: 1440, height: 1000 };
    await capture(browser, {
      file: 'overview-light.png', scheme: 'light', viewport: desktop, route: 'view=overview'
    });
    await capture(browser, {
      file: 'captures-dark.png', scheme: 'dark', viewport: desktop,
      route: 'view=captures&id=cap-20260728-safety-review'
    });
    await capture(browser, {
      file: 'finalization-retry.png', scheme: 'light', viewport: desktop,
      route: 'view=finalizations&id=op-finalize-benchmark'
    });
    await capture(browser, {
      file: 'trace-verification.png', scheme: 'dark', viewport: desktop,
      route: 'view=traces&id=cap-20260727-research-brief',
      prepare: async (page) => {
        await page.getByRole('button', { name: 'Verify now' }).click();
        await page.getByRole('tab', { name: 'Verification' }).click();
        await page.getByRole('tab', { name: 'Verification', selected: true }).waitFor();
        await page.getByText('Verification passed').waitFor();
        await page.evaluate(() => new Promise((resolveFrame) => {
          requestAnimationFrame(() => requestAnimationFrame(resolveFrame));
        }));
      }
    });
    await capture(browser, {
      file: 'mobile-navigation.png', scheme: 'light', viewport: { width: 390, height: 844 },
      route: 'view=captures&id=cap-20260728-knowledge-eval',
      prepare: async (page) => {
        await page.getByRole('button', { name: 'Open navigation' }).click();
        await page.getByRole('navigation', { name: 'Local dashboard' }).last().waitFor();
      }
    });
  } finally {
    await browser.close();
  }
} finally {
  server.kill('SIGTERM');
}
