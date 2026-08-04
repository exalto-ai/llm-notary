import react from '@vitejs/plugin-react';
import { playwright } from '@vitest/browser-playwright';
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

const localBrowser = process.env.PLAYWRIGHT_EXECUTABLE_PATH;

export default defineConfig({
  define: { __PUBLIC_ORIGIN__: JSON.stringify('https://llm-notary.example') },
  optimizeDeps: { include: ['cmdk', 'openapi-fetch', 'react-dom/client', 'react-markdown'] },
  resolve: { alias: { '@': resolve(process.cwd(), 'src') } },
  plugins: [react()],
  test: {
    include: ['src/Site.browser.test.jsx'],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(localBrowser ? { launchOptions: { executablePath: localBrowser } } : undefined),
      instances: [{ browser: 'chromium' }],
      viewport: { width: 1280, height: 900 }
    }
  }
});
