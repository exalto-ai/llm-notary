import react from '@vitejs/plugin-react';
import { playwright } from '@vitest/browser-playwright';
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

const localBrowser = process.env.PLAYWRIGHT_EXECUTABLE_PATH;

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(process.cwd(), 'src')
    }
  },
  plugins: [react()],
  test: {
    include: ['src/local-dashboard/**/*.browser.test.tsx'],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(localBrowser ? { launchOptions: { executablePath: localBrowser } } : undefined),
      instances: [{ browser: 'chromium' }],
      viewport: { width: 1280, height: 900 }
    }
  }
});
