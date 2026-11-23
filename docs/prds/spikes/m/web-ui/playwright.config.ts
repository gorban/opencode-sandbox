import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'tests',
  testMatch: '**/*.spec.mjs',
  workers: 1,
  use: { browserName: 'chromium', serviceWorkers: 'block', viewport: { width: 390, height: 800 } }
});
