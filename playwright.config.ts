import { defineConfig } from '@playwright/test';

const e2ePort = Number(process.env.PREMIER_E2E_PORT ?? 4318);
const e2eBaseUrl = `http://127.0.0.1:${e2ePort}`;

export default defineConfig({
  testDir: './tests',
  testIgnore: 'docs/**',
  timeout: 30_000,
  expect: { timeout: 5_000 },
  use: {
    baseURL: e2eBaseUrl,
    httpCredentials: { username: 'premier', password: 'e2e-secret' },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure'
  },
  webServer: {
    command: 'node scripts/e2e-server.mjs',
    url: `${e2eBaseUrl}/api/health`,
    timeout: 180_000,
    reuseExistingServer: false
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }]
});
