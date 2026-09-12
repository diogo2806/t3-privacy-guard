import { defineConfig, devices } from '@playwright/test';
import { resolve } from 'node:path';

const baseURL = process.env.CAPTURE_BASE_URL;
if (!baseURL) throw new Error('CAPTURE_BASE_URL is required');

const outputRoot = resolve(process.cwd(), process.env.CAPTURE_OUTPUT_DIR ?? '../artifacts/submission-capture');

export default defineConfig({
  testDir: '.',
  testMatch: 'submission.capture.spec.ts',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  outputDir: resolve(outputRoot, 'test-results'),
  reporter: [['line']],
  use: {
    ...devices['Desktop Chrome'],
    baseURL,
    trace: 'off',
    screenshot: 'off',
    video: { mode: 'on', size: { width: 1440, height: 900 } },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
