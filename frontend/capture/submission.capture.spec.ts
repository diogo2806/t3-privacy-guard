import { expect, test } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { assertNoSecretLeak } from '../../t3n-gateway/src/evidence/leak-detector.ts';

const baseURL = process.env.CAPTURE_BASE_URL;
const operatorUsername = process.env.CAPTURE_OPERATOR_USERNAME;
const operatorPassword = process.env.CAPTURE_OPERATOR_PASSWORD;
if (!baseURL || !operatorUsername || !operatorPassword) {
  throw new Error('CAPTURE_BASE_URL, CAPTURE_OPERATOR_USERNAME and CAPTURE_OPERATOR_PASSWORD are required');
}
const parsedBaseUrl = new URL(baseURL);
if (parsedBaseUrl.username || parsedBaseUrl.password) throw new Error('CAPTURE_BASE_URL must not embed credentials');
const safeBaseUrl = `${parsedBaseUrl.origin}${parsedBaseUrl.pathname}`;
const outputRoot = resolve(process.cwd(), process.env.CAPTURE_OUTPUT_DIR ?? '../artifacts/submission-capture');
const allowRemediation = process.env.CAPTURE_ALLOW_REMEDIATION === 'true';

async function authenticateWithoutRenderingPassword(page: import('@playwright/test').Page): Promise<void> {
  const request = page.context().request;
  const csrfResponse = await request.get(new URL('/api/auth/csrf', baseURL).toString());
  expect(csrfResponse.ok()).toBeTruthy();
  const csrf = await csrfResponse.json() as { token: string; headerName: string };
  const login = await request.post(new URL('/api/auth/login', baseURL).toString(), {
    data: { username: operatorUsername, password: operatorPassword },
    headers: { [csrf.headerName]: csrf.token },
  });
  expect(login.ok()).toBeTruthy();
}

async function screenshot(page: import('@playwright/test').Page, filename: string): Promise<string> {
  const path = resolve(outputRoot, filename);
  await page.screenshot({ path, fullPage: true });
  return filename;
}

async function metadataValue(page: import('@playwright/test').Page, label: string): Promise<string> {
  const row = page.locator('.evidence-metadata > div').filter({ has: page.locator('dt', { hasText: label }) }).first();
  return (await row.locator('dd').innerText()).trim();
}

test('capture submission material only from live testnet evidence', async ({ page }) => {
  await mkdir(outputRoot, { recursive: true });
  await authenticateWithoutRenderingPassword(page);
  await page.goto('/');
  await expect(page.getByText('Operator session', { exact: true })).toBeVisible();

  const status = page.getByRole('region', { name: 'Live T3N operational status' });
  await expect(status).toBeVisible();
  await expect(status).toContainText('Authenticated');
  await expect(status).toContainText('Resolved');
  await expect(status).toContainText('ACTIVE');
  await expect(status).not.toContainText(/UNKNOWN|NOT_GRANTED|REVOKED|Unavailable/i);

  const files: string[] = [];
  files.push(await screenshot(page, '01-live-status.png'));

  await page.getByRole('button', { name: 'Evidence', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'T3N testnet execution' })).toBeVisible();
  await expect(page.getByText('T3N_TESTNET', { exact: true })).toBeVisible();
  await expect(page.getByText('0 FAIL', { exact: true })).toBeVisible();

  const generatedAt = await metadataValue(page, 'Generated');
  const contractId = await metadataValue(page, 'Contract');
  const contractVersion = await metadataValue(page, 'Version');
  const wasmSha256 = await metadataValue(page, 'WASM SHA-256');
  const tenantDid = await metadataValue(page, 'Tenant DID');
  const agentDid = await metadataValue(page, 'Agent DID');
  expect(tenantDid).not.toBe(agentDid);
  expect(wasmSha256).toMatch(/^[a-f0-9]{64}$/);

  const redactRow = page.locator('.evidence-row').filter({ hasText: 'LIVE-DATA-MINIMIZATION' });
  await expect(redactRow).toContainText('PASS');
  await redactRow.scrollIntoViewIfNeeded();
  const redactFile = resolve(outputRoot, '03-data-minimization.png');
  await redactRow.screenshot({ path: redactFile });
  files.push('03-data-minimization.png');

  await page.getByRole('button', { name: 'Demo', exact: true }).click();
  await page.getByRole('button', { name: /Run attack scenario/i }).click();
  await expect(page.getByRole('heading', { name: 'DENY', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Agent proposal' })).toBeVisible();
  await expect(page.getByText('attacker.example', { exact: true })).toBeVisible();
  files.push(await screenshot(page, '02-real-ai-attack-deny.png'));

  await page.getByRole('button', { name: /Prepare safe remediation/i }).click();
  await expect(page.getByRole('heading', { name: 'ALLOW', exact: true })).toBeVisible();
  await expect(page.getByText('postman-echo.com', { exact: true })).toBeVisible();
  files.push(await screenshot(page, '04-safe-allow.png'));

  await page.getByRole('button', { name: 'Authorize remediation' }).click();
  await expect(page.getByRole('button', { name: 'Execute protected remediation' })).toBeVisible();
  files.push(await screenshot(page, '05-human-authorization.png'));

  let remediationExecuted = false;
  if (allowRemediation) {
    await page.getByRole('button', { name: 'Execute protected remediation' }).click();
    await expect(page.getByText(/Protected remediation completed/i)).toBeVisible();
    remediationExecuted = true;
    files.push(await screenshot(page, '06-remediation-completed.png'));
  }

  await page.getByRole('button', { name: 'Evidence', exact: true }).click();
  await expect(page.getByText('0 FAIL', { exact: true })).toBeVisible();
  files.push(await screenshot(page, '07-evidence-center.png'));

  const video = page.video();
  await page.close();
  const videoName = 'submission-demo.webm';
  if (video) await video.saveAs(resolve(outputRoot, videoName));

  const metadata = {
    capturedAt: new Date().toISOString(),
    baseUrl: safeBaseUrl,
    evidenceSource: 'T3N_TESTNET',
    evidenceGeneratedAt: generatedAt,
    contractId,
    contractVersion,
    wasmSha256,
    tenantDid,
    agentDid,
    remediationExecuted,
    screenshots: files,
    video: videoName,
  };
  const serialized = `${JSON.stringify(metadata, null, 2)}\n`;
  assertNoSecretLeak(serialized, [
    operatorPassword,
    process.env.T3N_API_KEY,
    process.env.T3N_AGENT_API_KEY,
    process.env.SECURITY_API_KEY,
    process.env.AI_API_KEY,
    process.env.GATEWAY_SERVICE_TOKEN,
    process.env.REMEDIATION_CAPABILITY_KEY,
    process.env.EVIDENCE_SENTINEL_SECRET,
  ]);
  await writeFile(resolve(outputRoot, 'capture-metadata.json'), serialized, 'utf8');
});
