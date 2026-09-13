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

async function captureValue(page: import('@playwright/test').Page, testId: string): Promise<string> {
  const value = page.getByTestId(testId);
  await expect(value).toHaveCount(1);
  return (await value.textContent() ?? '').trim();
}

async function expandEvidenceProvenance(page: import('@playwright/test').Page): Promise<void> {
  for (const group of ['Source & build', 'Identities & discoverability', 'Contract & policy']) {
    const summary = page.getByText(group, { exact: true });
    await expect(summary).toBeVisible();
    await summary.click();
  }
}

test('capture submission material only from live testnet evidence', async ({ page }) => {
  await mkdir(outputRoot, { recursive: true });
  await authenticateWithoutRenderingPassword(page);
  await page.goto('/');
  await expect(page.getByText('Operator session', { exact: true })).toBeVisible();

  await page.getByText('System readiness details', { exact: true }).click();
  const status = page.getByRole('region', { name: 'Live T3N operational status' });
  await expect(status).toBeVisible();
  await expect(status).toContainText('Operational');
  await expect(status).toContainText('Authenticated');
  await expect(status).toContainText('ACTIVE');
  await expect(status).not.toContainText(/UNKNOWN|NOT_GRANTED|REVOKED|Unavailable \/ incomplete/i);

  const files: string[] = [];
  files.push(await screenshot(page, '01-live-status.png'));

  await page.getByRole('button', { name: 'Evidence', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Execution proof at a glance' })).toBeVisible();
  await expect(page.getByTestId('evidence-network')).toContainText('TESTNET');
  await expect(page.getByTestId('evidence-fail-total')).toContainText('0');
  await expect(page.getByTestId('evidence-fail-total')).toContainText('FAIL');

  await expandEvidenceProvenance(page);
  const generatedAt = await captureValue(page, 'evidence-generated-at');
  const sourceCommit = await captureValue(page, 'evidence-source-commit');
  const sourceTree = await captureValue(page, 'evidence-source-tree');
  const contractId = await captureValue(page, 'evidence-contract-id');
  const contractVersion = await captureValue(page, 'evidence-contract-version');
  const wasmSha256 = await captureValue(page, 'evidence-wasm-sha256');
  const tenantDid = await captureValue(page, 'evidence-tenant-did');
  const proposalAgentDid = await captureValue(page, 'evidence-proposal-agent-did');
  const protectedExecutorDid = await captureValue(page, 'evidence-protected-executor-did');
  expect(sourceCommit).toMatch(/^[a-f0-9]{40}$/);
  expect(sourceTree).toBe('CLEAN');
  expect(tenantDid).not.toBe(proposalAgentDid);
  expect(tenantDid).not.toBe(protectedExecutorDid);
  expect(proposalAgentDid).not.toBe(protectedExecutorDid);
  expect(wasmSha256).toMatch(/^[a-f0-9]{64}$/);

  const redactRow = page.getByTestId('evidence-scenario-LIVE-DATA-MINIMIZATION');
  await expect(redactRow).toContainText('PASS');
  await redactRow.scrollIntoViewIfNeeded();
  const redactFile = resolve(outputRoot, '03-data-minimization.png');
  await redactRow.screenshot({ path: redactFile });
  files.push('03-data-minimization.png');

  await page.getByRole('button', { name: 'Protection flow', exact: true }).click();
  await page.getByRole('button', { name: /Credential compromised/i }).click();
  await page.getByRole('button', { name: 'Analyze with agent', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'DENY', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Agent proposal' })).toBeVisible();
  await expect(page.getByText('attacker.example', { exact: true })).toBeVisible();
  files.push(await screenshot(page, '02-real-ai-attack-deny.png'));

  await page.getByRole('button', { name: 'Prepare safe path', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'ALLOW', exact: true })).toBeVisible();
  await expect(page.getByText('postman-echo.com', { exact: true })).toBeVisible();
  files.push(await screenshot(page, '04-safe-allow.png'));

  await page.getByRole('button', { name: 'Authorize credential revocation', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Execute protected credential revocation', exact: true })).toBeVisible();
  files.push(await screenshot(page, '05-human-authorization.png'));

  let remediationVerified = false;
  if (allowRemediation) {
    await page.getByRole('button', { name: 'Execute protected credential revocation', exact: true }).click();
    const verifyButton = page.getByRole('button', { name: 'Verify external state', exact: true });
    if (await verifyButton.isVisible()) await verifyButton.click();
    await expect(page.getByText(/Independent read-back verified the expected external state/i)).toBeVisible();
    const remediationStatus = page.getByRole('region', { name: 'Remediation execution and verification status' });
    await expect(remediationStatus).toContainText('VERIFIED');
    await expect(remediationStatus).toContainText('COMPLETED');
    remediationVerified = true;
    files.push(await screenshot(page, '06-remediation-verified.png'));
  }

  await page.getByRole('button', { name: 'Evidence', exact: true }).click();
  await expect(page.getByTestId('evidence-fail-total')).toContainText('0');
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
    sourceCommit,
    sourceTree,
    contractId,
    contractVersion,
    wasmSha256,
    tenantDid,
    proposalAgentDid,
    protectedExecutorDid,
    remediationVerified,
    screenshots: files,
    video: videoName,
  };
  const serialized = `${JSON.stringify(metadata, null, 2)}\n`;
  assertNoSecretLeak(serialized, [
    operatorPassword,
    process.env.T3N_API_KEY,
    process.env.T3N_AGENT_API_KEY,
    process.env.T3N_EXECUTOR_API_KEY,
    process.env.SECURITY_API_KEY,
    process.env.AI_API_KEY,
    process.env.GATEWAY_SERVICE_TOKEN,
    process.env.REMEDIATION_CAPABILITY_KEY,
    process.env.AUDIT_INTEGRITY_KEY,
    process.env.EVIDENCE_SENTINEL_SECRET,
  ]);
  await writeFile(resolve(outputRoot, 'capture-metadata.json'), serialized, 'utf8');
});
