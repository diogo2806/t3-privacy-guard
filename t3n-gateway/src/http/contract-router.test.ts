import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import express from 'express';
import type { PolicyEvaluator } from '../contract/policy-evaluator.js';
import type { PolicyDecision } from '../contract/privacy-guard-contract.js';
import { createContractRouter } from './contract-router.js';

const SERVICE_TOKEN = 'gateway-service-token-1234567890123456';

const decision: PolicyDecision = {
  request_id: 'req-001',
  decision: 'REDACT',
  reason_code: 'DATA_MINIMIZATION_REQUIRED',
  reason: 'Action is allowed only after removing data or private references unnecessary for the declared purpose',
  allowed_fields: ['incident_id'],
  redacted_fields: ['employee_department'],
  allowed_private_refs: [],
  redacted_private_refs: [],
  policy_version: '2026-09-16.1',
  policy_hash: 'b'.repeat(64),
  requires_human_authorization: true,
};

const t3nMustNotBeCalled = async (): Promise<never> => { throw new Error('T3N contract must not be called for evaluation'); };

async function withRouter<T>(evaluator: PolicyEvaluator, run: (baseUrl: string) => Promise<T>): Promise<T> {
  const app = express();
  app.use(express.json());
  app.use('/internal/contracts/privacy-guard', createContractRouter(
    { identity: t3nMustNotBeCalled, remediate: t3nMustNotBeCalled, verifyRemediation: t3nMustNotBeCalled },
    { verifyAndConsume: () => { throw new Error('not used'); } },
    SERVICE_TOKEN,
    { status: t3nMustNotBeCalled },
    evaluator,
  ));
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    return await run(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  } finally {
    server.close();
    await once(server, 'close');
  }
}

function evaluate(baseUrl: string, token = SERVICE_TOKEN) {
  return fetch(`${baseUrl}/internal/contracts/privacy-guard/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Gateway-Service-Token': token },
    body: JSON.stringify({ request_id: 'req-001', action: 'revoke-credential', resource: 'credential:cred-42', purpose: 'incident-remediation', fields: ['incident_id'] }),
  });
}

test('evaluate is served by the configured runtime, not the T3N contract service', async () => {
  const received: unknown[] = [];
  const selfHosted: PolicyEvaluator = { runtime: 'selfhosted', evaluate: async (request) => { received.push(request); return decision; } };
  await withRouter(selfHosted, async (baseUrl) => {
    const response = await evaluate(baseUrl);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), decision);
  });
  assert.equal(received.length, 1);
});

test('evaluate fails closed with 503 when the runtime is unavailable', async () => {
  const unavailable: PolicyEvaluator = { runtime: 'selfhosted', evaluate: async () => { throw new Error('connection refused'); } };
  await withRouter(unavailable, async (baseUrl) => {
    const response = await evaluate(baseUrl);
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: 'Policy evaluation is unavailable' });
  });
});

test('evaluate still requires the internal service token', async () => {
  const selfHosted: PolicyEvaluator = { runtime: 'selfhosted', evaluate: async () => decision };
  await withRouter(selfHosted, async (baseUrl) => {
    assert.equal((await evaluate(baseUrl, 'wrong-token-1234567890123456789012345')).status, 401);
  });
});
