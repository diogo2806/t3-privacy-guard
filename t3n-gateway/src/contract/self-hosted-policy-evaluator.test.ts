import assert from 'node:assert/strict';
import test from 'node:test';
import type { PolicyEvaluationInput } from './policy-evaluator.js';
import { SelfHostedPolicyEvaluator, type GuardRuntimeConfig } from './self-hosted-policy-evaluator.js';

const config: GuardRuntimeConfig = {
  url: 'http://guard-runtime:3101/',
  token: 'guard-runtime-token-0123456789abcdef0123',
  agentId: 'agent:proposal',
  timeoutMs: 5000,
};

const input: PolicyEvaluationInput = {
  request_id: 'req-001',
  action: 'revoke-credential',
  resource: 'credential:cred-42',
  purpose: 'incident-remediation',
  host: 'postman-echo.com',
  fields: ['incident_id', 'credential_id', 'reason'],
};

function decision(overrides: Record<string, unknown> = {}) {
  return {
    request_id: 'req-001',
    decision: 'ALLOW',
    reason_code: 'POLICY_ALLOW',
    reason: 'Action and requested data satisfy the active versioned policy',
    allowed_fields: ['credential_id', 'incident_id', 'reason'],
    redacted_fields: [],
    allowed_private_refs: [],
    redacted_private_refs: [],
    policy_version: '2026-09-16.1',
    policy_hash: 'b'.repeat(64),
    requires_human_authorization: true,
    ...overrides,
  };
}

function fakeFetch(status: number, body: unknown) {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
  return { impl, calls };
}

test('self-hosted evaluation sends the contract wire format authenticated as the configured caller', async () => {
  const { impl, calls } = fakeFetch(200, decision());
  const result = await new SelfHostedPolicyEvaluator(config, impl).evaluate(input);

  assert.equal(result.decision, 'ALLOW');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'http://guard-runtime:3101/v1/functions/evaluate-action');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.redirect, 'error');
  assert.equal((calls[0].init.headers as Record<string, string>).Authorization, `Bearer ${config.token}`);
  const body = JSON.parse(String(calls[0].init.body));
  assert.equal(body.agent_did, 'agent:proposal');
  assert.deepEqual(body.private_refs, []);
  assert.deepEqual(body.fields, input.fields);
});

test('a client-supplied agent_did never reaches the guard runtime', async () => {
  const { impl, calls } = fakeFetch(200, decision());
  const forged = { ...input, agent_did: 'agent:attacker' } as PolicyEvaluationInput;
  await new SelfHostedPolicyEvaluator(config, impl).evaluate(forged);
  assert.equal(JSON.parse(String(calls[0].init.body)).agent_did, 'agent:proposal');
});

test('guard runtime errors fail closed without echoing the caller token', async () => {
  for (const status of [400, 401, 403, 413, 500]) {
    const { impl } = fakeFetch(status, { error: 'X' });
    await assert.rejects(
      new SelfHostedPolicyEvaluator(config, impl).evaluate(input),
      (error: unknown) => error instanceof Error && error.message.includes(String(status)) && !error.message.includes(config.token),
    );
  }
});

test('responses that are not a well-formed policy decision are rejected', async () => {
  for (const body of [{}, decision({ decision: 'MAYBE' }), decision({ policy_hash: 'short' }), decision({ allowed_fields: 'incident_id' })]) {
    const { impl } = fakeFetch(200, body);
    await assert.rejects(new SelfHostedPolicyEvaluator(config, impl).evaluate(input), /invalid policy decision/);
  }
});

test('an unreachable guard runtime surfaces as an error', async () => {
  const impl = (async () => { throw new TypeError('fetch failed'); }) as typeof fetch;
  await assert.rejects(new SelfHostedPolicyEvaluator(config, impl).evaluate(input), TypeError);
});
