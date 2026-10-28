import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import express from 'express';
import type { SelfHostedGatewayConfig } from '../config/env.js';
import { GuardRuntimeClient } from './guard-runtime-client.js';
import { createSelfHostedApp } from './self-hosted-app.js';
import { SelfHostedRuntime } from './self-hosted-runtime.js';

const SERVICE_TOKEN = 'gateway-service-token-1234567890123456';
const PROPOSAL_TOKEN = 'guard-runtime-proposal-token-0123456789abcdef';
const EXECUTOR_TOKEN = 'guard-runtime-executor-token-0123456789abcdef';
const ACTIVITY_HASH = 'c'.repeat(64);
const RULE = (purpose: string, refs: string[] = []) => ({
  purpose,
  allowed_fields: ['credential_id', 'incident_id', 'reason'],
  allowed_hosts: ['security-api.internal'],
  allowed_private_refs: refs,
  requires_host: true,
  requires_human_authorization: true,
});

interface FakeRuntime {
  readonly url: string;
  readonly received: { path: string; body: Record<string, unknown> }[];
  close(): Promise<void>;
}

/** Stand-in for guard-runtime speaking its HTTP contract, so the whole gateway is exercised without T3N. */
async function startFakeRuntime(): Promise<FakeRuntime> {
  const received: { path: string; body: Record<string, unknown> }[] = [];
  const callers: Record<string, { id: string; functions: string[] }> = {
    [PROPOSAL_TOKEN]: { id: 'agent:proposal', functions: ['evaluate-action'] },
    [EXECUTOR_TOKEN]: { id: 'agent:executor', functions: ['execute-remediation', 'verify-remediation'] },
  };
  const app = express();
  app.use(express.json());
  app.use((request, response, next) => {
    const caller = callers[(request.header('Authorization') ?? '').replace(/^Bearer /, '')];
    if (!caller) { response.status(401).json({ error: 'UNAUTHENTICATED' }); return; }
    response.locals.caller = caller;
    next();
  });
  app.get('/v1/caller', (_request, response) => response.json(response.locals.caller));
  app.get('/v1/readiness', (_request, response) => response.json({
    contract_id: 'guard-runtime', contract_version: '1.0.0', tenant_id: 'acme',
    policy_state: 'AVAILABLE', policy_version: '2026-10-28.1', policy_hash: 'b'.repeat(64),
    policy_document: { version: '2026-10-28.1', actions: {
      'create-incident': { ...RULE('incident-recording'), allowed_hosts: [], requires_host: false },
      'notify-security': RULE('incident-notification', ['verified_email']),
      'revoke-credential': RULE('incident-remediation'),
    } },
    endpoint_configuration_valid: true, execution_host: 'security-api.internal', verification_host: 'security-api.internal',
    insecure_http_allowed: false, credential_configured: true, verification_key_configured: true, private_profile_configured: true,
  }));
  app.get('/v1/activity', (_request, response) => response.json({
    events: [{ sequence: 7, hash: ACTIVITY_HASH, timestampMs: 1, callerType: 'agent', actorDid: 'agent:proposal', onBehalfOfDid: 'acme', contractId: 'guard-runtime', function: 'evaluate-action', outcome: 'success', roles: ['evaluate-action'] }],
    nextSequence: null,
    complete: true,
  }));
  app.post('/v1/functions/:fn', (request, response) => {
    const body = request.body as Record<string, unknown>;
    received.push({ path: request.params.fn, body });
    response.setHeader('X-Activity-Sequence', '7');
    response.setHeader('X-Activity-Hash', ACTIVITY_HASH);
    if (request.params.fn === 'evaluate-action') {
      response.json({
        request_id: body.request_id, decision: 'ALLOW', reason_code: 'POLICY_ALLOW', reason: 'ok',
        allowed_fields: body.fields, redacted_fields: [], allowed_private_refs: [], redacted_private_refs: [],
        policy_version: '2026-10-28.1', policy_hash: 'b'.repeat(64), requires_human_authorization: true,
      });
    } else if (request.params.fn === 'execute-remediation') {
      if (body.approved_host === 'changed.example') {
        response.status(422).json({ error: 'CONTRACT_REJECTED', reason: 'EXECUTION_DESTINATION_CHANGED' });
        return;
      }
      response.json({ request_id: body.request_id, status: 'PENDING_VERIFICATION', http_code: 202, operation_id: 'op-1', policy_version: body.policy_version, policy_hash: body.policy_hash });
    } else {
      response.json({ request_id: body.request_id, status: 'VERIFIED', observed_state: 'REVOKED' });
    }
  });
  const server: Server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    received,
    close: async () => { server.close(); await once(server, 'close'); },
  };
}

function config(runtimeUrl: string): SelfHostedGatewayConfig {
  return {
    port: 0,
    gatewayServiceToken: SERVICE_TOKEN,
    remediationAuthorizationPublicKeySpki: 'unused',
    remediationAuthorizationKeyId: 'primary',
    remediationReplayStorePath: 'unused',
    aiProvider: 'disabled',
    aiApiUrl: null,
    aiApiKey: null,
    aiModel: null,
    guardRuntime: { url: runtimeUrl, proposalAgentId: 'agent:proposal', proposalToken: PROPOSAL_TOKEN, executorId: 'agent:executor', executorToken: EXECUTOR_TOKEN, timeoutMs: 2_000 },
  };
}

async function withGateway<T>(runtimeUrl: string, run: (call: (method: string, path: string, body?: unknown, headers?: Record<string, string>) => Promise<Response>) => Promise<T>): Promise<T> {
  const cfg = config(runtimeUrl);
  const runtime = new SelfHostedRuntime(new GuardRuntimeClient(cfg.guardRuntime), cfg.guardRuntime);
  const app = createSelfHostedApp(cfg, runtime, { verifyAndConsume: () => undefined });
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    return await run((method, path, body, headers = {}) => fetch(`${base}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json', 'X-Gateway-Service-Token': SERVICE_TOKEN, ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }));
  } finally {
    server.close();
    await once(server, 'close');
  }
}

const remediationBody = (approvedHost = 'security-api.internal', executorDid = 'agent:executor') => ({
  incident_id: 'inc-1', action_id: 'act-1', decision_id: 'dec-1', request_id: 'req-1', action: 'revoke-credential',
  resource: 'credential:cred-42', purpose: 'incident-remediation', approved_host: approvedHost,
  fields: ['incident_id', 'credential_id', 'reason'], normal_payload: { incident_id: 'inc-1', credential_id: 'cred-42', reason: 'leak' },
  private_refs: [], policy_version: '2026-10-28.1', policy_hash: 'b'.repeat(64), executor_did: executorDid,
  operator_principal_hash: 'd'.repeat(64), authorization_recorded_at: 1,
});

test('self-hosted gateway serves the backend-facing status API from guard-runtime', async () => {
  const runtime = await startFakeRuntime();
  try {
    await withGateway(runtime.url, async (call) => {
      assert.deepEqual(await (await call('GET', '/health')).json(), { status: 'UP', service: 't3n-gateway', trustRuntime: 'selfhosted' });
      assert.equal((await call('GET', '/internal/t3n/status', undefined, { 'X-Gateway-Service-Token': 'wrong-token-1234567890123456789012' })).status, 401);
      assert.deepEqual(await (await call('GET', '/internal/t3n/status')).json(), { connected: true, ready: true, tenantDid: 'acme', network: 'selfhosted' });
      assert.equal((await (await call('GET', '/internal/agent/status')).json()).agentDid, 'agent:proposal');
      assert.equal((await (await call('GET', '/internal/executor/status')).json()).executorDid, 'agent:executor');

      const proposal = await (await call('GET', '/internal/agent/delegations/guard-runtime')).json();
      assert.equal(proposal.memberState, 'ACTIVE');
      assert.equal(proposal.effectiveState, 'ACTIVE');
      const executor = await (await call('GET', '/internal/executor/delegations/guard-runtime')).json();
      assert.deepEqual(executor.allowedHosts, ['security-api.internal']);
      assert.equal(executor.effectiveState, 'ACTIVE');

      const readiness = await (await call('GET', '/internal/contracts/privacy-guard/enterprise-integration-readiness')).json();
      assert.equal(readiness.state, 'READY');
      assert.deepEqual(readiness.evaluationOnlyActions, ['create-incident']);
      assert.deepEqual(await (await call('GET', '/internal/contracts/privacy-guard/identity')).json(), { contractId: 'guard-runtime', contractVersion: '1.0.0' });
      assert.equal((await (await call('GET', '/internal/agent/registration')).json()).state, 'NOT_REGISTERED');
      assert.equal((await (await call('GET', '/internal/t3n/activity?limit=10')).json()).events[0].function, 'evaluate-action');
    });
  } finally {
    await runtime.close();
  }
});

test('self-hosted gateway evaluates, remediates and verifies through guard-runtime with the right identities', async () => {
  const runtime = await startFakeRuntime();
  try {
    await withGateway(runtime.url, async (call) => {
      const decision = await (await call('POST', '/internal/contracts/privacy-guard/evaluate', {
        request_id: 'req-1', action: 'revoke-credential', resource: 'credential:cred-42', purpose: 'incident-remediation',
        host: 'security-api.internal', fields: ['incident_id'], agent_did: 'agent:attacker',
      })).json();
      assert.equal(decision.decision, 'ALLOW');
      assert.equal(decision.activity_sequence, 7);
      assert.equal(runtime.received[0].body.agent_did, 'agent:proposal');

      const remediation = await call('POST', '/internal/contracts/privacy-guard/remediate', remediationBody(), { 'X-Remediation-Capability': 'v2.payload.signature' });
      assert.equal(remediation.status, 200);
      assert.equal((await remediation.json()).operation_id, 'op-1');
      const executed = runtime.received.find((entry) => entry.path === 'execute-remediation')!.body;
      assert.equal(executed.executor_did, 'agent:executor');
      assert.equal(executed.agent_did, 'agent:proposal');
      assert.equal(executed.authorization_proof, 'v2.payload.signature');

      const changed = await call('POST', '/internal/contracts/privacy-guard/remediate', remediationBody('changed.example'), { 'X-Remediation-Capability': 'v2.payload.signature' });
      assert.equal(changed.status, 409);
      assert.equal((await changed.json()).code, 'EXECUTION_DESTINATION_CHANGED');

      const wrongExecutor = await call('POST', '/internal/contracts/privacy-guard/remediate', remediationBody('security-api.internal', 'agent:other'), { 'X-Remediation-Capability': 'v2.payload.signature' });
      assert.equal(wrongExecutor.status, 403);

      const verification = await (await call('POST', '/internal/contracts/privacy-guard/verify-remediation', {
        request_id: 'req-1', operation_id: 'op-1', action: 'revoke-credential', expected_state: 'REVOKED',
      })).json();
      assert.equal(verification.status, 'VERIFIED');
    });
  } finally {
    await runtime.close();
  }
});

test('self-hosted gateway fails closed when guard-runtime is down', async () => {
  const runtime = await startFakeRuntime();
  const url = runtime.url;
  await runtime.close();
  await withGateway(url, async (call) => {
    assert.equal((await call('GET', '/internal/t3n/status')).status, 503);
    assert.equal((await call('GET', '/internal/executor/status')).status, 503);
    assert.equal((await (await call('GET', '/internal/agent/delegations/guard-runtime')).json()).memberState, 'UNKNOWN');
    const readiness = await (await call('GET', '/internal/contracts/privacy-guard/enterprise-integration-readiness')).json();
    assert.equal(readiness.state, 'UNKNOWN');
    assert.equal(readiness.diagnosticCode, 'TRUST_RUNTIME_UNAVAILABLE');
    const evaluation = await call('POST', '/internal/contracts/privacy-guard/evaluate', { request_id: 'r', action: 'a', resource: 'r', purpose: 'p', fields: [] });
    assert.equal(evaluation.status, 503);
  });
});
