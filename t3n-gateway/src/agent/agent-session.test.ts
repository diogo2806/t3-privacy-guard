import assert from 'node:assert/strict';
import test from 'node:test';
import type { T3nClient } from '@terminal3/t3n-sdk';
import type { GatewayConfig } from '../config/env.js';
import type { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { AgentSession, type AgentSessionDependencies } from './agent-session.js';

const config = { network: 'testnet', agentApiKey: null } as GatewayConfig;
const trustFloorStore = {} as TrustManifestFloorStore;
const secpKey = `0x${'ab'.repeat(32)}`;
const orgAgentKey = 't3n_key_agent01.secret_value_1234567890';
const agentDid = 'did:t3n:agent123';

function fakeClient(): T3nClient {
  return {
    executeAndDecode: async () => ({ transport: 'session' }),
    checkDelegation: async () => ({ authorised: true }),
  } as unknown as T3nClient;
}

function baseDependencies(): AgentSessionDependencies {
  return {
    authenticateSecp256k1: async () => ({ client: fakeClient(), did: agentDid, trustManifestVersion: 7 }),
    authenticateOrgAgent: async () => ({ did: agentDid, trustManifestVersion: 7 }),
    invokeOrgAgent: async <T>() => ({ transport: 'stateless' } as T),
    checkOrgAgentDelegation: async () => ({ authorised: true }),
  };
}

test('keeps 0x credentials on the secp256k1 session transport', async () => {
  let secpCalls = 0;
  let orgAgentCalls = 0;
  const dependencies = baseDependencies();
  dependencies.authenticateSecp256k1 = async () => {
    secpCalls += 1;
    return { client: fakeClient(), did: agentDid, trustManifestVersion: 7 };
  };
  dependencies.authenticateOrgAgent = async () => {
    orgAgentCalls += 1;
    return { did: agentDid, trustManifestVersion: 7 };
  };

  const session = new AgentSession(config, trustFloorStore, secpKey, 'Agent', dependencies);
  await session.connect();

  assert.equal(secpCalls, 1);
  assert.equal(orgAgentCalls, 0);
  assert.equal(session.getAgentDid(), agentDid);
  assert.equal(session.getStatus().ready, true);
  assert.equal((await session.getClient().executeAndDecode<{ transport: string }>({
    contract_id: 'z:tenant:privacy-guard', contract_version: '1', function_name: 'evaluate-action',
  })).transport, 'session');
});

test('uses the stateless keyed transport for organization-owned t3n_key credentials', async () => {
  let secpCalls = 0;
  let orgAgentCalls = 0;
  let invokeCalls = 0;
  let delegationCalls = 0;
  const dependencies = baseDependencies();
  dependencies.authenticateSecp256k1 = async () => {
    secpCalls += 1;
    throw new Error('private-key authentication must not run');
  };
  dependencies.authenticateOrgAgent = async (apiKey) => {
    orgAgentCalls += 1;
    assert.equal(apiKey, orgAgentKey);
    return { did: agentDid, trustManifestVersion: 9 };
  };
  dependencies.invokeOrgAgent = async <T>(apiKey) => {
    invokeCalls += 1;
    assert.equal(apiKey, orgAgentKey);
    return { transport: 'stateless' } as T;
  };
  dependencies.checkOrgAgentDelegation = async (apiKey) => {
    delegationCalls += 1;
    assert.equal(apiKey, orgAgentKey);
    return { authorised: true };
  };

  const session = new AgentSession(config, trustFloorStore, orgAgentKey, 'Agent', dependencies);
  await session.connect();
  const result = await session.getClient().executeAndDecode<{ transport: string }>({
    contract_id: 'z:tenant:privacy-guard', contract_version: '1', function_name: 'evaluate-action',
  });
  const delegation = await session.getClient().checkDelegation({
    contract: 'z:tenant:privacy-guard', pii_did: 'did:t3n:tenant', functions: ['evaluate-action'], scopes: ['incident_id'],
  }) as { authorised: boolean };

  assert.equal(secpCalls, 0);
  assert.equal(orgAgentCalls, 1);
  assert.equal(invokeCalls, 1);
  assert.equal(delegationCalls, 1);
  assert.equal(result.transport, 'stateless');
  assert.equal(delegation.authorised, true);
  assert.deepEqual(session.getStatus(), {
    configured: true,
    connected: true,
    ready: true,
    agentDid,
    network: 'testnet',
    trustAnchorVerified: true,
    trustManifestVersion: 9,
    lastError: null,
  });
});

test('rejects malformed t3n_key credentials before authentication', async () => {
  const malformed = 't3n_key_missing-secret';
  const session = new AgentSession(config, trustFloorStore, malformed, 'Agent', baseDependencies());

  await assert.rejects(session.connect(), /Malformed T3N organization-owned agent credential/);
  assert.equal(session.getStatus().ready, false);
  assert.equal(session.getStatus().agentDid, null);
  assert.equal(JSON.stringify(session.getStatus()).includes(malformed), false);
});

test('fails closed and redacts an opaque credential from authentication failures', async () => {
  const dependencies = baseDependencies();
  dependencies.authenticateOrgAgent = async () => {
    throw new Error(`Unauthorized credential ${orgAgentKey}`);
  };
  const session = new AgentSession(config, trustFloorStore, orgAgentKey, 'Agent', dependencies);

  await assert.rejects(session.connect(), (error: Error) => {
    assert.equal(error.message.includes(orgAgentKey), false);
    assert.match(error.message, /^AUTHENTICATION:/);
    return true;
  });
  const status = session.getStatus();
  assert.equal(status.ready, false);
  assert.equal(status.connected, false);
  assert.equal(JSON.stringify(status).includes(orgAgentKey), false);
});

test('sanitizes stateless invoke network failures without changing readiness identity', async () => {
  const dependencies = baseDependencies();
  dependencies.invokeOrgAgent = async () => {
    throw new Error(`fetch failed for ${orgAgentKey}`);
  };
  const session = new AgentSession(config, trustFloorStore, orgAgentKey, 'Protected executor', dependencies);
  await session.connect();

  await assert.rejects(
    session.getClient().executeAndDecode({ contract_id: 'z:tenant:privacy-guard', contract_version: '1', function_name: 'execute-remediation' }),
    (error: Error) => {
      assert.equal(error.message.includes(orgAgentKey), false);
      assert.match(error.message, /^NETWORK:/);
      return true;
    },
  );
  assert.equal(session.getStatus().ready, true);
  assert.equal(JSON.stringify(session.getStatus()).includes(orgAgentKey), false);
});
