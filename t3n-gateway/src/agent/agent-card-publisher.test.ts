import assert from 'node:assert/strict';
import test from 'node:test';
import {
  publishAgentCardToOrganization,
  type AgentCardPublicationDependencies,
} from './agent-card-publisher.js';

function createDependencies(
  factory: (client: unknown, baseUrl: string) => unknown,
): AgentCardPublicationDependencies {
  return {
    createOrgDataClientFromSession: factory as AgentCardPublicationDependencies['createOrgDataClientFromSession'],
    getNodeUrl: (() => 'https://cn-api.testnet.t3n.example') as AgentCardPublicationDependencies['getNodeUrl'],
  };
}

test('publishes an Agent Card with separate organization owner and authenticated agent DIDs', async () => {
  const adminClient = { kind: 'tenant-admin-client' } as unknown as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0];
  const calls: Array<{ operation: string; input: unknown }> = [];
  let factoryClient: unknown;
  let factoryBaseUrl: string | undefined;

  const dependencies = createDependencies((client, baseUrl) => {
    factoryClient = client;
    factoryBaseUrl = baseUrl;
    return {
      agentCardSet: async (input: unknown) => { calls.push({ operation: 'set', input }); },
      agentCardPublish: async (input: unknown) => { calls.push({ operation: 'publish', input }); },
    };
  });

  await publishAgentCardToOrganization({
    ownerDid: 'did:t3n:organization123',
    agentDid: 'did:t3n:proposal456',
    card: '{"name":"Privacy Guard"}',
    adminClient,
  }, dependencies);

  assert.equal(factoryClient, adminClient);
  assert.equal(factoryBaseUrl, 'https://cn-api.testnet.t3n.example');
  assert.deepEqual(calls, [
    {
      operation: 'set',
      input: {
        ownerDid: 'did:t3n:organization123',
        agentDid: 'did:t3n:proposal456',
        card: '{"name":"Privacy Guard"}',
      },
    },
    {
      operation: 'publish',
      input: {
        ownerDid: 'did:t3n:organization123',
        agentDid: 'did:t3n:proposal456',
      },
    },
  ]);
});

test('does not reinterpret the Proposal Agent credential as an administrative client credential', async () => {
  const adminClient = { kind: 'tenant-admin-client' } as unknown as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0];
  const proposalAgentKey = 't3n_key_proposal.secret-value';
  let factoryArguments: unknown[] = [];

  const dependencies = createDependencies((...args) => {
    factoryArguments = args;
    return {
      agentCardSet: async () => undefined,
      agentCardPublish: async () => undefined,
    };
  });

  await publishAgentCardToOrganization({
    ownerDid: 'did:t3n:organization123',
    agentDid: 'did:t3n:proposal456',
    card: '{}',
    adminClient,
    secrets: [proposalAgentKey],
  }, dependencies);

  assert.equal(factoryArguments.length, 2);
  assert.equal(factoryArguments[0], adminClient);
  assert.equal(factoryArguments.includes(proposalAgentKey), false);
});

test('sanitizes Tenant/Admin and organization-owned agent credentials from publication failures', async () => {
  const tenantKey = `0x${'a'.repeat(64)}`;
  const proposalAgentKey = 't3n_key_proposal.super-secret-value';
  const dependencies = createDependencies(() => ({
    agentCardSet: async () => {
      throw new Error(`forbidden ${tenantKey} ${proposalAgentKey}`);
    },
    agentCardPublish: async () => undefined,
  }));

  await assert.rejects(
    publishAgentCardToOrganization({
      ownerDid: 'did:t3n:organization123',
      agentDid: 'did:t3n:proposal456',
      card: '{}',
      adminClient: {} as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0],
      secrets: [tenantKey, proposalAgentKey],
    }, dependencies),
    (error: unknown) => error instanceof Error
      && error.message.includes('T3N Agent Card publication failed (AUTHENTICATION)')
      && !error.message.includes(tenantKey)
      && !error.message.includes(proposalAgentKey)
      && error.message.includes('[REDACTED_PRIVATE_KEY]')
      && error.message.includes('[REDACTED_T3N_API_KEY]'),
  );
});
