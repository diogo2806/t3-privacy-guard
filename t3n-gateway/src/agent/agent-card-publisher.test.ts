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

const ownerDid = 'did:t3n:organization123';
const agentDid = 'did:t3n:proposal456';
const adminDid = 'did:t3n:tenant-admin789';

test('publishes an Agent Card without rewriting writers when the authenticated admin is already present', async () => {
  const adminClient = { kind: 'tenant-admin-client' } as unknown as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0];
  const calls: Array<{ operation: string; input: unknown }> = [];
  let factoryClient: unknown;
  let factoryBaseUrl: string | undefined;

  const dependencies = createDependencies((client, baseUrl) => {
    factoryClient = client;
    factoryBaseUrl = baseUrl;
    return {
      writersGet: async (input: unknown) => {
        calls.push({ operation: 'writers-get', input });
        return { writers: [adminDid] };
      },
      setWriters: async (input: unknown) => { calls.push({ operation: 'writers-set', input }); },
      agentCardSet: async (input: unknown) => { calls.push({ operation: 'set', input }); },
      agentCardPublish: async (input: unknown) => { calls.push({ operation: 'publish', input }); },
    };
  });

  await publishAgentCardToOrganization({
    ownerDid,
    agentDid,
    adminDid,
    card: '{"name":"Privacy Guard"}',
    adminClient,
  }, dependencies);

  assert.equal(factoryClient, adminClient);
  assert.equal(factoryBaseUrl, 'https://cn-api.testnet.t3n.example');
  assert.deepEqual(calls, [
    {
      operation: 'writers-get',
      input: {
        orgDid: ownerDid,
        scope: 'agent-cards',
      },
    },
    {
      operation: 'set',
      input: {
        ownerDid,
        agentDid,
        card: '{"name":"Privacy Guard"}',
      },
    },
    {
      operation: 'publish',
      input: {
        ownerDid,
        agentDid,
      },
    },
  ]);
});

test('preserves existing writers and adds only the authenticated admin before setting the Agent Card', async () => {
  const calls: Array<{ operation: string; input: unknown }> = [];
  const existingWriter = 'did:t3n:existing-writer';
  const dependencies = createDependencies(() => ({
    writersGet: async (input: unknown) => {
      calls.push({ operation: 'writers-get', input });
      return { writers: [existingWriter] };
    },
    setWriters: async (input: unknown) => { calls.push({ operation: 'writers-set', input }); },
    agentCardSet: async (input: unknown) => { calls.push({ operation: 'set', input }); },
    agentCardPublish: async (input: unknown) => { calls.push({ operation: 'publish', input }); },
  }));

  await publishAgentCardToOrganization({
    ownerDid,
    agentDid,
    adminDid,
    card: '{}',
    adminClient: {} as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0],
  }, dependencies);

  assert.deepEqual(calls, [
    {
      operation: 'writers-get',
      input: { orgDid: ownerDid, scope: 'agent-cards' },
    },
    {
      operation: 'writers-set',
      input: {
        orgDid: ownerDid,
        scope: 'agent-cards',
        writers: [existingWriter, adminDid],
      },
    },
    {
      operation: 'set',
      input: { ownerDid, agentDid, card: '{}' },
    },
    {
      operation: 'publish',
      input: { ownerDid, agentDid },
    },
  ]);
});

test('deduplicates writers while preserving their canonical values and order', async () => {
  const calls: Array<{ operation: string; input: unknown }> = [];
  const existingWriter = 'did:t3n:existing-writer';
  const dependencies = createDependencies(() => ({
    writersGet: async () => ({ writers: [existingWriter, ` ${existingWriter} `, adminDid, adminDid] }),
    setWriters: async (input: unknown) => { calls.push({ operation: 'writers-set', input }); },
    agentCardSet: async (input: unknown) => { calls.push({ operation: 'set', input }); },
    agentCardPublish: async (input: unknown) => { calls.push({ operation: 'publish', input }); },
  }));

  await publishAgentCardToOrganization({
    ownerDid,
    agentDid,
    adminDid,
    card: '{}',
    adminClient: {} as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0],
  }, dependencies);

  assert.deepEqual(calls[0], {
    operation: 'writers-set',
    input: {
      orgDid: ownerDid,
      scope: 'agent-cards',
      writers: [existingWriter, adminDid],
    },
  });
  assert.deepEqual(calls.map((call) => call.operation), ['writers-set', 'set', 'publish']);
});

test('fails closed before setting the card when the current writer list cannot be read', async () => {
  let cardSetCalled = false;
  const dependencies = createDependencies(() => ({
    writersGet: async () => { throw new Error('temporary writer read failure'); },
    setWriters: async () => undefined,
    agentCardSet: async () => { cardSetCalled = true; },
    agentCardPublish: async () => undefined,
  }));

  await assert.rejects(
    publishAgentCardToOrganization({
      ownerDid,
      agentDid,
      adminDid,
      card: '{}',
      adminClient: {} as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0],
    }, dependencies),
    /T3N Agent Card publication failed/,
  );
  assert.equal(cardSetCalled, false);
});

test('fails closed before setting the card when the writer response is invalid', async () => {
  let cardSetCalled = false;
  const dependencies = createDependencies(() => ({
    writersGet: async () => ({ writers: null }),
    setWriters: async () => undefined,
    agentCardSet: async () => { cardSetCalled = true; },
    agentCardPublish: async () => undefined,
  }));

  await assert.rejects(
    publishAgentCardToOrganization({
      ownerDid,
      agentDid,
      adminDid,
      card: '{}',
      adminClient: {} as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0],
    }, dependencies),
    /writer response is invalid/,
  );
  assert.equal(cardSetCalled, false);
});

test('fails closed before setting the card when the writer ACL cannot be updated', async () => {
  let cardSetCalled = false;
  const dependencies = createDependencies(() => ({
    writersGet: async () => ({ writers: [] }),
    setWriters: async () => { throw new Error('writer update denied'); },
    agentCardSet: async () => { cardSetCalled = true; },
    agentCardPublish: async () => undefined,
  }));

  await assert.rejects(
    publishAgentCardToOrganization({
      ownerDid,
      agentDid,
      adminDid,
      card: '{}',
      adminClient: {} as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0],
    }, dependencies),
    /T3N Agent Card publication failed/,
  );
  assert.equal(cardSetCalled, false);
});

test('does not publish when setting the Agent Card fails after writer reconciliation', async () => {
  let publishCalled = false;
  const dependencies = createDependencies(() => ({
    writersGet: async () => ({ writers: [adminDid] }),
    setWriters: async () => undefined,
    agentCardSet: async () => { throw new Error('card set failed'); },
    agentCardPublish: async () => { publishCalled = true; },
  }));

  await assert.rejects(
    publishAgentCardToOrganization({
      ownerDid,
      agentDid,
      adminDid,
      card: '{}',
      adminClient: {} as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0],
    }, dependencies),
    /T3N Agent Card publication failed/,
  );
  assert.equal(publishCalled, false);
});

test('does not reinterpret the Proposal Agent credential as an administrative client credential', async () => {
  const adminClient = { kind: 'tenant-admin-client' } as unknown as Parameters<AgentCardPublicationDependencies['createOrgDataClientFromSession']>[0];
  const proposalAgentKey = 't3n_key_proposal.secret-value';
  let factoryArguments: unknown[] = [];

  const dependencies = createDependencies((...args) => {
    factoryArguments = args;
    return {
      writersGet: async () => ({ writers: [adminDid] }),
      setWriters: async () => undefined,
      agentCardSet: async () => undefined,
      agentCardPublish: async () => undefined,
    };
  });

  await publishAgentCardToOrganization({
    ownerDid,
    agentDid,
    adminDid,
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
    writersGet: async () => ({ writers: [adminDid] }),
    setWriters: async () => undefined,
    agentCardSet: async () => {
      throw new Error(`forbidden ${tenantKey} ${proposalAgentKey}`);
    },
    agentCardPublish: async () => undefined,
  }));

  await assert.rejects(
    publishAgentCardToOrganization({
      ownerDid,
      agentDid,
      adminDid,
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
