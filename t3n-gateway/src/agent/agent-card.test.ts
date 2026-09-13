import assert from 'node:assert/strict';
import test from 'node:test';
import type { AgentSession } from './agent-session.js';
import { AgentCardRegistry, buildAgentCard, buildAgentCardForSession, serializeAgentCard, validateResolvedAgentCard, type AgentCardFetch } from './agent-card.js';

const AGENT_DID = 'did:t3n:0123456789abcdef0123456789abcdef01234567';
const OTHER_DID = 'did:t3n:89abcdef0123456789abcdef0123456789abcdef';

function fakeSession(did = AGENT_DID): AgentSession {
  return { getAgentDid: () => did } as unknown as AgentSession;
}

function fetchResponse(status: number, body = ''): AgentCardFetch {
  return async () => ({ ok: status >= 200 && status < 300, status, text: async () => body });
}

test('builder reads the canonical Agent DID from the authenticated session and advertises only the DID service', () => {
  const card = buildAgentCardForSession(fakeSession());
  assert.equal(card.services.length, 1);
  assert.deepEqual(card.services[0], { name: 'DID', endpoint: AGENT_DID, version: 'v1' });
  assert.equal(card.x402Support, false);
  assert.equal(card.active, true);
  assert.deepEqual(card.supportedTrust, []);
});

test('builder rejects non-canonical or hard-coded-looking DID input', () => {
  assert.throws(() => buildAgentCard('did:t3n:agent'), /canonical did:t3n identifier/);
});

test('serialized card contains no credential-shaped metadata', () => {
  const serialized = serializeAgentCard(buildAgentCard(AGENT_DID));
  assert.doesNotMatch(serialized, /T3N_AGENT_API_KEY|api[_-]?key|private[_-]?key|password|secret|token/i);
});

test('resolved card with matching DID becomes REGISTERED', async () => {
  const body = serializeAgentCard(buildAgentCard(AGENT_DID));
  const result = await new AgentCardRegistry(fakeSession(), fetchResponse(200, body), () => 'https://node.example/').verify();
  assert.equal(result.state, 'REGISTERED');
  assert.equal(result.agentDid, AGENT_DID);
  assert.deepEqual(result.services, ['DID']);
  assert.match(result.cardSha256 ?? '', /^[a-f0-9]{64}$/);
});

test('missing public card becomes NOT_REGISTERED', async () => {
  const result = await new AgentCardRegistry(fakeSession(), fetchResponse(404), () => 'https://node.example/').verify();
  assert.equal(result.state, 'NOT_REGISTERED');
  assert.equal(result.cardUri, null);
});

test('resolved card for a different DID becomes MISMATCH', async () => {
  const body = serializeAgentCard(buildAgentCard(OTHER_DID));
  const result = await new AgentCardRegistry(fakeSession(), fetchResponse(200, body), () => 'https://node.example/').verify();
  assert.equal(result.state, 'MISMATCH');
});

test('unsupported service or secret metadata is rejected', () => {
  const card = JSON.parse(serializeAgentCard(buildAgentCard(AGENT_DID))) as Record<string, unknown>;
  card.services = [{ name: 'MCP', endpoint: 'https://mcp.example', version: '2025-06-18' }];
  assert.throws(() => validateResolvedAgentCard(AGENT_DID, JSON.stringify(card)), /unsupported service/);

  const secretCard = JSON.parse(serializeAgentCard(buildAgentCard(AGENT_DID))) as Record<string, unknown>;
  secretCard.apiKey = 'synthetic-secret-value';
  assert.throws(() => validateResolvedAgentCard(AGENT_DID, JSON.stringify(secretCard)), /sensitive metadata key|unsupported metadata field/);

  const hiddenSecretCard = JSON.parse(serializeAgentCard(buildAgentCard(AGENT_DID))) as Record<string, unknown>;
  hiddenSecretCard.description = `public metadata ${'0x' + 'a'.repeat(64)}`;
  assert.throws(() => validateResolvedAgentCard(AGENT_DID, JSON.stringify(hiddenSecretCard)), /private-key-shaped metadata/);
});

test('inactive card becomes MISMATCH', async () => {
  const card = JSON.parse(serializeAgentCard(buildAgentCard(AGENT_DID))) as Record<string, unknown>;
  card.active = false;
  const result = await new AgentCardRegistry(fakeSession(), fetchResponse(200, JSON.stringify(card)), () => 'https://node.example/').verify();
  assert.equal(result.state, 'MISMATCH');
});

test('network failure becomes UNAVAILABLE and never REGISTERED', async () => {
  const failingFetch: AgentCardFetch = async () => { throw new Error('offline'); };
  const result = await new AgentCardRegistry(fakeSession(), failingFetch, () => 'https://node.example/').verify();
  assert.equal(result.state, 'UNAVAILABLE');
});
