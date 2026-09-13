import assert from 'node:assert/strict';
import test from 'node:test';
import type { AgentSession } from './agent-session.js';
import { AgentCardRegistry, buildAgentCard, buildAgentCardForSession, serializeAgentCard, validateResolvedAgentCard, type AgentCardFetch } from './agent-card.js';

const AGENT_DID = 'did:t3n:0123456789abcdef0123456789abcdef01234567';
const OTHER_DID = 'did:t3n:89abcdef0123456789abcdef0123456789abcdef';
const A2A_URL = 'https://guard.example/a2a';

function fakeSession(did = AGENT_DID): AgentSession {
  return { getAgentDid: () => did } as unknown as AgentSession;
}

function fetchResponse(status: number, body = ''): AgentCardFetch {
  return async () => ({ ok: status >= 200 && status < 300, status, text: async () => body });
}

test('builder reads the canonical Agent DID from the authenticated session and advertises only DID by default', () => {
  const card = buildAgentCardForSession(fakeSession());
  assert.equal(card.services.length, 1);
  assert.deepEqual(card.services[0], { name: 'DID', endpoint: AGENT_DID, version: 'v1' });
  assert.equal(card.x402Support, false);
  assert.equal(card.active, true);
  assert.deepEqual(card.supportedTrust, []);
});

test('builder advertises A2A only when the public endpoint is configured', () => {
  const card = buildAgentCardForSession(fakeSession(), A2A_URL);
  assert.deepEqual(card.services, [
    { name: 'DID', endpoint: AGENT_DID, version: 'v1' },
    { name: 'A2A', endpoint: 'https://guard.example/.well-known/agent-card.json', version: '1.0' },
  ]);
  const serialized = serializeAgentCard(card);
  assert.doesNotMatch(serialized, /MCP|x402Support": true|private[_-]?key|api[_-]?key|password|token/i);
});

test('builder rejects unsafe or non-public A2A endpoints and non-canonical DID input', () => {
  assert.throws(() => buildAgentCard('did:t3n:agent'), /canonical did:t3n identifier/);
  assert.throws(() => buildAgentCard(AGENT_DID, 'http://guard.example/a2a'), /HTTPS/);
  assert.throws(() => buildAgentCard(AGENT_DID, 'https://guard.example/not-a2a'), /public \/a2a endpoint/);
  assert.throws(() => buildAgentCard(AGENT_DID, 'https://localhost/a2a'), /public hostname/);
  assert.throws(() => buildAgentCard(AGENT_DID, 'https://10.0.0.2/a2a'), /public hostname/);
  assert.throws(() => buildAgentCard(AGENT_DID, 'https://[::1]/a2a'), /public hostname/);
});

test('serialized card contains no credential-shaped metadata', () => {
  const serialized = serializeAgentCard(buildAgentCard(AGENT_DID, A2A_URL));
  assert.doesNotMatch(serialized, /T3N_AGENT_API_KEY|api[_-]?key|private[_-]?key|password|secret|token/i);
});

test('resolved card with matching DID and configured A2A becomes REGISTERED', async () => {
  const body = serializeAgentCard(buildAgentCard(AGENT_DID, A2A_URL));
  const result = await new AgentCardRegistry(fakeSession(), fetchResponse(200, body), () => 'https://node.example/', A2A_URL).verify();
  assert.equal(result.state, 'REGISTERED');
  assert.equal(result.agentDid, AGENT_DID);
  assert.deepEqual(result.services, ['A2A', 'DID']);
  assert.equal(result.a2aConfigured, true);
  assert.equal(result.a2aPublicUrl, A2A_URL);
  assert.match(result.a2aConfigurationCheckedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(result.cardSha256 ?? '', /^[a-f0-9]{64}$/);
});

test('configured A2A must be present and must match the expected discovery URL', async () => {
  const didOnly = serializeAgentCard(buildAgentCard(AGENT_DID));
  const missing = await new AgentCardRegistry(fakeSession(), fetchResponse(200, didOnly), () => 'https://node.example/', A2A_URL).verify();
  assert.equal(missing.state, 'MISMATCH');

  const card = JSON.parse(serializeAgentCard(buildAgentCard(AGENT_DID, A2A_URL))) as Record<string, unknown>;
  card.services = [
    { name: 'DID', endpoint: AGENT_DID, version: 'v1' },
    { name: 'A2A', endpoint: 'https://evil.example/.well-known/agent-card.json', version: '1.0' },
  ];
  assert.throws(() => validateResolvedAgentCard(AGENT_DID, JSON.stringify(card), A2A_URL), /does not match local configuration/);
});

test('unconfigured deployment rejects a resolved card that claims A2A', async () => {
  const body = serializeAgentCard(buildAgentCard(AGENT_DID, A2A_URL));
  const result = await new AgentCardRegistry(fakeSession(), fetchResponse(200, body), () => 'https://node.example/').verify();
  assert.equal(result.state, 'MISMATCH');
  assert.equal(result.a2aConfigured, false);
});

test('missing public card becomes NOT_REGISTERED', async () => {
  const result = await new AgentCardRegistry(fakeSession(), fetchResponse(404), () => 'https://node.example/', A2A_URL).verify();
  assert.equal(result.state, 'NOT_REGISTERED');
  assert.equal(result.cardUri, null);
  assert.equal(result.a2aConfigured, true);
});

test('resolved card for a different DID becomes MISMATCH', async () => {
  const body = serializeAgentCard(buildAgentCard(OTHER_DID));
  const result = await new AgentCardRegistry(fakeSession(), fetchResponse(200, body), () => 'https://node.example/').verify();
  assert.equal(result.state, 'MISMATCH');
});

test('unsupported service, trust claim or secret metadata is rejected', () => {
  const card = JSON.parse(serializeAgentCard(buildAgentCard(AGENT_DID))) as Record<string, unknown>;
  card.services = [{ name: 'MCP', endpoint: 'https://mcp.example', version: '2025-06-18' }];
  assert.throws(() => validateResolvedAgentCard(AGENT_DID, JSON.stringify(card)), /unsupported service/);

  const trustCard = JSON.parse(serializeAgentCard(buildAgentCard(AGENT_DID))) as Record<string, unknown>;
  trustCard.supportedTrust = ['tee-attestation'];
  assert.throws(() => validateResolvedAgentCard(AGENT_DID, JSON.stringify(trustCard)), /unsupported trust evidence/);

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
  const result = await new AgentCardRegistry(fakeSession(), failingFetch, () => 'https://node.example/', A2A_URL).verify();
  assert.equal(result.state, 'UNAVAILABLE');
  assert.equal(result.a2aConfigured, true);
});
