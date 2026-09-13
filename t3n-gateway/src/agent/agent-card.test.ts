import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import type { AgentSession } from './agent-session.js';
import {
  AgentCardRegistrationService,
  assertAgentCardMatches,
  buildAgentCard,
  serializeAgentCard,
} from './agent-card.js';

const DID = 'did:t3n:029ff61abb4e88ccbbbf74262f91cbbdba128cab';

function session(agentDid = DID): AgentSession {
  return {
    getStatus: () => ({
      configured: true,
      connected: true,
      ready: true,
      agentDid,
      network: 'testnet',
      trustAnchorVerified: true,
      trustManifestVersion: 1,
      lastError: null,
    }),
  } as AgentSession;
}

function response(body: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } });
}

test('builder uses only the canonical Agent DID and emits deterministic secret-free metadata', () => {
  const first = serializeAgentCard(buildAgentCard(DID));
  const second = serializeAgentCard(buildAgentCard(DID));
  assert.equal(first, second);
  assert.match(first, new RegExp(DID));
  assert.doesNotMatch(first, /api[_-]?key|secret|password|token/i);
  assert.doesNotMatch(first, /A2A|MCP|x402/i);
  assertAgentCardMatches(JSON.parse(first), DID);
});

test('verifier returns REGISTERED only when the public card matches the authenticated session', async () => {
  const raw = serializeAgentCard(buildAgentCard(DID));
  const service = new AgentCardRegistrationService(
    session(),
    'testnet',
    async () => response(raw),
    () => new Date('2026-09-12T22:00:00.000Z'),
  );
  const status = await service.verify();
  assert.equal(status.agentRegistrationState, 'REGISTERED');
  assert.equal(status.agentDid, DID);
  assert.equal(status.agentCardSha256, createHash('sha256').update(raw).digest('hex'));
  assert.deepEqual(status.agentCardServices, ['DID']);
});

test('verifier differentiates not registered, mismatch and network unavailability', async () => {
  const missing = new AgentCardRegistrationService(session(), 'testnet', async () => response('', 404));
  assert.equal((await missing.verify()).agentRegistrationState, 'NOT_REGISTERED');

  const otherDid = 'did:t3n:another-agent';
  const mismatch = new AgentCardRegistrationService(session(), 'testnet', async () => response(serializeAgentCard(buildAgentCard(otherDid))));
  assert.equal((await mismatch.verify()).agentRegistrationState, 'MISMATCH');

  const unavailable = new AgentCardRegistrationService(session(), 'testnet', async () => { throw new Error('offline'); });
  assert.equal((await unavailable.verify()).agentRegistrationState, 'UNAVAILABLE');
});

test('malformed, inactive or unsupported-service cards never become REGISTERED', async () => {
  const malformed = new AgentCardRegistrationService(session(), 'testnet', async () => response('{bad-json'));
  assert.equal((await malformed.verify()).agentRegistrationState, 'MISMATCH');

  const inactive = { ...buildAgentCard(DID), active: false };
  const inactiveVerifier = new AgentCardRegistrationService(session(), 'testnet', async () => response(JSON.stringify(inactive)));
  assert.equal((await inactiveVerifier.verify()).agentRegistrationState, 'MISMATCH');

  const unsupported = { ...buildAgentCard(DID), services: [{ name: 'A2A', endpoint: 'https://example.test', version: 'v1' }] };
  const unsupportedVerifier = new AgentCardRegistrationService(session(), 'testnet', async () => response(JSON.stringify(unsupported)));
  assert.equal((await unsupportedVerifier.verify()).agentRegistrationState, 'MISMATCH');
});
