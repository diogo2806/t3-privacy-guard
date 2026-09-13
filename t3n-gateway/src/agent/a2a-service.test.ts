import assert from 'node:assert/strict';
import test from 'node:test';
import type { PolicyDecision } from '../contract/privacy-guard-contract.js';
import { SensitivePromptError } from '../security/prompt-privacy-guard.js';
import { A2aEvaluationService, A2aProviderUnavailableError } from './a2a-service.js';
import type { AgentProvider } from './agent-provider.js';
import { AgentService } from './agent-service.js';

const AGENT_DID = 'did:t3n:0123456789abcdef0123456789abcdef01234567';

function decision(): PolicyDecision {
  return {
    request_id: 'server-generated',
    decision: 'REDACT',
    reason_code: 'FIELD_REDACTION_REQUIRED',
    reason: 'Synthetic field is outside the permitted scope.',
    allowed_fields: ['incident_id'],
    redacted_fields: ['email'],
    allowed_private_refs: [],
    redacted_private_refs: ['verified_email'],
    policy_version: '1.2.3',
    policy_hash: 'a'.repeat(64),
    requires_human_authorization: false,
  };
}

test('A2A evaluation reuses AgentService proposal and T3N evaluate-action input without client identities', async () => {
  const provider: AgentProvider = {
    propose: async () => ({
      provider: 'test-provider',
      model: 'test-model',
      proposal: {
        action: 'notify-user',
        resource: 'incident:synthetic',
        purpose: 'incident-response',
        host: null,
        fields: ['incident_id', 'email'],
        private_refs: ['verified_email'],
      },
    }),
  };
  let evaluated: unknown;
  const service = new A2aEvaluationService(
    new AgentService(provider),
    { evaluate: async (request) => { evaluated = request; return decision(); } },
    { getAgentDid: () => AGENT_DID },
  );

  const result = await service.evaluate('Evaluate this synthetic incident without literal PII.');

  assert.equal(result.agentDid, AGENT_DID);
  assert.equal(result.decision, 'REDACT');
  assert.equal(result.reasonCode, 'FIELD_REDACTION_REQUIRED');
  assert.equal(result.policyVersion, '1.2.3');
  assert.equal(result.policyHash, 'a'.repeat(64));
  assert.deepEqual(result.proposal.private_refs, ['verified_email']);
  const request = evaluated as Record<string, unknown>;
  assert.match(String(request.request_id), /^[0-9a-f-]{36}$/i);
  assert.equal('agent_did' in request, false);
  assert.equal('pii_did' in request, false);
  assert.equal('decision' in request, false);
});

test('sensitive prompt is rejected before policy evaluation and never echoed', async () => {
  let policyCalls = 0;
  const provider: AgentProvider = {
    propose: async () => { throw new Error('provider must not receive sensitive prompt'); },
  };
  const service = new A2aEvaluationService(
    new AgentService(provider),
    { evaluate: async () => { policyCalls += 1; return decision(); } },
    { getAgentDid: () => AGENT_DID },
  );

  await assert.rejects(
    () => service.evaluate('email=user@example.com'),
    (error: unknown) => error instanceof SensitivePromptError,
  );
  assert.equal(policyCalls, 0);
});

test('malformed provider proposal cannot inject decision or identity fields', async () => {
  const provider: AgentProvider = {
    propose: async () => ({
      provider: 'test-provider',
      model: 'test-model',
      proposal: {
        action: 'notify-user',
        resource: 'incident:synthetic',
        purpose: 'incident-response',
        fields: [],
        private_refs: [],
        decision: 'ALLOW',
        agent_did: 'did:t3n:attacker',
      } as never,
    }),
  };
  let policyCalls = 0;
  const service = new A2aEvaluationService(
    new AgentService(provider),
    { evaluate: async () => { policyCalls += 1; return decision(); } },
    { getAgentDid: () => AGENT_DID },
  );

  await assert.rejects(() => service.evaluate('Evaluate the synthetic incident.'), A2aProviderUnavailableError);
  assert.equal(policyCalls, 0);
});
