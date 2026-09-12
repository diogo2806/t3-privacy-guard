import assert from 'node:assert/strict';
import test from 'node:test';
import { buildDelegatedExecutionRequest } from './privacy-guard-contract.js';

const tenantDid = 'did:t3n:tenant123';
const agentDid = 'did:t3n:agent456';
const contractId = 'z:tenant123:privacy-guard';
const contractVersion = '0.2.0';

function input() {
  return {
    request_id: 'req-001',
    agent_did: agentDid,
    action: 'revoke-credential',
    resource: 'credential:security-api',
    purpose: 'incident-remediation',
    fields: ['incident_id', 'credential_id', 'reason'],
  };
}

test('evaluation execution is bound to the authenticated tenant DID', () => {
  const request = buildDelegatedExecutionRequest(
    tenantDid,
    contractId,
    contractVersion,
    'evaluate-action',
    input(),
  );

  assert.equal(request.pii_did, tenantDid);
  assert.equal(request.function_name, 'evaluate-action');
  assert.equal(request.input.agent_did, agentDid);
  assert.notEqual(request.pii_did, request.input.agent_did);
});

test('remediation execution uses the same tenant delegation subject', () => {
  const request = buildDelegatedExecutionRequest(
    tenantDid,
    contractId,
    contractVersion,
    'execute-remediation',
    input(),
  );

  assert.equal(request.pii_did, tenantDid);
  assert.equal(request.function_name, 'execute-remediation');
});

test('rejects a missing or non-T3N tenant DID', () => {
  assert.throws(
    () => buildDelegatedExecutionRequest('', contractId, contractVersion, 'evaluate-action', input()),
    /Authenticated tenant DID is required/,
  );
  assert.throws(
    () => buildDelegatedExecutionRequest('tenant123', contractId, contractVersion, 'evaluate-action', input()),
    /Authenticated tenant DID is required/,
  );
});

test('caller-controlled agent metadata cannot replace the delegation subject', () => {
  const forgedInput = { ...input(), agent_did: 'did:t3n:forged-agent' };
  const request = buildDelegatedExecutionRequest(
    tenantDid,
    contractId,
    contractVersion,
    'evaluate-action',
    forgedInput,
  );

  assert.equal(request.pii_did, tenantDid);
  assert.equal(request.input.agent_did, 'did:t3n:forged-agent');
});
