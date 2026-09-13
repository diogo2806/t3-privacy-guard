import assert from 'node:assert/strict';
import test from 'node:test';
import { buildDelegatedExecutionRequest } from './privacy-guard-contract.js';

const tenantDid = 'did:t3n:tenant123';
const agentDid = 'did:t3n:agent456';
const executorDid = 'did:t3n:executor789';
const contractId = 'z:tenant123:privacy-guard';
const contractVersion = '0.4.0';
const policyVersion = '2026-09-12.1';
const policyHash = 'a'.repeat(64);
const approvedHost = 'security-api.internal';
const normalPayload = { incident_id: 'inc-demo-001', credential_id: 'cred-demo-001', reason: 'suspected compromise' };

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
  assert.equal(request.contract_version, '0.4.0');
  assert.equal(request.function_name, 'evaluate-action');
  assert.equal(request.input.agent_did, agentDid);
  assert.notEqual(request.pii_did, request.input.agent_did);
});

test('remediation execution carries exact proof, policy provenance, executor, destination and trusted payload into T3N', () => {
  const request = buildDelegatedExecutionRequest(
    tenantDid,
    contractId,
    contractVersion,
    'execute-remediation',
    {
      ...input(),
      incident_id: 'incident-1',
      action_id: 'action-1',
      decision_id: 'decision-1',
      executor_did: executorDid,
      authorization_proof: 'v2.payload.signature',
      approved_host: approvedHost,
      normal_payload: normalPayload,
      policy_version: policyVersion,
      policy_hash: policyHash,
    },
  );

  assert.equal(request.pii_did, tenantDid);
  assert.equal(request.function_name, 'execute-remediation');
  assert.equal(request.input.approved_host, approvedHost);
  assert.deepEqual(request.input.normal_payload, normalPayload);
  assert.equal(request.input.policy_version, policyVersion);
  assert.equal(request.input.policy_hash, policyHash);
  assert.equal(request.input.executor_did, executorDid);
  assert.equal(request.input.authorization_proof, 'v2.payload.signature');
});

test('verification execution uses the same tenant delegation subject', () => {
  const request = buildDelegatedExecutionRequest(
    tenantDid,
    contractId,
    contractVersion,
    'verify-remediation',
    { request_id: 'req-001', operation_id: 'op-001', expected_state: 'REVOKED' },
  );

  assert.equal(request.pii_did, tenantDid);
  assert.equal(request.function_name, 'verify-remediation');
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
