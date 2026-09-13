import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { DelegationStatus } from '../agent/delegation-service.js';
import type { OperationalPolicyDocument } from '../policy/policy-document.js';
import { evaluateEnterpriseIntegrationReadiness } from './enterprise-integration-readiness.js';

const checkedAt = '2026-09-13T21:00:00.000Z';

function policy(hosts = ['security.company.example', 'verify.company.example']): OperationalPolicyDocument {
  return {
    version: '2026-09-13.1',
    actions: {
      'create-incident': {
        purpose: 'incident-recording',
        allowed_fields: ['incident_id'],
        allowed_hosts: [],
        allowed_private_refs: [],
        requires_host: false,
        requires_human_authorization: false,
      },
      'isolate-account': {
        purpose: 'incident-remediation',
        allowed_fields: ['incident_id'],
        allowed_hosts: hosts,
        allowed_private_refs: [],
        requires_host: true,
        requires_human_authorization: true,
      },
      'notify-security': {
        purpose: 'incident-notification',
        allowed_fields: ['incident_id'],
        allowed_hosts: hosts,
        allowed_private_refs: ['verified_email'],
        requires_host: true,
        requires_human_authorization: false,
      },
      'revoke-credential': {
        purpose: 'incident-remediation',
        allowed_fields: ['incident_id', 'credential_id', 'reason'],
        allowed_hosts: hosts,
        allowed_private_refs: [],
        requires_host: true,
        requires_human_authorization: true,
      },
    },
  };
}

function delegation(overrides: Partial<DelegationStatus> = {}): DelegationStatus {
  return {
    memberState: 'ACTIVE',
    effectiveState: 'ACTIVE',
    functions: ['execute-remediation', 'verify-remediation'],
    scopes: ['incident_id', 'credential_id', 'reason'],
    allowedHosts: ['security.company.example', 'verify.company.example'],
    checkedFunctions: ['execute-remediation', 'verify-remediation'],
    checkedScopes: ['incident_id', 'credential_id', 'reason'],
    ...overrides,
  };
}

function evaluate(overrides: Partial<Parameters<typeof evaluateEnterpriseIntegrationReadiness>[0]> = {}) {
  return evaluateEnterpriseIntegrationReadiness({
    executionUrl: 'https://security.company.example/private/revoke?tenant=acme',
    verificationUrl: 'https://verify.company.example/private/read-back#state',
    credentialConfigured: true,
    policy: policy(),
    executorDelegation: delegation(),
    checkedAt,
    ...overrides,
  });
}

describe('enterprise integration readiness', () => {
  it('reports READY only when config, policy, delegation and verification contract align', () => {
    const result = evaluate();
    assert.equal(result.state, 'READY');
    assert.equal(result.executionHost, 'security.company.example');
    assert.equal(result.verificationHost, 'verify.company.example');
    assert.equal(result.policyAllowsExecutionHost, true);
    assert.equal(result.policyAllowsVerificationHost, true);
    assert.equal(result.executorDelegationAllowsExecutionHost, true);
    assert.equal(result.executorDelegationAllowsVerificationHost, true);
    assert.deepEqual(result.supportedExecutableActions, ['revoke-credential']);
    assert.deepEqual(result.supportedVerifiedActions, ['revoke-credential']);
    assert.deepEqual(result.verificationContracts, [{ action: 'revoke-credential', expectedState: 'REVOKED' }]);
    assert.deepEqual(result.evaluationOnlyActions, ['create-incident', 'isolate-account', 'notify-security']);
  });

  it('reports INCOMPLETE when a required endpoint is absent', () => {
    assert.equal(evaluate({ verificationUrl: null }).state, 'INCOMPLETE');
  });

  it('reports INCOMPLETE when the execution credential is absent without exposing it', () => {
    const result = evaluate({ credentialConfigured: false });
    assert.equal(result.state, 'INCOMPLETE');
    assert.equal(result.credentialConfigured, false);
  });

  it('does not treat evidence/demo endpoints as enterprise configuration', () => {
    const result = evaluate({
      executionUrl: 'https://postman-echo.com/post',
      policy: policy(['postman-echo.com', 'verify.company.example']),
      executorDelegation: delegation({ allowedHosts: ['postman-echo.com', 'verify.company.example'] }),
    });
    assert.equal(result.state, 'INCOMPLETE');
  });

  it('reports MISMATCH when active policy does not allow the configured host', () => {
    const result = evaluate({ policy: policy(['different.example', 'verify.company.example']) });
    assert.equal(result.state, 'MISMATCH');
    assert.equal(result.policyAllowsExecutionHost, false);
  });

  it('reports MISMATCH when Executor delegation does not allow the configured host', () => {
    const result = evaluate({ executorDelegation: delegation({ allowedHosts: ['security.company.example'] }) });
    assert.equal(result.state, 'MISMATCH');
    assert.equal(result.executorDelegationAllowsVerificationHost, false);
  });

  it('fails closed to UNKNOWN for inconclusive effective delegation', () => {
    const result = evaluate({ executorDelegation: delegation({ effectiveState: 'UNKNOWN' }) });
    assert.equal(result.state, 'UNKNOWN');
  });

  it('fails closed to UNKNOWN for malformed or non-HTTPS private endpoint configuration', () => {
    assert.equal(evaluate({ executionUrl: 'http://security.company.example/private' }).state, 'UNKNOWN');
    assert.equal(evaluate({ executionUrl: 'not-a-url' }).state, 'UNKNOWN');
  });

  it('returns only canonical hostnames and never private paths, query strings or credentials', () => {
    const result = evaluate();
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes('/private/'), false);
    assert.equal(serialized.includes('tenant=acme'), false);
    assert.equal(serialized.includes('#state'), false);
    assert.equal(serialized.includes('https://'), false);
  });
});
