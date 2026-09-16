import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { DelegationStatus } from '../agent/delegation-service.js';
import type { OperationalPolicyDocument } from '../policy/policy-document.js';
import { evaluateEnterpriseIntegrationReadiness, unknownEnterpriseIntegrationReadiness } from './enterprise-integration-readiness.js';

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
        allowed_fields: ['incident_id', 'severity', 'summary'],
        allowed_hosts: hosts,
        allowed_private_refs: ['verified_email'],
        requires_host: true,
        requires_human_authorization: true,
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
    scopes: ['incident_id', 'credential_id', 'reason', 'verified_contacts.email.value'],
    allowedHosts: ['security.company.example', 'verify.company.example'],
    checkedFunctions: ['execute-remediation', 'verify-remediation'],
    checkedScopes: ['incident_id', 'credential_id', 'reason', 'verified_contacts.email.value'],
    ...overrides,
  };
}

function evaluate(overrides: Partial<Parameters<typeof evaluateEnterpriseIntegrationReadiness>[0]> = {}) {
  return evaluateEnterpriseIntegrationReadiness({
    executionUrl: 'https://security.company.example/private/remediate?tenant=acme',
    verificationUrl: 'https://verify.company.example/private/read-back#state',
    credentialConfigured: true,
    policy: policy(),
    executorDelegation: delegation(),
    checkedAt,
    ...overrides,
  });
}

describe('enterprise integration readiness', () => {
  it('reports READY only when config, both executable policy rules, delegation and verification contracts align', () => {
    const result = evaluate();
    assert.equal(result.state, 'READY');
    assert.equal(result.diagnosticCode, 'NONE');
    assert.equal(result.executionHost, 'security.company.example');
    assert.equal(result.verificationHost, 'verify.company.example');
    assert.equal(result.policyAllowsExecutionHost, true);
    assert.equal(result.policyAllowsVerificationHost, true);
    assert.equal(result.executorDelegationAllowsExecutionHost, true);
    assert.equal(result.executorDelegationAllowsVerificationHost, true);
    assert.deepEqual(result.supportedExecutableActions, ['revoke-credential', 'notify-security']);
    assert.deepEqual(result.supportedVerifiedActions, ['revoke-credential', 'notify-security']);
    assert.deepEqual(result.verificationContracts, [
      { action: 'revoke-credential', expectedState: 'REVOKED' },
      { action: 'notify-security', expectedState: 'DELIVERED' },
    ]);
    assert.deepEqual(result.evaluationOnlyActions, ['create-incident', 'isolate-account']);
  });

  it('reports INCOMPLETE when no enterprise execution integration is configured', () => {
    const result = evaluate({
      executionUrl: null,
      verificationUrl: null,
      credentialConfigured: false,
      executorDelegation: delegation({ allowedHosts: [] }),
    });
    assert.equal(result.state, 'INCOMPLETE');
    assert.equal(result.diagnosticCode, 'NONE');
    assert.equal(result.executionConfigured, false);
    assert.equal(result.verificationConfigured, false);
    assert.equal(result.credentialConfigured, false);
    assert.equal(result.executorDelegationAllowsExecutionHost, false);
    assert.equal(result.executorDelegationAllowsVerificationHost, false);
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
    assert.equal(result.diagnosticCode, 'NONE');
    assert.equal(result.policyAllowsExecutionHost, false);
  });

  it('reports MISMATCH when only one executable action allows the configured host', () => {
    const partial = policy();
    partial.actions['notify-security'] = {
      ...partial.actions['notify-security'],
      allowed_hosts: ['verify.company.example'],
    };
    const result = evaluate({ policy: partial });
    assert.equal(result.state, 'MISMATCH');
    assert.equal(result.policyAllowsExecutionHost, false);
  });

  it('reports MISMATCH when Executor delegation does not allow the configured host', () => {
    const result = evaluate({ executorDelegation: delegation({ allowedHosts: ['security.company.example'] }) });
    assert.equal(result.state, 'MISMATCH');
    assert.equal(result.executorDelegationAllowsVerificationHost, false);
  });

  it('fails closed with a delegation diagnostic for inconclusive effective delegation', () => {
    const result = evaluate({ executorDelegation: delegation({ effectiveState: 'UNKNOWN' }) });
    assert.equal(result.state, 'UNKNOWN');
    assert.equal(result.diagnosticCode, 'DELEGATION_UNAVAILABLE');
  });

  it('fails closed with a sanitized endpoint diagnostic for malformed or non-HTTPS private endpoint configuration', () => {
    assert.equal(evaluate({ executionUrl: 'http://security.company.example/private' }).diagnosticCode, 'ENDPOINT_CONFIGURATION_INVALID');
    assert.equal(evaluate({ executionUrl: 'not-a-url' }).diagnosticCode, 'ENDPOINT_CONFIGURATION_INVALID');
  });

  it('builds an allowlisted unknown response without arbitrary error text', () => {
    const result = unknownEnterpriseIntegrationReadiness(checkedAt, 'POLICY_UNAVAILABLE');
    assert.equal(result.state, 'UNKNOWN');
    assert.equal(result.diagnosticCode, 'POLICY_UNAVAILABLE');
    assert.equal(JSON.stringify(result).includes('secret'), false);
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
