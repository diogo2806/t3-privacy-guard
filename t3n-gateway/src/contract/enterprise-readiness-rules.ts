import type { DelegationStatus } from '../agent/delegation-service.js';
import type { OperationalPolicyDocument } from '../policy/policy-document.js';

// Readiness rules shared by both runtimes. No T3N SDK here: the self-hosted gateway imports this module.

export type EnterpriseIntegrationState = 'READY' | 'INCOMPLETE' | 'MISMATCH' | 'UNKNOWN';
export type EnterpriseIntegrationDiagnosticCode =
  | 'NONE'
  | 'POLICY_UNAVAILABLE'
  | 'POLICY_INVALID'
  | 'PRIVATE_CONFIGURATION_UNAVAILABLE'
  | 'ENDPOINT_CONFIGURATION_INVALID'
  | 'DELEGATION_UNAVAILABLE'
  | 'INSUFFICIENT_CREDIT'
  | 'T3N_CONTROL_PLANE_UNAVAILABLE'
  | 'TRUST_RUNTIME_UNAVAILABLE';

export interface EnterpriseVerificationContract {
  readonly action: string;
  readonly expectedState: string;
}

export interface EnterpriseIntegrationReadiness {
  readonly state: EnterpriseIntegrationState;
  readonly diagnosticCode: EnterpriseIntegrationDiagnosticCode;
  readonly executionConfigured: boolean | null;
  readonly verificationConfigured: boolean | null;
  readonly credentialConfigured: boolean | null;
  readonly executionHost: string | null;
  readonly verificationHost: string | null;
  readonly policyAllowsExecutionHost: boolean | null;
  readonly policyAllowsVerificationHost: boolean | null;
  readonly executorDelegationAllowsExecutionHost: boolean | null;
  readonly executorDelegationAllowsVerificationHost: boolean | null;
  readonly supportedExecutableActions: string[];
  readonly supportedVerifiedActions: string[];
  readonly verificationContracts: EnterpriseVerificationContract[];
  readonly evaluationOnlyActions: string[];
  readonly checkedAt: string;
}

export interface EnterpriseIntegrationInputs {
  readonly executionUrl: string | null;
  readonly verificationUrl: string | null;
  readonly credentialConfigured: boolean;
  readonly policy: OperationalPolicyDocument;
  readonly executorDelegation: DelegationStatus;
  readonly checkedAt: string;
}

/** Same inputs with endpoints already reduced to canonical hostnames (what the self-hosted runtime reports). */
export interface EnterpriseIntegrationHostInputs {
  readonly executionHost: string | null;
  readonly verificationHost: string | null;
  readonly credentialConfigured: boolean;
  readonly policy: OperationalPolicyDocument;
  readonly executorDelegation: DelegationStatus;
  readonly checkedAt: string;
}

export const VERIFICATION_CONTRACTS: readonly EnterpriseVerificationContract[] = Object.freeze([
  Object.freeze({ action: 'revoke-credential', expectedState: 'REVOKED' }),
  Object.freeze({ action: 'notify-security', expectedState: 'DELIVERED' }),
]);
const DEMO_HOSTS = new Set(['postman-echo.com']);

function canonicalHttpsHost(value: string | null): string | null {
  if (value == null || !value.trim()) return null;
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || !parsed.hostname) {
    throw new Error('invalid enterprise endpoint');
  }
  return parsed.hostname.toLowerCase().replace(/\.$/, '');
}

function normalizedHosts(values: readonly string[]): Set<string> {
  return new Set(values.map((value) => value.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean));
}

function allSupportedRulesAllowHost(rules: readonly OperationalPolicyDocument['actions'][string][], host: string | null): boolean {
  if (host == null || rules.length !== VERIFICATION_CONTRACTS.length) return false;
  return rules.every((rule) => normalizedHosts(rule.allowed_hosts).has(host));
}

function isDemoHost(host: string | null): boolean {
  return host != null && (DEMO_HOSTS.has(host) || host === 'example.invalid' || host.endsWith('.invalid'));
}

export function unknownEnterpriseIntegrationReadiness(
  checkedAt: string,
  diagnosticCode: EnterpriseIntegrationDiagnosticCode = 'T3N_CONTROL_PLANE_UNAVAILABLE',
): EnterpriseIntegrationReadiness {
  return {
    state: 'UNKNOWN',
    diagnosticCode,
    executionConfigured: null,
    verificationConfigured: null,
    credentialConfigured: null,
    executionHost: null,
    verificationHost: null,
    policyAllowsExecutionHost: null,
    policyAllowsVerificationHost: null,
    executorDelegationAllowsExecutionHost: null,
    executorDelegationAllowsVerificationHost: null,
    supportedExecutableActions: VERIFICATION_CONTRACTS.map(({ action }) => action),
    supportedVerifiedActions: VERIFICATION_CONTRACTS.map(({ action }) => action),
    verificationContracts: VERIFICATION_CONTRACTS.map((contract) => ({ ...contract })),
    evaluationOnlyActions: [],
    checkedAt,
  };
}

export function evaluateEnterpriseIntegrationReadiness(input: EnterpriseIntegrationInputs): EnterpriseIntegrationReadiness {
  let executionHost: string | null;
  let verificationHost: string | null;
  try {
    executionHost = canonicalHttpsHost(input.executionUrl);
    verificationHost = canonicalHttpsHost(input.verificationUrl);
  } catch {
    return unknownEnterpriseIntegrationReadiness(input.checkedAt, 'ENDPOINT_CONFIGURATION_INVALID');
  }
  return evaluateEnterpriseIntegrationReadinessForHosts({
    executionHost,
    verificationHost,
    credentialConfigured: input.credentialConfigured,
    policy: input.policy,
    executorDelegation: input.executorDelegation,
    checkedAt: input.checkedAt,
  });
}

export function evaluateEnterpriseIntegrationReadinessForHosts(input: EnterpriseIntegrationHostInputs): EnterpriseIntegrationReadiness {
  const { executionHost, verificationHost } = input;
  const executionConfigured = executionHost != null;
  const verificationConfigured = verificationHost != null;
  const supportedExecutableActions = VERIFICATION_CONTRACTS.map(({ action }) => action);
  const supportedVerifiedActions = [...supportedExecutableActions];
  const supportedSet = new Set(supportedExecutableActions);
  const evaluationOnlyActions = Object.keys(input.policy.actions).filter((action) => !supportedSet.has(action)).sort();
  const supportedPolicyRules = supportedExecutableActions
    .map((action) => input.policy.actions[action])
    .filter((rule): rule is OperationalPolicyDocument['actions'][string] => rule != null);
  const executorHosts = normalizedHosts(input.executorDelegation.allowedHosts);
  const policyAllowsExecutionHost = allSupportedRulesAllowHost(supportedPolicyRules, executionHost);
  const policyAllowsVerificationHost = allSupportedRulesAllowHost(supportedPolicyRules, verificationHost);
  const delegationUnknown = input.executorDelegation.memberState === 'UNKNOWN' || input.executorDelegation.effectiveState === 'UNKNOWN';
  const delegationActive = input.executorDelegation.memberState === 'ACTIVE' && input.executorDelegation.effectiveState === 'ACTIVE';
  const executorDelegationAllowsExecutionHost = delegationUnknown
    ? null
    : executionHost != null && delegationActive && executorHosts.has(executionHost);
  const executorDelegationAllowsVerificationHost = delegationUnknown
    ? null
    : verificationHost != null && delegationActive && executorHosts.has(verificationHost);

  let state: EnterpriseIntegrationState;
  let diagnosticCode: EnterpriseIntegrationDiagnosticCode = 'NONE';
  if (!executionConfigured || !verificationConfigured || !input.credentialConfigured || isDemoHost(executionHost) || isDemoHost(verificationHost)) {
    state = 'INCOMPLETE';
  } else if (delegationUnknown) {
    state = 'UNKNOWN';
    diagnosticCode = 'DELEGATION_UNAVAILABLE';
  } else if (
    supportedPolicyRules.length !== supportedExecutableActions.length
    || !policyAllowsExecutionHost
    || !policyAllowsVerificationHost
    || !executorDelegationAllowsExecutionHost
    || !executorDelegationAllowsVerificationHost
  ) {
    state = 'MISMATCH';
  } else {
    state = 'READY';
  }

  return {
    state,
    diagnosticCode,
    executionConfigured,
    verificationConfigured,
    credentialConfigured: input.credentialConfigured,
    executionHost,
    verificationHost,
    policyAllowsExecutionHost,
    policyAllowsVerificationHost,
    executorDelegationAllowsExecutionHost,
    executorDelegationAllowsVerificationHost,
    supportedExecutableActions,
    supportedVerifiedActions,
    verificationContracts: VERIFICATION_CONTRACTS.map((contract) => ({ ...contract })),
    evaluationOnlyActions,
    checkedAt: input.checkedAt,
  };
}
