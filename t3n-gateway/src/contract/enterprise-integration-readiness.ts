import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import type { DelegationService, DelegationStatus } from '../agent/delegation-service.js';
import { canonicalizeOperationalPolicy, type OperationalPolicyDocument } from '../policy/policy-document.js';
import type { T3nSession } from '../t3n/session.js';
import type { PrivacyGuardContractService } from './privacy-guard-contract.js';

export type EnterpriseIntegrationState = 'READY' | 'INCOMPLETE' | 'MISMATCH' | 'UNKNOWN';
export type EnterpriseIntegrationDiagnosticCode =
  | 'NONE'
  | 'POLICY_UNAVAILABLE'
  | 'POLICY_INVALID'
  | 'PRIVATE_CONFIGURATION_UNAVAILABLE'
  | 'ENDPOINT_CONFIGURATION_INVALID'
  | 'DELEGATION_UNAVAILABLE'
  | 'T3N_CONTROL_PLANE_UNAVAILABLE';

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

interface EnterpriseIntegrationInputs {
  readonly executionUrl: string | null;
  readonly verificationUrl: string | null;
  readonly credentialConfigured: boolean;
  readonly policy: OperationalPolicyDocument;
  readonly executorDelegation: DelegationStatus;
  readonly checkedAt: string;
}

interface PrivateConfiguration {
  readonly executionUrl: string | null;
  readonly verificationUrl: string | null;
  readonly credentialConfigured: boolean;
  readonly policy: OperationalPolicyDocument;
}

class ReadinessDiagnosticError extends Error {
  constructor(readonly diagnosticCode: EnterpriseIntegrationDiagnosticCode) {
    super(diagnosticCode);
    this.name = 'ReadinessDiagnosticError';
  }
}

const VERIFICATION_CONTRACTS: readonly EnterpriseVerificationContract[] = Object.freeze([
  Object.freeze({ action: 'revoke-credential', expectedState: 'REVOKED' }),
  Object.freeze({ action: 'notify-security', expectedState: 'DELIVERED' }),
]);
const DEMO_HOSTS = new Set(['postman-echo.com']);

function extractValue(value: unknown, depth = 0): string | null {
  if (depth > 4) return null;
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  for (const key of ['value', 'data', 'result']) {
    const extracted = extractValue(record[key], depth + 1);
    if (extracted != null) return extracted;
  }
  return null;
}

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

export class EnterpriseIntegrationReadinessService {
  constructor(
    private readonly tenantSession: T3nSession,
    private readonly executorDelegationService: DelegationService,
    private readonly contractService: PrivacyGuardContractService,
  ) {}

  async status(): Promise<EnterpriseIntegrationReadiness> {
    const checkedAt = new Date().toISOString();
    try {
      const contractId = await this.contractService.canonicalContractId();
      const configuration = await this.readPrivateConfiguration();
      let executorDelegation: DelegationStatus;
      try {
        executorDelegation = await this.executorDelegationService.status(contractId);
      } catch {
        throw new ReadinessDiagnosticError('DELEGATION_UNAVAILABLE');
      }
      return evaluateEnterpriseIntegrationReadiness({ ...configuration, executorDelegation, checkedAt });
    } catch (error) {
      const diagnosticCode = error instanceof ReadinessDiagnosticError
        ? error.diagnosticCode
        : 'T3N_CONTROL_PLANE_UNAVAILABLE';
      return unknownEnterpriseIntegrationReadiness(checkedAt, diagnosticCode);
    }
  }

  private async readPrivateConfiguration(): Promise<PrivateConfiguration> {
    await this.tenantSession.connect();
    const tenant = new TenantClient({
      t3n: this.tenantSession.getClient(),
      baseUrl: getNodeUrl(),
      tenantDid: this.tenantSession.getTenantDid(),
    });
    await tenant.tenant.me();
    const executeControl = tenant.executeControl.bind(tenant) as (name: string, input: Record<string, string>) => Promise<unknown>;
    const readEntry = async (mapName: string, key: string): Promise<string | null> => extractValue(await executeControl('map-entry-get', { map_name: mapName, key }));
    const secretsMapName = tenant.canonicalName('secrets');
    const policyMapName = tenant.canonicalName('privacy-guard-policy');

    let policyRaw: string | null;
    try {
      policyRaw = await readEntry(policyMapName, 'current');
    } catch {
      throw new ReadinessDiagnosticError('POLICY_UNAVAILABLE');
    }
    if (!policyRaw) throw new ReadinessDiagnosticError('POLICY_UNAVAILABLE');

    let policy: OperationalPolicyDocument;
    try {
      policy = canonicalizeOperationalPolicy(JSON.parse(policyRaw) as unknown).document;
    } catch {
      throw new ReadinessDiagnosticError('POLICY_INVALID');
    }

    let executionUrl: string | null;
    let verificationUrl: string | null;
    let credential: string | null;
    try {
      [executionUrl, verificationUrl, credential] = await Promise.all([
        readEntry(secretsMapName, 'security_api_url'),
        readEntry(secretsMapName, 'security_verification_url'),
        readEntry(secretsMapName, 'security_api_key'),
      ]);
    } catch {
      throw new ReadinessDiagnosticError('PRIVATE_CONFIGURATION_UNAVAILABLE');
    }

    return {
      executionUrl: executionUrl?.trim() || null,
      verificationUrl: verificationUrl?.trim() || null,
      credentialConfigured: Boolean(credential?.trim()),
      policy,
    };
  }
}
