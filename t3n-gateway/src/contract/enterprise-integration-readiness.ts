import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import type { DelegationService, DelegationStatus } from '../agent/delegation-service.js';
import { canonicalizeOperationalPolicy, type OperationalPolicyDocument } from '../policy/policy-document.js';
import type { T3nSession } from '../t3n/session.js';
import type { PrivacyGuardContractService } from './privacy-guard-contract.js';

export type EnterpriseIntegrationState = 'READY' | 'INCOMPLETE' | 'MISMATCH' | 'UNKNOWN';

export interface EnterpriseVerificationContract {
  readonly action: string;
  readonly expectedState: string;
}

export interface EnterpriseIntegrationReadiness {
  readonly state: EnterpriseIntegrationState;
  readonly executionConfigured: boolean;
  readonly verificationConfigured: boolean;
  readonly credentialConfigured: boolean;
  readonly executionHost: string | null;
  readonly verificationHost: string | null;
  readonly policyAllowsExecutionHost: boolean;
  readonly policyAllowsVerificationHost: boolean;
  readonly executorDelegationAllowsExecutionHost: boolean;
  readonly executorDelegationAllowsVerificationHost: boolean;
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
    throw new Error('Enterprise integration endpoint must be an HTTPS URL without embedded credentials');
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

function unknownReadiness(checkedAt: string): EnterpriseIntegrationReadiness {
  return {
    state: 'UNKNOWN',
    executionConfigured: false,
    verificationConfigured: false,
    credentialConfigured: false,
    executionHost: null,
    verificationHost: null,
    policyAllowsExecutionHost: false,
    policyAllowsVerificationHost: false,
    executorDelegationAllowsExecutionHost: false,
    executorDelegationAllowsVerificationHost: false,
    supportedExecutableActions: VERIFICATION_CONTRACTS.map(({ action }) => action),
    supportedVerifiedActions: VERIFICATION_CONTRACTS.map(({ action }) => action),
    verificationContracts: VERIFICATION_CONTRACTS.map((contract) => ({ ...contract })),
    evaluationOnlyActions: [],
    checkedAt,
  };
}

export function evaluateEnterpriseIntegrationReadiness(input: EnterpriseIntegrationInputs): EnterpriseIntegrationReadiness {
  try {
    const executionHost = canonicalHttpsHost(input.executionUrl);
    const verificationHost = canonicalHttpsHost(input.verificationUrl);
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
    const delegationActive = input.executorDelegation.memberState === 'ACTIVE' && input.executorDelegation.effectiveState === 'ACTIVE';
    const executorDelegationAllowsExecutionHost = executionHost != null && delegationActive && executorHosts.has(executionHost);
    const executorDelegationAllowsVerificationHost = verificationHost != null && delegationActive && executorHosts.has(verificationHost);

    let state: EnterpriseIntegrationState;
    if (!executionConfigured || !verificationConfigured || !input.credentialConfigured || isDemoHost(executionHost) || isDemoHost(verificationHost)) {
      state = 'INCOMPLETE';
    } else if (input.executorDelegation.memberState === 'UNKNOWN' || input.executorDelegation.effectiveState === 'UNKNOWN') {
      state = 'UNKNOWN';
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
  } catch {
    return unknownReadiness(input.checkedAt);
  }
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
      const [configuration, executorDelegation] = await Promise.all([
        this.readPrivateConfiguration(),
        this.executorDelegationService.status(contractId),
      ]);
      return evaluateEnterpriseIntegrationReadiness({ ...configuration, executorDelegation, checkedAt });
    } catch {
      return unknownReadiness(checkedAt);
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
    const readOptionalEntry = async (mapName: string, key: string): Promise<string | null> => {
      try {
        return await readEntry(mapName, key);
      } catch {
        return null;
      }
    };
    const secretsMapName = tenant.canonicalName('secrets');
    const policyMapName = tenant.canonicalName('privacy-guard-policy');
    const policyRaw = await readEntry(policyMapName, 'current');
    if (!policyRaw) throw new Error('Active operational policy is unavailable');
    const [executionUrl, verificationUrl, credential] = await Promise.all([
      readOptionalEntry(secretsMapName, 'security_api_url'),
      readOptionalEntry(secretsMapName, 'security_verification_url'),
      readOptionalEntry(secretsMapName, 'security_api_key'),
    ]);
    const policy = canonicalizeOperationalPolicy(JSON.parse(policyRaw) as unknown).document;
    return {
      executionUrl: executionUrl?.trim() || null,
      verificationUrl: verificationUrl?.trim() || null,
      credentialConfigured: Boolean(credential?.trim()),
      policy,
    };
  }
}
