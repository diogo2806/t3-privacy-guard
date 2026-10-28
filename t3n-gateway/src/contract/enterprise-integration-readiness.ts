import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import type { DelegationService, DelegationStatus } from '../agent/delegation-service.js';
import { canonicalizeOperationalPolicy, type OperationalPolicyDocument } from '../policy/policy-document.js';
import {
  AdministrativePrivateMapError,
  readAdministrativePrivateMapEntry,
} from '../t3n/administrative-private-map.js';
import type { T3nSession } from '../t3n/session.js';
import type { PrivacyGuardContractService } from './privacy-guard-contract.js';
import {
  evaluateEnterpriseIntegrationReadiness,
  unknownEnterpriseIntegrationReadiness,
  type EnterpriseIntegrationDiagnosticCode,
  type EnterpriseIntegrationReadiness,
} from './enterprise-readiness-rules.js';

export * from './enterprise-readiness-rules.js';

export interface EnterprisePrivateConfiguration {
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

function rethrowReadinessMapDiagnostic(
  error: unknown,
  fallbackCode: EnterpriseIntegrationDiagnosticCode,
): never {
  if (error instanceof AdministrativePrivateMapError && error.diagnosticCode === 'INSUFFICIENT_CREDIT') {
    throw new ReadinessDiagnosticError('INSUFFICIENT_CREDIT');
  }
  throw new ReadinessDiagnosticError(fallbackCode);
}

export async function readEnterprisePrivateConfigurationFromTenant(
  tenant: TenantClient,
): Promise<EnterprisePrivateConfiguration> {
  const readEntry = async (mapTail: string, key: string): Promise<string | null> =>
    readAdministrativePrivateMapEntry(tenant, mapTail, key);

  let policyRaw: string | null;
  try {
    policyRaw = await readEntry('privacy-guard-policy', 'current');
  } catch (error) {
    rethrowReadinessMapDiagnostic(error, 'POLICY_UNAVAILABLE');
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
      readEntry('secrets', 'security_api_url'),
      readEntry('secrets', 'security_verification_url'),
      readEntry('secrets', 'security_api_key'),
    ]);
  } catch (error) {
    rethrowReadinessMapDiagnostic(error, 'PRIVATE_CONFIGURATION_UNAVAILABLE');
  }

  return {
    executionUrl: executionUrl?.trim() || null,
    verificationUrl: verificationUrl?.trim() || null,
    credentialConfigured: Boolean(credential?.trim()),
    policy,
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

  private async readPrivateConfiguration(): Promise<EnterprisePrivateConfiguration> {
    await this.tenantSession.connect();
    const tenant = new TenantClient({
      t3n: this.tenantSession.getClient(),
      baseUrl: getNodeUrl(),
      tenantDid: this.tenantSession.getTenantDid(),
    });
    await tenant.tenant.me();
    return readEnterprisePrivateConfigurationFromTenant(tenant);
  }
}
