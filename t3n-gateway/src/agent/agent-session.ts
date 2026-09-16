import type { T3nClient } from '@terminal3/t3n-sdk';
import type { GatewayConfig } from '../config/env.js';
import { sanitizeError, type SanitizedError } from '../security/sanitize.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import {
  authenticateOrgAgentPrincipal,
  authenticatePrincipal,
  checkOrgAgentDelegation,
  classifyPrincipalCredential,
  invokeOrgAgent,
  type PrincipalCredentialKind,
  type PrincipalDelegationCheckRequest,
  type PrincipalExecutionRequest,
} from '../t3n/authenticated-client.js';

export interface AgentSessionStatus {
  readonly configured: boolean;
  readonly connected: boolean;
  readonly ready: boolean;
  readonly agentDid: string | null;
  readonly network: GatewayConfig['network'];
  readonly trustAnchorVerified: boolean;
  readonly trustManifestVersion: number | null;
  readonly lastError: SanitizedError | null;
}

export interface AgentPrincipalClient {
  executeAndDecode<T = unknown>(request: PrincipalExecutionRequest): Promise<T>;
  checkDelegation(request: PrincipalDelegationCheckRequest): Promise<unknown>;
}

export interface AgentSessionDependencies {
  readonly authenticateSecp256k1: typeof authenticatePrincipal;
  readonly authenticateOrgAgent: typeof authenticateOrgAgentPrincipal;
  readonly invokeOrgAgent: typeof invokeOrgAgent;
  readonly checkOrgAgentDelegation: typeof checkOrgAgentDelegation;
}

const DEFAULT_DEPENDENCIES: AgentSessionDependencies = Object.freeze({
  authenticateSecp256k1: authenticatePrincipal,
  authenticateOrgAgent: authenticateOrgAgentPrincipal,
  invokeOrgAgent,
  checkOrgAgentDelegation,
});

export class AgentSession {
  private client: T3nClient | null = null;
  private credentialKind: PrincipalCredentialKind | null = null;
  private agentDid: string | null = null;
  private trustManifestVersion: number | null = null;
  private lastError: SanitizedError | null = null;
  private connecting: Promise<void> | null = null;

  constructor(
    private readonly config: GatewayConfig,
    private readonly trustFloorStore: TrustManifestFloorStore,
    private readonly principalApiKey: string | null = config.agentApiKey,
    private readonly principalLabel: string = 'Agent',
    private readonly dependencies: AgentSessionDependencies = DEFAULT_DEPENDENCIES,
  ) {}

  getClient(): AgentPrincipalClient {
    if (!this.agentDid || !this.credentialKind || !this.principalApiKey) {
      throw new Error(`${this.principalLabel} session is not authenticated`);
    }

    if (this.credentialKind === 'secp256k1') {
      if (!this.client) throw new Error(`${this.principalLabel} session is not authenticated`);
      const client = this.client;
      return {
        executeAndDecode: <T = unknown>(request: PrincipalExecutionRequest) => client.executeAndDecode(request) as Promise<T>,
        checkDelegation: (request: PrincipalDelegationCheckRequest) => client.checkDelegation(request),
      };
    }

    const apiKey = this.principalApiKey;
    return {
      executeAndDecode: async <T = unknown>(request: PrincipalExecutionRequest): Promise<T> => {
        try {
          return await this.dependencies.invokeOrgAgent<T>(apiKey, this.config.network, request);
        } catch (error) {
          throw this.sanitizedTransportError(error, apiKey);
        }
      },
      checkDelegation: async (request: PrincipalDelegationCheckRequest): Promise<unknown> => {
        try {
          return await this.dependencies.checkOrgAgentDelegation(apiKey, this.config.network, request);
        } catch (error) {
          throw this.sanitizedTransportError(error, apiKey);
        }
      },
    };
  }

  getAgentDid(): string {
    if (!this.agentDid) throw new Error(`${this.principalLabel} session is not authenticated`);
    return this.agentDid;
  }

  getStatus(): AgentSessionStatus {
    const configured = Boolean(this.principalApiKey);
    const connected = this.credentialKind !== null && this.agentDid !== null;
    return {
      configured,
      connected,
      ready: configured && connected && this.lastError === null,
      agentDid: this.agentDid,
      network: this.config.network,
      trustAnchorVerified: connected && this.trustManifestVersion !== null,
      trustManifestVersion: this.trustManifestVersion,
      lastError: this.lastError,
    };
  }

  async connect(): Promise<void> {
    if (!this.principalApiKey) throw new Error(`${this.principalLabel} T3N key is not configured`);
    if (this.getStatus().ready) return;
    if (this.connecting) return this.connecting;

    this.connecting = this.connectInternal(this.principalApiKey);
    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private async connectInternal(apiKey: string): Promise<void> {
    try {
      const credentialKind = classifyPrincipalCredential(apiKey);
      if (credentialKind === 'secp256k1') {
        const principal = await this.dependencies.authenticateSecp256k1(apiKey, this.config.network, this.trustFloorStore);
        this.client = principal.client;
        this.agentDid = principal.did;
        this.trustManifestVersion = principal.trustManifestVersion;
      } else {
        const principal = await this.dependencies.authenticateOrgAgent(apiKey, this.config.network, this.trustFloorStore);
        this.client = null;
        this.agentDid = principal.did;
        this.trustManifestVersion = principal.trustManifestVersion;
      }
      this.credentialKind = credentialKind;
      this.lastError = null;
    } catch (error) {
      this.client = null;
      this.credentialKind = null;
      this.agentDid = null;
      this.trustManifestVersion = null;
      this.lastError = sanitizeError(error, [apiKey]);
      throw new Error(`${this.lastError.category}: ${this.lastError.message}`);
    }
  }

  private sanitizedTransportError(error: unknown, apiKey: string): Error {
    const sanitized = sanitizeError(error, [apiKey]);
    return new Error(`${sanitized.category}: ${sanitized.message}`);
  }
}
