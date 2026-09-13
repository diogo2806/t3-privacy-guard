import { T3nClient } from '@terminal3/t3n-sdk';
import type { GatewayConfig } from '../config/env.js';
import { sanitizeError, type SanitizedError } from '../security/sanitize.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { authenticatePrincipal } from '../t3n/authenticated-client.js';

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

export class AgentSession {
  private client: T3nClient | null = null;
  private agentDid: string | null = null;
  private trustManifestVersion: number | null = null;
  private lastError: SanitizedError | null = null;
  private connecting: Promise<void> | null = null;

  constructor(
    private readonly config: GatewayConfig,
    private readonly trustFloorStore: TrustManifestFloorStore,
    private readonly principalApiKey: string | null = config.agentApiKey,
    private readonly principalLabel: string = 'Agent',
  ) {}

  getClient(): T3nClient {
    if (!this.client || !this.agentDid) throw new Error(`${this.principalLabel} session is not authenticated`);
    return this.client;
  }

  getAgentDid(): string {
    if (!this.agentDid) throw new Error(`${this.principalLabel} session is not authenticated`);
    return this.agentDid;
  }

  getStatus(): AgentSessionStatus {
    const configured = Boolean(this.principalApiKey);
    const connected = this.client !== null && this.agentDid !== null;
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
      const principal = await authenticatePrincipal(apiKey, this.config.network, this.trustFloorStore);
      this.client = principal.client;
      this.agentDid = principal.did;
      this.trustManifestVersion = principal.trustManifestVersion;
      this.lastError = null;
    } catch (error) {
      this.client = null;
      this.agentDid = null;
      this.trustManifestVersion = null;
      this.lastError = sanitizeError(error, [apiKey]);
      throw new Error(`${this.lastError.category}: ${this.lastError.message}`);
    }
  }
}
