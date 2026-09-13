import { T3nClient } from '@terminal3/t3n-sdk';
import type { GatewayConfig } from '../config/env.js';
import { sanitizeError, type SanitizedError } from '../security/sanitize.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { authenticatePrincipal } from './authenticated-client.js';

export interface T3nSessionStatus {
  readonly connected: boolean;
  readonly ready: boolean;
  readonly tenantDid: string | null;
  readonly network: GatewayConfig['network'];
  readonly trustAnchorVerified: boolean;
  readonly trustManifestVersion: number | null;
  readonly lastError: SanitizedError | null;
}

export class T3nSession {
  private client: T3nClient | null = null;
  private tenantDid: string | null = null;
  private trustManifestVersion: number | null = null;
  private lastError: SanitizedError | null = null;
  private connecting: Promise<void> | null = null;

  constructor(
    private readonly config: GatewayConfig,
    private readonly trustFloorStore: TrustManifestFloorStore,
  ) {}

  getClient(): T3nClient {
    if (!this.client || !this.tenantDid) {
      throw new Error('T3N session is not authenticated');
    }
    return this.client;
  }

  getTenantDid(): string {
    if (!this.tenantDid) {
      throw new Error('T3N session is not authenticated');
    }
    return this.tenantDid;
  }

  getStatus(): T3nSessionStatus {
    const connected = this.client !== null && this.tenantDid !== null;
    return {
      connected,
      ready: connected && this.lastError === null,
      tenantDid: this.tenantDid,
      network: this.config.network,
      trustAnchorVerified: connected && this.trustManifestVersion !== null,
      trustManifestVersion: this.trustManifestVersion,
      lastError: this.lastError,
    };
  }

  async connect(): Promise<void> {
    if (this.getStatus().ready) return;
    if (this.connecting) return this.connecting;

    this.connecting = this.connectInternal();
    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private async connectInternal(): Promise<void> {
    try {
      const principal = await authenticatePrincipal(this.config.apiKey, this.config.network, this.trustFloorStore);
      this.client = principal.client;
      this.tenantDid = principal.did;
      this.trustManifestVersion = principal.trustManifestVersion;
      this.lastError = null;
    } catch (error) {
      this.client = null;
      this.tenantDid = null;
      this.trustManifestVersion = null;
      this.lastError = sanitizeError(error, [this.config.apiKey]);
      throw new Error(`${this.lastError.category}: ${this.lastError.message}`);
    }
  }
}
