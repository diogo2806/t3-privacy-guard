import { T3nClient } from '@terminal3/t3n-sdk';
import type { GatewayConfig } from '../config/env.js';
import { sanitizeError, type SanitizedError } from '../security/sanitize.js';
import { authenticatePrincipal } from './authenticated-client.js';

export interface T3nSessionStatus {
  readonly connected: boolean;
  readonly ready: boolean;
  readonly tenantDid: string | null;
  readonly network: GatewayConfig['network'];
  readonly lastError: SanitizedError | null;
}

export class T3nSession {
  private client: T3nClient | null = null;
  private tenantDid: string | null = null;
  private lastError: SanitizedError | null = null;
  private connecting: Promise<void> | null = null;

  constructor(private readonly config: GatewayConfig) {}

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
    return {
      connected: this.client !== null && this.tenantDid !== null,
      ready: this.client !== null && this.tenantDid !== null && this.lastError === null,
      tenantDid: this.tenantDid,
      network: this.config.network,
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
      const principal = await authenticatePrincipal(this.config.apiKey, this.config.network);
      this.client = principal.client;
      this.tenantDid = principal.did;
      this.lastError = null;
    } catch (error) {
      this.client = null;
      this.tenantDid = null;
      this.lastError = sanitizeError(error, [this.config.apiKey]);
      throw new Error(`${this.lastError.category}: ${this.lastError.message}`);
    }
  }
}
