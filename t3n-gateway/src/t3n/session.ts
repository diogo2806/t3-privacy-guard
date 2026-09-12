import {
  T3nClient,
  createEthAuthInput,
  eth_get_address,
  fetchTrustedManifest,
  loadWasmComponent,
  metamask_sign,
  setEnvironment,
} from '@terminal3/t3n-sdk';
import type { GatewayConfig } from '../config/env.js';
import { sanitizeError, type SanitizedError } from '../security/sanitize.js';

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
    if (this.getStatus().ready) {
      return;
    }
    if (this.connecting) {
      return this.connecting;
    }

    this.connecting = this.connectInternal();
    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private async connectInternal(): Promise<void> {
    try {
      setEnvironment(this.config.network);
      const wasmComponent = await loadWasmComponent();
      const address = eth_get_address(this.config.apiKey);
      const trustAnchor = await fetchTrustedManifest(this.config.network);
      const client = new T3nClient({
        trustAnchor,
        wasmComponent,
        handlers: {
          EthSign: metamask_sign(address, undefined, this.config.apiKey),
        },
      });

      await client.handshake();
      const did = await client.authenticate(createEthAuthInput(address));

      this.client = client;
      this.tenantDid = did.value;
      this.lastError = null;
    } catch (error) {
      this.client = null;
      this.tenantDid = null;
      this.lastError = sanitizeError(error, [this.config.apiKey]);
      throw new Error(`${this.lastError.category}: ${this.lastError.message}`);
    }
  }
}
