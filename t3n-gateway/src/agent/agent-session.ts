import { T3nClient } from '@terminal3/t3n-sdk';
import type { GatewayConfig } from '../config/env.js';
import { sanitizeError, type SanitizedError } from '../security/sanitize.js';
import { authenticatePrincipal } from '../t3n/authenticated-client.js';

export interface AgentSessionStatus {
  readonly configured: boolean;
  readonly connected: boolean;
  readonly ready: boolean;
  readonly agentDid: string | null;
  readonly network: GatewayConfig['network'];
  readonly lastError: SanitizedError | null;
}

export class AgentSession {
  private client: T3nClient | null = null;
  private agentDid: string | null = null;
  private lastError: SanitizedError | null = null;
  private connecting: Promise<void> | null = null;

  constructor(private readonly config: GatewayConfig) {}

  getClient(): T3nClient {
    if (!this.client || !this.agentDid) throw new Error('Agent session is not authenticated');
    return this.client;
  }

  getAgentDid(): string {
    if (!this.agentDid) throw new Error('Agent session is not authenticated');
    return this.agentDid;
  }

  getStatus(): AgentSessionStatus {
    const configured = Boolean(this.config.agentApiKey);
    return {
      configured,
      connected: this.client !== null && this.agentDid !== null,
      ready: configured && this.client !== null && this.agentDid !== null && this.lastError === null,
      agentDid: this.agentDid,
      network: this.config.network,
      lastError: this.lastError,
    };
  }

  async connect(): Promise<void> {
    if (!this.config.agentApiKey) throw new Error('T3N agent key is not configured');
    if (this.getStatus().ready) return;
    if (this.connecting) return this.connecting;

    this.connecting = this.connectInternal(this.config.agentApiKey);
    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private async connectInternal(agentApiKey: string): Promise<void> {
    try {
      const principal = await authenticatePrincipal(agentApiKey, this.config.network);
      this.client = principal.client;
      this.agentDid = principal.did;
      this.lastError = null;
    } catch (error) {
      this.client = null;
      this.agentDid = null;
      this.lastError = sanitizeError(error, [agentApiKey]);
      throw new Error(`${this.lastError.category}: ${this.lastError.message}`);
    }
  }
}
