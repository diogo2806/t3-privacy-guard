import type { GatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { AgentSession, type AgentSessionStatus } from './agent-session.js';

export interface ExecutorSessionStatus extends Omit<AgentSessionStatus, 'agentDid'> {
  readonly executorDid: string | null;
}

export class ExecutorSession extends AgentSession {
  constructor(config: GatewayConfig, trustFloorStore: TrustManifestFloorStore) {
    super(config, trustFloorStore, config.executorApiKey, 'Protected executor');
  }

  getExecutorDid(): string {
    return this.getAgentDid();
  }

  getExecutorStatus(): ExecutorSessionStatus {
    const status = this.getStatus();
    const { agentDid, ...rest } = status;
    return { ...rest, executorDid: agentDid };
  }
}
