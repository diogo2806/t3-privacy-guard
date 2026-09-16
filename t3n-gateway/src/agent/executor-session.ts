import type { GatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import type { PrincipalIdentityGuard } from '../t3n/principal-identity.js';
import { AgentSession, type AgentSessionDependencies, type AgentSessionStatus } from './agent-session.js';

export interface ExecutorSessionStatus extends Omit<AgentSessionStatus, 'agentDid'> {
  readonly executorDid: string | null;
}

export class ExecutorSession extends AgentSession {
  constructor(
    config: GatewayConfig,
    trustFloorStore: TrustManifestFloorStore,
    identityGuard: PrincipalIdentityGuard | null = null,
    dependencies?: AgentSessionDependencies,
  ) {
    super(
      config,
      trustFloorStore,
      config.executorApiKey,
      'Protected executor',
      dependencies,
      identityGuard,
      'protected-executor',
    );
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
