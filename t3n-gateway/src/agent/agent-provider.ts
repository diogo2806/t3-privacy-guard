import type { AgentProposal } from './proposal-schema.js';

export interface AgentProviderResult {
  readonly provider: string;
  readonly model: string;
  readonly proposal: AgentProposal;
}

export interface AgentProvider {
  propose(prompt: string): Promise<AgentProviderResult>;
}

export class AgentProviderUnavailableError extends Error {
  constructor(message = 'AI agent provider is unavailable') {
    super(message);
    this.name = 'AgentProviderUnavailableError';
  }
}
