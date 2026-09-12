import { assertPromptSafeForExternalProvider } from '../security/prompt-privacy-guard.js';
import type { AgentProvider, AgentProviderResult } from './agent-provider.js';

export class AgentService {
  constructor(private readonly provider: AgentProvider | null) {}

  async propose(prompt: string): Promise<AgentProviderResult> {
    if (!this.provider) throw new Error('AI_PROVIDER_DISABLED');
    const normalized = prompt.trim();
    if (!normalized || normalized.length > 4_000) throw new Error('AGENT_PROMPT_INVALID');
    assertPromptSafeForExternalProvider(normalized);
    return this.provider.propose(normalized);
  }
}
