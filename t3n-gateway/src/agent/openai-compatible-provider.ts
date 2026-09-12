import { AgentProviderUnavailableError, type AgentProvider, type AgentProviderResult } from './agent-provider.js';
import { validateAgentProposal } from './proposal-schema.js';

interface ProviderConfig {
  apiUrl: string;
  apiKey: string;
  model: string;
}

export class OpenAiCompatibleProvider implements AgentProvider {
  constructor(private readonly config: ProviderConfig) {}

  async propose(prompt: string): Promise<AgentProviderResult> {
    if (!prompt.trim() || prompt.length > 4_000) throw new Error('AGENT_PROMPT_INVALID');

    const response = await fetch(this.config.apiUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: this.config.model,
        temperature: 0,
        messages: [
          {
            role: 'system',
            content: 'You are an incident-response agent. Propose one structured action through the provided tool. Never decide authorization. Never invent or request secret values. T3N policy decides whether the proposal is allowed.',
          },
          { role: 'user', content: prompt },
        ],
        tools: [{
          type: 'function',
          function: {
            name: 'propose_privacy_guard_action',
            description: 'Propose an incident-response action for independent T3N policy evaluation.',
            parameters: {
              type: 'object',
              additionalProperties: false,
              required: ['action', 'resource', 'purpose', 'fields'],
              properties: {
                action: { type: 'string' },
                resource: { type: 'string' },
                purpose: { type: 'string' },
                host: { anyOf: [{ type: 'string' }, { type: 'null' }] },
                fields: { type: 'array', maxItems: 20, items: { type: 'string' } },
              },
            },
          },
        }],
        tool_choice: { type: 'function', function: { name: 'propose_privacy_guard_action' } },
      }),
      signal: AbortSignal.timeout(20_000),
    }).catch(() => { throw new AgentProviderUnavailableError(); });

    if (!response.ok) throw new AgentProviderUnavailableError(`AI provider returned HTTP ${response.status}`);
    const payload = await response.json() as {
      choices?: Array<{ message?: { tool_calls?: Array<{ function?: { name?: string; arguments?: string } }> } }>;
    };
    const calls = payload.choices?.[0]?.message?.tool_calls ?? [];
    if (calls.length !== 1 || calls[0]?.function?.name !== 'propose_privacy_guard_action') {
      throw new Error('AGENT_TOOL_CALL_REQUIRED');
    }
    const rawArguments = calls[0].function?.arguments;
    if (!rawArguments) throw new Error('AGENT_TOOL_CALL_INVALID');

    let parsed: unknown;
    try { parsed = JSON.parse(rawArguments); }
    catch { throw new Error('AGENT_TOOL_CALL_INVALID_JSON'); }

    return {
      provider: 'openai-compatible',
      model: this.config.model,
      proposal: validateAgentProposal(parsed),
    };
  }
}
