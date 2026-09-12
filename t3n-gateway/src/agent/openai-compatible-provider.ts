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
      headers: { Authorization: `Bearer ${this.config.apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.config.model,
        temperature: 0,
        messages: [
          {
            role: 'system',
            content: 'You are an incident-response agent. Propose one structured action through the provided tool. Never decide authorization. Never invent, request or output private values. When a verified user email is operationally necessary, request only the logical private reference verified_email; never emit a {{profile.*}} placeholder. T3N policy decides authorization and resolves private references only inside protected egress.',
          },
          { role: 'user', content: prompt },
        ],
        tools: [{
          type: 'function',
          function: {
            name: 'propose_privacy_guard_action',
            description: 'Propose an incident-response action for independent T3N policy evaluation. Private data is represented only by logical references.',
            parameters: {
              type: 'object',
              additionalProperties: false,
              required: ['action', 'resource', 'purpose', 'fields', 'private_refs'],
              properties: {
                action: { type: 'string' },
                resource: { type: 'string' },
                purpose: { type: 'string' },
                host: { anyOf: [{ type: 'string' }, { type: 'null' }] },
                fields: { type: 'array', maxItems: 20, items: { type: 'string' } },
                private_refs: {
                  type: 'array', maxItems: 4, items: { type: 'string', enum: ['verified_email'] },
                  description: 'Logical T3N private-data references only. Never include plaintext or a {{profile.*}} marker.',
                },
              },
            },
          },
        }],
        tool_choice: { type: 'function', function: { name: 'propose_privacy_guard_action' } },
      }),
      signal: AbortSignal.timeout(20_000),
      redirect: 'manual',
    }).catch(() => { throw new AgentProviderUnavailableError(); });

    if (response.status >= 300 && response.status < 400) throw new AgentProviderUnavailableError('AI provider redirects are not allowed');
    if (!response.ok) throw new AgentProviderUnavailableError(`AI provider returned HTTP ${response.status}`);
    const payload = await response.json() as { choices?: Array<{ message?: { tool_calls?: Array<{ function?: { name?: string; arguments?: string } }> } }> };
    const calls = payload.choices?.[0]?.message?.tool_calls ?? [];
    if (calls.length !== 1 || calls[0]?.function?.name !== 'propose_privacy_guard_action') throw new Error('AGENT_TOOL_CALL_REQUIRED');
    const rawArguments = calls[0].function?.arguments;
    if (!rawArguments) throw new Error('AGENT_TOOL_CALL_INVALID');

    let parsed: unknown;
    try { parsed = JSON.parse(rawArguments); }
    catch { throw new Error('AGENT_TOOL_CALL_INVALID_JSON'); }

    return { provider: 'openai-compatible', model: this.config.model, proposal: validateAgentProposal(parsed) };
  }
}
