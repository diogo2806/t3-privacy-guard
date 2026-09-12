export type T3nNetwork = 'testnet' | 'production';
export type AiProvider = 'disabled' | 'openai-compatible';

export interface GatewayConfig {
  readonly apiKey: string;
  readonly agentApiKey: string | null;
  readonly network: T3nNetwork;
  readonly port: number;
  readonly contractTail: string;
  readonly contractVersion: string;
  readonly gatewayServiceToken: string;
  readonly remediationCapabilityKey: string;
  readonly remediationReplayStorePath: string;
  readonly aiProvider: AiProvider;
  readonly aiApiUrl: string | null;
  readonly aiApiKey: string | null;
  readonly aiModel: string | null;
}

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

function requiredSecret(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value || value.length < 32) throw new ConfigurationError(`${name} is required and must contain at least 32 characters`);
  return value;
}

export function readGatewayConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const apiKey = env.T3N_API_KEY?.trim();
  if (!apiKey) throw new ConfigurationError('T3N_API_KEY is required and must be provided through the runtime environment');

  const agentApiKey = env.T3N_AGENT_API_KEY?.trim() || null;
  if (agentApiKey && agentApiKey === apiKey) throw new ConfigurationError('T3N_AGENT_API_KEY must be different from T3N_API_KEY');

  const networkValue = (env.T3N_NETWORK ?? 'testnet').trim().toLowerCase();
  if (networkValue !== 'testnet' && networkValue !== 'production') throw new ConfigurationError('T3N_NETWORK must be either testnet or production');

  const portValue = Number(env.T3N_GATEWAY_PORT ?? 3001);
  if (!Number.isInteger(portValue) || portValue < 1 || portValue > 65535) throw new ConfigurationError('T3N_GATEWAY_PORT must be a valid TCP port');

  const contractTail = (env.T3N_CONTRACT_TAIL ?? 'privacy-guard').trim();
  if (!/^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,127}$/.test(contractTail)) throw new ConfigurationError('T3N_CONTRACT_TAIL has an invalid format');

  const contractVersion = (env.T3N_CONTRACT_VERSION ?? '0.3.0').trim();
  if (!/^\d+\.\d+\.\d+$/.test(contractVersion)) throw new ConfigurationError('T3N_CONTRACT_VERSION must be semantic version MAJOR.MINOR.PATCH');

  const aiProviderValue = (env.AI_PROVIDER ?? 'disabled').trim().toLowerCase();
  if (aiProviderValue !== 'disabled' && aiProviderValue !== 'openai-compatible') throw new ConfigurationError('AI_PROVIDER must be disabled or openai-compatible');
  let aiApiUrl: string | null = null;
  let aiApiKey: string | null = null;
  let aiModel: string | null = null;
  if (aiProviderValue === 'openai-compatible') {
    aiApiUrl = env.AI_API_URL?.trim() || 'https://api.openai.com/v1/chat/completions';
    aiApiKey = env.AI_API_KEY?.trim() || null;
    aiModel = env.AI_MODEL?.trim() || null;
    if (!aiApiKey || !aiModel) throw new ConfigurationError('AI_API_KEY and AI_MODEL are required when AI_PROVIDER=openai-compatible');
    let parsed: URL;
    try { parsed = new URL(aiApiUrl); } catch { throw new ConfigurationError('AI_API_URL must be a valid URL'); }
    if (!['https:', 'http:'].includes(parsed.protocol)) throw new ConfigurationError('AI_API_URL must use http or https');
  }

  return {
    apiKey,
    agentApiKey,
    network: networkValue,
    port: portValue,
    contractTail,
    contractVersion,
    gatewayServiceToken: requiredSecret(env, 'GATEWAY_SERVICE_TOKEN'),
    remediationCapabilityKey: requiredSecret(env, 'REMEDIATION_CAPABILITY_KEY'),
    remediationReplayStorePath: (env.REMEDIATION_REPLAY_STORE_PATH ?? '/data/remediation-capability-nonces.json').trim(),
    aiProvider: aiProviderValue,
    aiApiUrl,
    aiApiKey,
    aiModel,
  };
}
