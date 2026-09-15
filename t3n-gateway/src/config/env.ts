import { createPublicKey } from 'node:crypto';

export type T3nNetwork = 'testnet' | 'production';
export type AiProvider = 'disabled' | 'openai-compatible';

export interface GatewayConfig {
  readonly apiKey: string;
  readonly agentApiKey: string | null;
  readonly executorApiKey: string | null;
  readonly network: T3nNetwork;
  readonly port: number;
  readonly contractTail: string;
  readonly contractVersion: string;
  readonly gatewayServiceToken: string;
  readonly remediationAuthorizationPublicKeySpki: string;
  readonly remediationAuthorizationKeyId: string;
  readonly remediationReplayStorePath: string;
  readonly trustManifestFloorStorePath: string;
  readonly aiProvider: AiProvider;
  readonly aiApiUrl: string | null;
  readonly aiApiKey: string | null;
  readonly aiModel: string | null;
  readonly a2aPublicUrl: string | null;
  readonly remediationCapabilityKey?: undefined;
}

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

const DOCUMENTATION_PLACEHOLDER_PREFIX = 'replace-with-';
const PUBLIC_KEY_PEM_BEGIN = '-----BEGIN PUBLIC KEY-----';
const PUBLIC_KEY_PEM_END = '-----END PUBLIC KEY-----';

export function rejectDocumentationPlaceholder(value: string, name: string): void {
  if (value.trim().startsWith(DOCUMENTATION_PLACEHOLDER_PREFIX)) {
    throw new ConfigurationError(`${name} must be replaced with a runtime-specific value`);
  }
}

function requiredSecret(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value || value.length < 32) throw new ConfigurationError(`${name} is required and must contain at least 32 characters`);
  rejectDocumentationPlaceholder(value, name);
  return value;
}

function requiredKeyId(env: NodeJS.ProcessEnv, name: string, fallback: string): string {
  const raw = env[name];
  const value = raw === undefined ? fallback : raw.trim();
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(value)) throw new ConfigurationError(`${name} must match [A-Za-z0-9._-]{1,32}`);
  return value;
}

function decodeBase64Strict(value: string): Buffer {
  const compact = value.replace(/\s+/g, '');
  if (!compact || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 !== 0) {
    throw new Error('invalid base64');
  }
  const decoded = Buffer.from(compact, 'base64');
  if (!decoded.length || decoded.toString('base64') !== compact) throw new Error('invalid base64');
  return decoded;
}

function decodePublicKeyPem(value: string): Buffer {
  const trimmed = value.trim();
  if (!trimmed.startsWith(PUBLIC_KEY_PEM_BEGIN)) throw new Error('invalid public key PEM');
  const endIndex = trimmed.indexOf(PUBLIC_KEY_PEM_END, PUBLIC_KEY_PEM_BEGIN.length);
  if (endIndex < 0) throw new Error('invalid public key PEM');
  if (trimmed.slice(endIndex + PUBLIC_KEY_PEM_END.length).trim()) throw new Error('invalid public key PEM');
  const body = trimmed.slice(PUBLIC_KEY_PEM_BEGIN.length, endIndex);
  return decodeBase64Strict(body);
}

function decodeEd25519PublicKey(value: string): Buffer {
  const trimmed = value.trim();
  if (trimmed.startsWith(PUBLIC_KEY_PEM_BEGIN)) return decodePublicKeyPem(trimmed);

  const decoded = decodeBase64Strict(trimmed);
  const decodedText = decoded.toString('ascii').trim();
  if (decodedText.startsWith(PUBLIC_KEY_PEM_BEGIN)) return decodePublicKeyPem(decodedText);
  return decoded;
}

function requiredEd25519PublicKey(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new ConfigurationError(`${name} is required`);
  try {
    const der = decodeEd25519PublicKey(value);
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
    return der.toString('base64');
  } catch {
    throw new ConfigurationError(`${name} must be an Ed25519 SPKI public key encoded as DER base64, PEM, or base64-wrapped PEM`);
  }
}

function requiredPath(env: NodeJS.ProcessEnv, name: string, fallback: string): string {
  const raw = env[name];
  if (raw !== undefined && !raw.trim()) throw new ConfigurationError(`${name} must not be empty`);
  return raw?.trim() || fallback;
}

function ipv4Octets(hostname: string): number[] | null {
  const parts = hostname.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const octets = parts.map((part) => Number(part));
  return octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255) ? octets : null;
}

function isIpv4Loopback(hostname: string): boolean {
  return ipv4Octets(hostname)?.[0] === 127;
}

function isNonPublicIpv4(hostname: string): boolean {
  const octets = ipv4Octets(hostname);
  if (!octets) return false;
  const [first, second, third] = octets;
  if (first === 0 || first === 10 || first === 127 || first >= 224) return true;
  if (first === 100 && second >= 64 && second <= 127) return true;
  if (first === 169 && second === 254) return true;
  if (first === 172 && second >= 16 && second <= 31) return true;
  if (first === 192 && second === 168) return true;
  if (first === 192 && second === 0) return true;
  if (first === 192 && second === 0 && third === 2) return true;
  if (first === 198 && (second === 18 || second === 19)) return true;
  if (first === 198 && second === 51 && third === 100) return true;
  if (first === 203 && second === 0 && third === 113) return true;
  return false;
}

function isNonPublicHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  if (normalized === 'localhost' || normalized.endsWith('.localhost') || normalized.endsWith('.local')) return true;
  if (isNonPublicIpv4(normalized)) return true;
  if (!normalized.startsWith('[') || !normalized.endsWith(']')) return false;
  const ipv6 = normalized.slice(1, -1);
  return ipv6 === '::'
    || ipv6 === '::1'
    || ipv6.startsWith('fc')
    || ipv6.startsWith('fd')
    || /^fe[89ab]/.test(ipv6)
    || ipv6.startsWith('ff')
    || ipv6 === '2001:db8::'
    || ipv6.startsWith('2001:db8:')
    || ipv6.startsWith('::ffff:');
}

export function validateAiProviderUrl(parsed: URL): URL {
  if (parsed.username || parsed.password) throw new ConfigurationError('AI_API_URL must not contain embedded credentials');
  if (parsed.protocol === 'https:') return parsed;
  if (parsed.protocol !== 'http:') throw new ConfigurationError('AI_API_URL must use https for remote providers or http only on loopback');

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const loopback = hostname === 'localhost' || hostname === '[::1]' || isIpv4Loopback(hostname);
  if (!loopback) throw new ConfigurationError('AI_API_URL must use https for remote providers; http is allowed only on loopback');
  return parsed;
}

export function validateA2aPublicUrl(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new ConfigurationError('A2A_PUBLIC_URL must be a valid absolute URL'); }
  if (parsed.protocol !== 'https:') throw new ConfigurationError('A2A_PUBLIC_URL must use HTTPS');
  if (parsed.username || parsed.password) throw new ConfigurationError('A2A_PUBLIC_URL must not contain embedded credentials');
  if (parsed.search || parsed.hash) throw new ConfigurationError('A2A_PUBLIC_URL must not contain query parameters or fragments');
  if (!parsed.hostname || isNonPublicHostname(parsed.hostname)) throw new ConfigurationError('A2A_PUBLIC_URL must contain a public hostname');
  const normalizedPath = parsed.pathname.replace(/\/+$/, '');
  if (!normalizedPath.endsWith('/a2a')) throw new ConfigurationError('A2A_PUBLIC_URL must point to the public /a2a endpoint');
  parsed.pathname = normalizedPath;
  return parsed.toString();
}

export function readGatewayConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const apiKey = env.T3N_API_KEY?.trim();
  if (!apiKey) throw new ConfigurationError('T3N_API_KEY is required and must be provided through the runtime environment');

  const agentApiKey = env.T3N_AGENT_API_KEY?.trim() || null;
  if (agentApiKey && agentApiKey === apiKey) throw new ConfigurationError('T3N_AGENT_API_KEY must be different from T3N_API_KEY');

  const executorApiKey = env.T3N_EXECUTOR_API_KEY?.trim() || null;
  if (executorApiKey && executorApiKey === apiKey) throw new ConfigurationError('T3N_EXECUTOR_API_KEY must be different from T3N_API_KEY');
  if (executorApiKey && agentApiKey && executorApiKey === agentApiKey) throw new ConfigurationError('T3N_EXECUTOR_API_KEY must be different from T3N_AGENT_API_KEY');

  const networkValue = (env.T3N_NETWORK ?? 'testnet').trim().toLowerCase();
  if (networkValue !== 'testnet' && networkValue !== 'production') throw new ConfigurationError('T3N_NETWORK must be either testnet or production');

  const portValue = Number(env.T3N_GATEWAY_PORT ?? 3001);
  if (!Number.isInteger(portValue) || portValue < 1 || portValue > 65535) throw new ConfigurationError('T3N_GATEWAY_PORT must be a valid TCP port');

  const contractTail = (env.T3N_CONTRACT_TAIL ?? 'privacy-guard').trim();
  if (!/^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,127}$/.test(contractTail)) throw new ConfigurationError('T3N_CONTRACT_TAIL has an invalid format');

  const contractVersion = (env.T3N_CONTRACT_VERSION ?? '0.4.0').trim();
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
    validateAiProviderUrl(parsed);
  }

  const a2aPublicUrlRaw = env.A2A_PUBLIC_URL?.trim() || null;
  const a2aPublicUrl = a2aPublicUrlRaw ? validateA2aPublicUrl(a2aPublicUrlRaw) : null;

  return {
    apiKey,
    agentApiKey,
    executorApiKey,
    network: networkValue,
    port: portValue,
    contractTail,
    contractVersion,
    gatewayServiceToken: requiredSecret(env, 'GATEWAY_SERVICE_TOKEN'),
    remediationAuthorizationPublicKeySpki: requiredEd25519PublicKey(env, 'REMEDIATION_AUTH_PUBLIC_KEY_SPKI'),
    remediationAuthorizationKeyId: requiredKeyId(env, 'REMEDIATION_AUTH_KEY_ID', 'primary'),
    remediationReplayStorePath: requiredPath(env, 'REMEDIATION_REPLAY_STORE_PATH', '/data/remediation-capability-nonces.json'),
    trustManifestFloorStorePath: requiredPath(env, 'T3N_TRUST_FLOOR_STORE_PATH', '/data/t3n-trust-floor.json'),
    aiProvider: aiProviderValue,
    aiApiUrl,
    aiApiKey,
    aiModel,
    a2aPublicUrl,
  };
}
