const PRIVATE_KEY_PATTERN = /\b0x[a-fA-F0-9]{64}\b/g;
const ORG_AGENT_API_KEY_PATTERN = /\bt3n_key_[A-Za-z0-9._-]+/g;

export type T3nErrorCategory = 'AUTHENTICATION' | 'NETWORK' | 'TRUST_ANCHOR' | 'CONFIGURATION' | 'UNKNOWN';

export interface SanitizedError {
  readonly category: T3nErrorCategory;
  readonly message: string;
}

function messageFrom(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

export function sanitizeText(value: string, secrets: readonly string[] = []): string {
  let sanitized = value
    .replace(PRIVATE_KEY_PATTERN, '[REDACTED_PRIVATE_KEY]')
    .replace(ORG_AGENT_API_KEY_PATTERN, '[REDACTED_T3N_API_KEY]');
  for (const secret of secrets) {
    if (secret) {
      sanitized = sanitized.split(secret).join('[REDACTED_SECRET]');
    }
  }
  return sanitized;
}

export function classifyT3nError(error: unknown): T3nErrorCategory {
  const message = messageFrom(error).toLowerCase();
  if (
    message.includes('orgpolicynotinitialised')
    || message.includes('org policy is not initialised')
    || message.includes('organisationnotfound')
    || message.includes('organizationnotfound')
    || message.includes('organisation does not exist')
    || message.includes('organization does not exist')
    || message.includes('t3n_org_did')
  ) {
    return 'CONFIGURATION';
  }
  if (message.includes('trust') || message.includes('manifest') || message.includes('attestation')) {
    return 'TRUST_ANCHOR';
  }
  if (message.includes('auth') || message.includes('signature') || message.includes('unauthorized') || message.includes('forbidden')) {
    return 'AUTHENTICATION';
  }
  if (message.includes('network') || message.includes('fetch') || message.includes('timeout') || message.includes('connect') || message.includes('socket')) {
    return 'NETWORK';
  }
  return 'UNKNOWN';
}

export function sanitizeError(error: unknown, secrets: readonly string[] = []): SanitizedError {
  return {
    category: classifyT3nError(error),
    message: sanitizeText(messageFrom(error), secrets),
  };
}
