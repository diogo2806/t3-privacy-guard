export type PrincipalCredentialKind = 'secp256k1' | 'org-agent';

const SECP256K1_PRIVATE_KEY_PATTERN = /^0x[a-fA-F0-9]{64}$/;
const ORG_AGENT_API_KEY_PATTERN = /^t3n_key_[A-Za-z0-9]+\.[A-Za-z0-9_-]+$/;

export function classifyPrincipalCredential(value: string): PrincipalCredentialKind {
  if (SECP256K1_PRIVATE_KEY_PATTERN.test(value)) return 'secp256k1';
  if (ORG_AGENT_API_KEY_PATTERN.test(value)) return 'org-agent';
  if (value.startsWith('t3n_key_')) throw new Error('Malformed T3N organization-owned agent credential');
  throw new Error('Unsupported T3N principal credential format');
}
