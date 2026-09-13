import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const TOKEN_VERSION = 'v2';
const MAX_TOKEN_LENGTH = 8_192;
const MAX_CAPABILITY_LIFETIME_MS = 300_000;
const CLOCK_SKEW_MS = 5_000;

export interface RemediationBody {
  incident_id: string;
  action_id: string;
  decision_id: string;
  request_id: string;
  action: string;
  resource: string;
  purpose: string;
  approved_host: string;
  fields: string[];
  normal_payload: Record<string, string>;
  private_refs: string[];
  policy_version: string;
  policy_hash: string;
  executor_did: string;
}

export interface RemediationAuthorizationClaims {
  incidentId: string;
  actionId: string;
  requestId: string;
  decisionId: string;
  action: string;
  resource: string;
  purpose: string;
  approvedHost: string;
  fieldsHash: string;
  normalPayloadHash: string;
  privateRefsHash: string;
  policyVersion: string;
  policyHash: string;
  executorDid: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
}

interface ReplayEntry { nonceHash: string; expiresAt: number }

function listHash(values: string[] | undefined): string {
  return createHash('sha256').update(JSON.stringify([...(values ?? [])].map((value) => value.trim()).sort())).digest('hex');
}

function lexicalCompare(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

export function canonicalNormalPayload(value: unknown): string {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('CAPABILITY_INVALID');
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > 16) throw new Error('CAPABILITY_INVALID');
  return entries
    .sort(([left], [right]) => lexicalCompare(left, right))
    .map(([key, raw]) => {
      if (!/^[a-z][a-z0-9_]{0,79}$/.test(key) || typeof raw !== 'string' || !raw.trim() || Buffer.byteLength(raw, 'utf8') > 512) {
        throw new Error('CAPABILITY_INVALID');
      }
      return `${Buffer.byteLength(key, 'utf8')}:${key}=${Buffer.byteLength(raw, 'utf8')}:${raw}\n`;
    })
    .join('');
}

export function normalPayloadHash(value: unknown): string {
  return createHash('sha256').update(canonicalNormalPayload(value), 'utf8').digest('hex');
}

export function canonicalizeApprovedHost(value: unknown): string {
  if (typeof value !== 'string') throw new Error('CAPABILITY_INVALID');
  const input = value.trim();
  if (!input || input.length > 253 || input !== input.toLowerCase()
    || input.includes('://') || /[\/@:?#]/.test(input) || input.endsWith('.')) {
    throw new Error('CAPABILITY_INVALID');
  }
  const labels = input.split('.');
  if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new Error('CAPABILITY_INVALID');
  }
  return input;
}

export function authorizationPublicKeyFingerprint(publicKeySpki: string): string {
  const der = Buffer.from(publicKeySpki, 'base64');
  return createHash('sha256').update(der).digest('hex');
}

function parsePublicKey(publicKeySpki: string): KeyObject {
  try {
    const key = createPublicKey({ key: Buffer.from(publicKeySpki, 'base64'), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
    return key;
  } catch {
    throw new Error('CAPABILITY_VERIFICATION_KEY_INVALID');
  }
}

function decodeClaims(payloadPart: string): RemediationAuthorizationClaims {
  if (!/^[A-Za-z0-9_-]+$/.test(payloadPart)) throw new Error('CAPABILITY_INVALID');
  try {
    const parsed = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8')) as RemediationAuthorizationClaims;
    if (!parsed || typeof parsed !== 'object') throw new Error('CAPABILITY_INVALID');
    return parsed;
  } catch {
    throw new Error('CAPABILITY_INVALID');
  }
}

export class RemediationAuthorizationVerifier {
  private readonly publicKey: KeyObject;

  constructor(
    publicKeySpki: string,
    private readonly replayStorePath: string,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.publicKey = parsePublicKey(publicKeySpki);
  }

  verifyAndConsume(token: string, body: RemediationBody): RemediationAuthorizationClaims {
    if (!token || token.length > MAX_TOKEN_LENGTH) throw new Error('CAPABILITY_INVALID');
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== TOKEN_VERSION) throw new Error('CAPABILITY_INVALID');
    const [version, payloadPart, signaturePart] = parts;
    if (!/^[A-Za-z0-9_-]+$/.test(signaturePart)) throw new Error('CAPABILITY_INVALID');
    const supplied = Buffer.from(signaturePart, 'base64url');
    const signingInput = Buffer.from(`${version}.${payloadPart}`, 'ascii');
    if (supplied.length !== 64 || !verifySignature(null, signingInput, this.publicKey, supplied)) throw new Error('CAPABILITY_INVALID');

    const claims = decodeClaims(payloadPart);
    const currentTime = this.now();
    if (!Number.isSafeInteger(claims.issuedAt) || !Number.isSafeInteger(claims.expiresAt)
      || claims.issuedAt <= 0 || claims.expiresAt <= claims.issuedAt
      || claims.expiresAt - claims.issuedAt > MAX_CAPABILITY_LIFETIME_MS) throw new Error('CAPABILITY_INVALID');
    if (claims.expiresAt <= currentTime) throw new Error('CAPABILITY_EXPIRED');
    if (claims.issuedAt > currentTime + CLOCK_SKEW_MS) throw new Error('CAPABILITY_INVALID');
    if (!/^[A-Za-z0-9._:-]{8,128}$/.test(claims.nonce ?? '')) throw new Error('CAPABILITY_INVALID');
    if (!claims.policyVersion || !/^[a-f0-9]{64}$/.test(claims.policyHash ?? '')) throw new Error('CAPABILITY_INVALID');
    if (!claims.executorDid?.startsWith('did:t3n:')) throw new Error('CAPABILITY_INVALID');
    if (!/^[a-f0-9]{64}$/.test(claims.fieldsHash ?? '')
      || !/^[a-f0-9]{64}$/.test(claims.normalPayloadHash ?? '')
      || !/^[a-f0-9]{64}$/.test(claims.privateRefsHash ?? '')) throw new Error('CAPABILITY_INVALID');
    const approvedHost = canonicalizeApprovedHost(body.approved_host);
    const claimApprovedHost = canonicalizeApprovedHost(claims.approvedHost);

    const mismatched = claims.incidentId !== body.incident_id
      || claims.actionId !== body.action_id
      || claims.decisionId !== body.decision_id
      || claims.requestId !== body.request_id
      || claims.action !== body.action
      || claims.resource !== body.resource
      || claims.purpose !== body.purpose
      || claimApprovedHost !== approvedHost
      || claims.fieldsHash !== listHash(body.fields)
      || claims.normalPayloadHash !== normalPayloadHash(body.normal_payload)
      || claims.privateRefsHash !== listHash(body.private_refs)
      || claims.policyVersion !== body.policy_version
      || claims.policyHash !== body.policy_hash
      || claims.executorDid !== body.executor_did;
    if (mismatched) throw new Error('CAPABILITY_BODY_MISMATCH');

    const nonceHash = createHash('sha256').update(claims.nonce, 'utf8').digest('hex');
    const entries = this.loadEntries().filter((entry) => entry.expiresAt > currentTime);
    if (entries.some((entry) => entry.nonceHash === nonceHash)) throw new Error('CAPABILITY_REPLAY');
    entries.push({ nonceHash, expiresAt: claims.expiresAt });
    this.persistEntries(entries);
    return claims;
  }

  private loadEntries(): ReplayEntry[] {
    if (!existsSync(this.replayStorePath)) return [];
    try {
      const parsed = JSON.parse(readFileSync(this.replayStorePath, 'utf8')) as ReplayEntry[];
      return Array.isArray(parsed) ? parsed.filter((entry) => typeof entry?.nonceHash === 'string' && Number.isSafeInteger(entry?.expiresAt)) : [];
    } catch {
      throw new Error('CAPABILITY_REPLAY_STORE_UNAVAILABLE');
    }
  }

  private persistEntries(entries: ReplayEntry[]): void {
    mkdirSync(dirname(this.replayStorePath), { recursive: true });
    const temporary = `${this.replayStorePath}.tmp`;
    writeFileSync(temporary, JSON.stringify(entries), { encoding: 'utf8', mode: 0o600 });
    renameSync(temporary, this.replayStorePath);
  }
}
