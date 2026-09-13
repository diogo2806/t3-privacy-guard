import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const TOKEN_VERSION = 'v2';

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
  operator_principal_hash: string;
  authorization_recorded_at: number;
}

export interface RemediationAuthorizationClaims {
  keyId: string;
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
  operatorPrincipalHash: string;
  authorizedAt: number;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
}

interface ReplayEntry { nonce: string; expiresAt: number }

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

function parsePublicKey(encoded: string): KeyObject {
  try {
    const raw = Buffer.from(encoded, 'base64url');
    if (raw.length !== 32) throw new Error('invalid Ed25519 public key length');
    return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
  } catch {
    throw new Error('CAPABILITY_PUBLIC_KEY_INVALID');
  }
}

export class RemediationAuthorizationVerifier {
  private readonly publicKey: KeyObject;

  constructor(
    publicKey: string,
    private readonly keyId: string,
    private readonly replayStorePath: string,
    private readonly now: () => number = () => Date.now(),
  ) {
    if (!/^[A-Za-z0-9._-]{1,32}$/.test(keyId)) throw new Error('CAPABILITY_KEY_ID_INVALID');
    this.publicKey = parsePublicKey(publicKey);
  }

  verifyAndConsume(token: string, body: RemediationBody): RemediationAuthorizationClaims {
    if (Buffer.byteLength(token, 'utf8') > 8192) throw new Error('CAPABILITY_INVALID');
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== TOKEN_VERSION) throw new Error('CAPABILITY_INVALID');
    const [, payloadPart, signaturePart] = parts;
    const supplied = Buffer.from(signaturePart, 'base64url');
    if (supplied.length !== 64 || !verifySignature(null, Buffer.from(payloadPart, 'ascii'), this.publicKey, supplied)) {
      throw new Error('CAPABILITY_INVALID');
    }

    let claims: RemediationAuthorizationClaims;
    try {
      claims = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8')) as RemediationAuthorizationClaims;
    } catch {
      throw new Error('CAPABILITY_INVALID');
    }
    const now = this.now();
    if (claims.keyId !== this.keyId) throw new Error('CAPABILITY_KEY_MISMATCH');
    if (!claims.nonce || claims.nonce.length > 128 || !Number.isSafeInteger(claims.expiresAt) || claims.expiresAt <= now) {
      throw new Error('CAPABILITY_EXPIRED');
    }
    if (!Number.isSafeInteger(claims.authorizedAt) || claims.authorizedAt <= 0
      || !Number.isSafeInteger(claims.issuedAt) || claims.issuedAt <= 0
      || claims.authorizedAt > claims.issuedAt
      || claims.issuedAt > now + 5_000
      || claims.expiresAt <= claims.issuedAt
      || claims.expiresAt - claims.issuedAt > 300_000) {
      throw new Error('CAPABILITY_INVALID');
    }
    if (!claims.policyVersion || !/^[a-f0-9]{64}$/.test(claims.policyHash ?? '')) throw new Error('CAPABILITY_INVALID');
    if (!claims.executorDid?.startsWith('did:t3n:')) throw new Error('CAPABILITY_INVALID');
    if (!/^[a-f0-9]{64}$/.test(claims.normalPayloadHash ?? '')) throw new Error('CAPABILITY_INVALID');
    if (!/^[a-f0-9]{64}$/.test(claims.operatorPrincipalHash ?? '')) throw new Error('CAPABILITY_INVALID');
    if (!/^[a-f0-9]{64}$/.test(body.operator_principal_hash ?? '')
      || !Number.isSafeInteger(body.authorization_recorded_at) || body.authorization_recorded_at <= 0) {
      throw new Error('CAPABILITY_INVALID');
    }
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
      || claims.executorDid !== body.executor_did
      || claims.operatorPrincipalHash !== body.operator_principal_hash
      || claims.authorizedAt !== body.authorization_recorded_at;
    if (mismatched) throw new Error('CAPABILITY_BODY_MISMATCH');

    const entries = this.loadEntries().filter((entry) => entry.expiresAt > now);
    if (entries.some((entry) => entry.nonce === claims.nonce)) throw new Error('CAPABILITY_REPLAY');
    entries.push({ nonce: claims.nonce, expiresAt: claims.expiresAt });
    this.persistEntries(entries);
    return claims;
  }

  private loadEntries(): ReplayEntry[] {
    if (!existsSync(this.replayStorePath)) return [];
    try {
      const parsed = JSON.parse(readFileSync(this.replayStorePath, 'utf8')) as ReplayEntry[];
      return Array.isArray(parsed) ? parsed : [];
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
