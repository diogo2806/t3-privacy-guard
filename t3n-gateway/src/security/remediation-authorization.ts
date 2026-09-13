import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const MAX_PROOF_BYTES = 8_192;
const MAX_TTL_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 5;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

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
  private_refs: string[];
  policy_version: string;
  policy_hash: string;
  executor_did: string;
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
  privateRefsHash: string;
  policyVersion: string;
  policyHash: string;
  executorDid: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
}

interface ReplayEntry { nonce: string; expiresAt: number }

function listHash(values: string[] | undefined): string {
  return createHash('sha256').update(JSON.stringify([...(values ?? [])].map((value) => value.trim()).sort())).digest('hex');
}

function validIdentifier(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
}

function createEd25519PublicKey(publicKeyHex: string): KeyObject {
  if (!/^[a-f0-9]{64}$/.test(publicKeyHex)) throw new Error('CAPABILITY_CONFIGURATION_INVALID');
  try {
    return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, 'hex')]), format: 'der', type: 'spki' });
  } catch {
    throw new Error('CAPABILITY_CONFIGURATION_INVALID');
  }
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

export class RemediationAuthorizationVerifier {
  private readonly publicKey: KeyObject;

  constructor(
    publicKeyHex: string,
    private readonly expectedKeyId: string,
    private readonly replayStorePath: string,
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
  ) {
    if (!validIdentifier(expectedKeyId)) throw new Error('CAPABILITY_CONFIGURATION_INVALID');
    this.publicKey = createEd25519PublicKey(publicKeyHex);
  }

  verifyAndConsume(token: string, body: RemediationBody): RemediationAuthorizationClaims {
    if (!token || Buffer.byteLength(token, 'utf8') > MAX_PROOF_BYTES) throw new Error('CAPABILITY_INVALID');
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== 'v2' || !parts[1] || !/^[a-f0-9]{128}$/.test(parts[2])) {
      throw new Error('CAPABILITY_INVALID');
    }
    const [, payloadPart, signaturePart] = parts;
    const signingInput = Buffer.from(`v2.${payloadPart}`, 'ascii');
    const signature = Buffer.from(signaturePart, 'hex');
    if (!verifySignature(null, signingInput, this.publicKey, signature)) throw new Error('CAPABILITY_INVALID');

    let claims: RemediationAuthorizationClaims;
    try {
      claims = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8')) as RemediationAuthorizationClaims;
    } catch {
      throw new Error('CAPABILITY_INVALID');
    }
    const current = this.now();
    if (!validIdentifier(claims.keyId) || claims.keyId !== this.expectedKeyId) throw new Error('CAPABILITY_INVALID');
    if (!validIdentifier(claims.nonce)
      || !Number.isSafeInteger(claims.issuedAt) || !Number.isSafeInteger(claims.expiresAt)
      || claims.expiresAt <= claims.issuedAt || claims.expiresAt - claims.issuedAt > MAX_TTL_SECONDS) {
      throw new Error('CAPABILITY_INVALID');
    }
    if (claims.expiresAt <= current) throw new Error('CAPABILITY_EXPIRED');
    if (claims.issuedAt > current + CLOCK_SKEW_SECONDS) throw new Error('CAPABILITY_INVALID');
    if (!claims.policyVersion || !/^[a-f0-9]{64}$/.test(claims.policyHash ?? '')) throw new Error('CAPABILITY_INVALID');
    if (!/^[a-f0-9]{64}$/.test(claims.fieldsHash ?? '') || !/^[a-f0-9]{64}$/.test(claims.privateRefsHash ?? '')) throw new Error('CAPABILITY_INVALID');
    if (!claims.executorDid?.startsWith('did:t3n:')) throw new Error('CAPABILITY_INVALID');
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
      || claims.privateRefsHash !== listHash(body.private_refs)
      || claims.policyVersion !== body.policy_version
      || claims.policyHash !== body.policy_hash
      || claims.executorDid !== body.executor_did;
    if (mismatched) throw new Error('CAPABILITY_BODY_MISMATCH');

    const entries = this.loadEntries().filter((entry) => entry.expiresAt > current);
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
