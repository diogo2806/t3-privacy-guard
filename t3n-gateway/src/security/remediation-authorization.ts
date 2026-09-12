import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface RemediationBody {
  incident_id: string;
  action_id: string;
  decision_id: string;
  request_id: string;
  action: string;
  resource: string;
  purpose: string;
  fields: string[];
}

interface Claims {
  incidentId: string;
  actionId: string;
  requestId: string;
  decisionId: string;
  action: string;
  resource: string;
  purpose: string;
  fieldsHash: string;
  authorizedAt: number;
  expiresAt: number;
  nonce: string;
}

interface ReplayEntry { nonce: string; expiresAt: number }

export class RemediationAuthorizationVerifier {
  constructor(
    private readonly key: string,
    private readonly replayStorePath: string,
    private readonly now: () => number = () => Date.now(),
  ) {}

  verifyAndConsume(token: string, body: RemediationBody): Claims {
    const parts = token.split('.');
    if (parts.length !== 2) throw new Error('CAPABILITY_INVALID');
    const [payloadPart, signaturePart] = parts;
    const expected = createHmac('sha256', this.key).update(payloadPart, 'ascii').digest();
    const supplied = Buffer.from(signaturePart, 'base64url');
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) throw new Error('CAPABILITY_INVALID');

    const claims = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8')) as Claims;
    if (!claims.nonce || !claims.expiresAt || claims.expiresAt <= this.now()) throw new Error('CAPABILITY_EXPIRED');
    if (claims.authorizedAt > this.now() + 5_000) throw new Error('CAPABILITY_INVALID');

    const fieldsHash = createHash('sha256').update(JSON.stringify([...(body.fields ?? [])].sort())).digest('hex');
    const mismatched = claims.incidentId !== body.incident_id
      || claims.actionId !== body.action_id
      || claims.decisionId !== body.decision_id
      || claims.requestId !== body.request_id
      || claims.action !== body.action
      || claims.resource !== body.resource
      || claims.purpose !== body.purpose
      || claims.fieldsHash !== fieldsHash;
    if (mismatched) throw new Error('CAPABILITY_BODY_MISMATCH');

    const entries = this.loadEntries().filter((entry) => entry.expiresAt > this.now());
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
