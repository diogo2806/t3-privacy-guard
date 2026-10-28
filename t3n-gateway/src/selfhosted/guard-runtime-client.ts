import type { GuardRuntimeConfig } from '../config/env.js';
import type { ActivityReference } from '../contract/contract-types.js';
import type { OperationalPolicyDocument } from '../policy/policy-document.js';

export type GuardFunction = 'evaluate-action' | 'execute-remediation' | 'verify-remediation';

/** status is null when the runtime could not be reached at all; reason is the contract's refusal text on 422. */
export class GuardRuntimeError extends Error {
  constructor(message: string, readonly status: number | null, readonly reason: string | null = null) {
    super(message);
    this.name = 'GuardRuntimeError';
  }
}

export interface RuntimeCaller {
  readonly id: string;
  readonly functions: string[];
}

export interface RuntimeReadiness {
  readonly contract_id: string;
  readonly contract_version: string;
  readonly tenant_id: string;
  readonly policy_state: 'AVAILABLE' | 'UNAVAILABLE' | 'INVALID';
  readonly policy_version: string | null;
  readonly policy_hash: string | null;
  readonly policy_document: OperationalPolicyDocument | null;
  readonly endpoint_configuration_valid: boolean;
  readonly execution_host: string | null;
  readonly verification_host: string | null;
  readonly insecure_http_allowed: boolean;
  readonly credential_configured: boolean;
  readonly verification_key_configured: boolean;
  readonly private_profile_configured: boolean;
}

export interface FunctionResult {
  readonly body: unknown;
  readonly activity?: ActivityReference;
}

export interface ActivityQuery {
  readonly beforeSeq?: number;
  readonly fromMs?: number;
  readonly toMs?: number;
  readonly limit?: number;
}

const ACTIVITY_HASH = /^[a-f0-9]{64}$/;

/** HTTP client for guard-runtime. Tokens only ever travel in the Authorization header and never appear in errors. */
export class GuardRuntimeClient {
  private readonly baseUrl: string;

  constructor(
    private readonly config: GuardRuntimeConfig,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.baseUrl = config.url.replace(/\/+$/, '');
  }

  async invoke(fn: GuardFunction, token: string, input: object): Promise<FunctionResult> {
    const response = await this.request('POST', `/v1/functions/${fn}`, token, input);
    if (response.status === 422) {
      const reason = await this.reason(response);
      throw new GuardRuntimeError(`Guard runtime rejected ${fn}: ${reason ?? 'unspecified'}`, 422, reason);
    }
    if (!response.ok) throw new GuardRuntimeError(`Guard runtime ${fn} returned HTTP ${response.status}`, response.status);
    return { body: await response.json() as unknown, activity: activityFrom(response) };
  }

  /** null when the runtime does not know the token, the equivalent of a missing T3N grant. */
  async caller(token: string): Promise<RuntimeCaller | null> {
    const response = await this.request('GET', '/v1/caller', token);
    if (response.status === 401) return null;
    if (!response.ok) throw new GuardRuntimeError(`Guard runtime caller check returned HTTP ${response.status}`, response.status);
    const body = await response.json() as Partial<RuntimeCaller>;
    if (typeof body.id !== 'string' || !Array.isArray(body.functions) || !body.functions.every((value) => typeof value === 'string')) {
      throw new GuardRuntimeError('Guard runtime returned an invalid caller', response.status);
    }
    return { id: body.id, functions: [...body.functions] };
  }

  async readiness(token: string): Promise<RuntimeReadiness> {
    const response = await this.request('GET', '/v1/readiness', token);
    if (!response.ok) throw new GuardRuntimeError(`Guard runtime readiness returned HTTP ${response.status}`, response.status);
    return await response.json() as RuntimeReadiness;
  }

  async activity(token: string, query: ActivityQuery): Promise<unknown> {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) if (value != null) params.set(key, String(value));
    const response = await this.request('GET', `/v1/activity?${params.toString()}`, token);
    if (!response.ok) throw new GuardRuntimeError(`Guard runtime activity returned HTTP ${response.status}`, response.status);
    return await response.json() as unknown;
  }

  private async request(method: 'GET' | 'POST', path: string, token: string, body?: object): Promise<Response> {
    try {
      return await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        redirect: 'error',
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch {
      throw new GuardRuntimeError('Guard runtime is unreachable', null);
    }
  }

  private async reason(response: Response): Promise<string | null> {
    try {
      const body = await response.json() as { reason?: unknown };
      return typeof body.reason === 'string' ? body.reason.slice(0, 300) : null;
    } catch {
      return null;
    }
  }
}

function activityFrom(response: Response): ActivityReference | undefined {
  const sequence = Number(response.headers.get('X-Activity-Sequence'));
  const hash = response.headers.get('X-Activity-Hash') ?? '';
  return Number.isSafeInteger(sequence) && sequence > 0 && ACTIVITY_HASH.test(hash) ? { sequence, hash } : undefined;
}
