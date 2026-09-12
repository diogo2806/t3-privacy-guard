import type { T3nSession } from './session.js';

const MAX_ACTIVITY_EVENTS = 200;
const MAX_ACTIVITY_PAGES = 20;
const CAPTURE_SCAN_LIMIT = 50;

export interface ActivityLogQuery {
  readonly beforeSeq?: number;
  readonly fromMs?: number;
  readonly toMs?: number;
  readonly limit?: number;
}

export interface SanitizedActivityEvent {
  readonly sequence: number;
  readonly hash: string;
  readonly timestampMs: number;
  readonly callerType: 'agent' | 'human';
  readonly actorDid: string;
  readonly onBehalfOfDid: string;
  readonly orgDid: string;
  readonly contractId: string;
  readonly function: string;
  readonly outcome: 'success' | 'denied' | 'error';
  readonly roles: string[];
}

export interface SanitizedActivityPage {
  readonly events: SanitizedActivityEvent[];
  readonly nextSequence: number | null;
  readonly complete: boolean;
}

export interface ActivityCaptureCriteria {
  readonly actorDid: string;
  readonly onBehalfOfDid: string;
  readonly contractId: string;
  readonly function: string;
}

export interface ActivityReference {
  readonly sequence: number;
  readonly hash: string;
}

interface SdkActivityPage {
  readonly entries?: unknown[];
  readonly next_seq?: number | null;
}

function finiteInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function nonBlank(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function sanitizeEntry(value: unknown): SanitizedActivityEvent | null {
  if (!value || typeof value !== 'object') return null;
  const entry = value as Record<string, unknown>;
  if (!finiteInteger(entry.seq_no)
    || !nonBlank(entry.hash)
    || !finiteInteger(entry.timestamp_ms)
    || (entry.caller_type !== 'agent' && entry.caller_type !== 'human')
    || !nonBlank(entry.actor)
    || !nonBlank(entry.on_behalf_of)
    || !nonBlank(entry.org)
    || !nonBlank(entry.contract)
    || !nonBlank(entry.function)
    || (entry.outcome !== 'success' && entry.outcome !== 'denied' && entry.outcome !== 'error')) return null;

  const roles = Array.isArray(entry.roles)
    ? entry.roles.filter((role): role is string => typeof role === 'string' && role.length <= 120).slice(0, 20)
    : [];

  return {
    sequence: entry.seq_no,
    hash: entry.hash.slice(0, 128),
    timestampMs: entry.timestamp_ms,
    callerType: entry.caller_type,
    actorDid: entry.actor.slice(0, 180),
    onBehalfOfDid: entry.on_behalf_of.slice(0, 180),
    orgDid: entry.org.slice(0, 180),
    contractId: entry.contract.slice(0, 240),
    function: entry.function.slice(0, 120),
    outcome: entry.outcome,
    roles,
  };
}

function requestedLimit(value?: number): number {
  if (value == null) return 100;
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('Activity log limit must be a positive integer');
  return Math.min(value, MAX_ACTIVITY_EVENTS);
}

export class ActivityLogService {
  constructor(private readonly session: T3nSession) {}

  async read(query: ActivityLogQuery = {}): Promise<SanitizedActivityPage> {
    await this.session.connect();
    const limit = requestedLimit(query.limit);
    const events = new Map<number, SanitizedActivityEvent>();
    const seenCursors = new Set<number>();
    let cursor = query.beforeSeq;
    let nextSequence: number | null = cursor ?? null;
    let complete = false;

    for (let pageCount = 0; pageCount < MAX_ACTIVITY_PAGES && events.size < limit; pageCount += 1) {
      if (cursor != null) {
        if (!finiteInteger(cursor) || seenCursors.has(cursor)) break;
        seenCursors.add(cursor);
      }

      const page = await this.session.getClient().getActivityLog({
        limit: Math.min(MAX_ACTIVITY_EVENTS, Math.max(1, limit - events.size)),
        ...(cursor != null ? { before_seq: cursor } : {}),
        ...(query.fromMs != null ? { from_ms: query.fromMs } : {}),
        ...(query.toMs != null ? { to_ms: query.toMs } : {}),
      }) as unknown as SdkActivityPage;

      for (const raw of page.entries ?? []) {
        const sanitized = sanitizeEntry(raw);
        if (sanitized && !events.has(sanitized.sequence)) events.set(sanitized.sequence, sanitized);
        if (events.size >= limit) break;
      }

      const next = finiteInteger(page.next_seq) ? page.next_seq : null;
      nextSequence = next;
      if (next == null) {
        complete = true;
        break;
      }
      cursor = next;
    }

    return {
      events: [...events.values()].sort((left, right) => right.sequence - left.sequence),
      nextSequence,
      complete,
    };
  }

  async capture<T>(criteria: ActivityCaptureCriteria, operation: () => Promise<T>): Promise<{ result: T; activity?: ActivityReference }> {
    let baseline: number | undefined;
    try {
      const before = await this.read({ limit: 1 });
      baseline = before.events[0]?.sequence ?? -1;
    } catch {
      baseline = undefined;
    }

    const result = await operation();
    if (baseline == null) return { result };

    try {
      const after = await this.read({ limit: CAPTURE_SCAN_LIMIT });
      const matches = after.events.filter((event) => event.sequence > baseline
        && event.callerType === 'agent'
        && event.actorDid === criteria.actorDid
        && event.onBehalfOfDid === criteria.onBehalfOfDid
        && event.contractId === criteria.contractId
        && event.function === criteria.function
        && event.outcome === 'success');
      if (matches.length === 1) return { result, activity: { sequence: matches[0].sequence, hash: matches[0].hash } };
    } catch {
      // Activity provenance is evidence only; it must never change the policy or remediation result.
    }
    return { result };
  }
}
