import assert from 'node:assert/strict';
import test from 'node:test';
import type { T3nSession } from './session.js';
import { ActivityLogService } from './activity-log-service.js';

function entry(sequence: number, overrides: Record<string, unknown> = {}) {
  return {
    seq_no: sequence,
    hash: `hash-${sequence}`,
    timestamp_ms: 1_700_000_000_000 + sequence,
    caller_type: 'agent',
    actor: 'did:t3n:agent',
    on_behalf_of: 'did:t3n:tenant',
    org: 'did:t3n:org',
    contract: 'z:tenant:privacy-guard',
    function: 'evaluate-action',
    outcome: 'success',
    roles: ['incident-agent'],
    ...overrides,
  };
}

function serviceWithPages(pages: Array<{ entries: unknown[]; next_seq: number | null }>) {
  let index = 0;
  const session = {
    connect: async () => undefined,
    getClient: () => ({
      getActivityLog: async () => pages[Math.min(index++, pages.length - 1)],
    }),
  } as unknown as T3nSession;
  return new ActivityLogService(session);
}

test('follows next_seq even when an intermediate page is empty', async () => {
  const service = serviceWithPages([
    { entries: [], next_seq: 50 },
    { entries: [entry(49), entry(48)], next_seq: null },
  ]);

  const result = await service.read({ limit: 2 });
  assert.deepEqual(result.events.map((event) => event.sequence), [49, 48]);
  assert.equal(result.nextSequence, null);
  assert.equal(result.complete, true);
});

test('deduplicates and orders by sequence instead of timestamp', async () => {
  const service = serviceWithPages([{
    entries: [
      entry(8, { timestamp_ms: 2 }),
      entry(10, { timestamp_ms: 1 }),
      entry(10, { timestamp_ms: 999 }),
      entry(9, { timestamp_ms: 3 }),
    ],
    next_seq: null,
  }]);

  const result = await service.read({ limit: 10 });
  assert.deepEqual(result.events.map((event) => event.sequence), [10, 9, 8]);
});

test('returns only the explicit metadata allowlist', async () => {
  const service = serviceWithPages([{
    entries: [entry(3, { raw_payload: 'SECRET_SENTINEL', request_body: 'PRIVATE_VALUE', roles: ['operator', 123] })],
    next_seq: null,
  }]);

  const result = await service.read({ limit: 1 });
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('SECRET_SENTINEL'), false);
  assert.equal(serialized.includes('PRIVATE_VALUE'), false);
  assert.deepEqual(result.events[0].roles, ['operator']);
});

test('captures a reference only when exactly one new event matches concrete identifiers', async () => {
  let call = 0;
  const session = {
    connect: async () => undefined,
    getClient: () => ({
      getActivityLog: async () => {
        call += 1;
        if (call === 1) return { entries: [entry(20)], next_seq: null };
        return { entries: [entry(21), entry(20)], next_seq: null };
      },
    }),
  } as unknown as T3nSession;
  const service = new ActivityLogService(session);

  const captured = await service.capture({
    actorDid: 'did:t3n:agent',
    onBehalfOfDid: 'did:t3n:tenant',
    contractId: 'z:tenant:privacy-guard',
    function: 'evaluate-action',
  }, async () => 'ALLOW');

  assert.equal(captured.result, 'ALLOW');
  assert.deepEqual(captured.activity, { sequence: 21, hash: 'hash-21' });
});

test('does not fabricate a correlation when multiple new events match', async () => {
  let call = 0;
  const session = {
    connect: async () => undefined,
    getClient: () => ({
      getActivityLog: async () => {
        call += 1;
        if (call === 1) return { entries: [entry(20)], next_seq: null };
        return { entries: [entry(22), entry(21), entry(20)], next_seq: null };
      },
    }),
  } as unknown as T3nSession;
  const service = new ActivityLogService(session);

  const captured = await service.capture({
    actorDid: 'did:t3n:agent',
    onBehalfOfDid: 'did:t3n:tenant',
    contractId: 'z:tenant:privacy-guard',
    function: 'evaluate-action',
  }, async () => 'ALLOW');

  assert.equal(captured.result, 'ALLOW');
  assert.equal(captured.activity, undefined);
});
