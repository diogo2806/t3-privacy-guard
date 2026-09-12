import assert from 'node:assert/strict';
import test from 'node:test';
import type { NextFunction, Request, Response } from 'express';
import { requireServiceToken } from './service-auth.js';

function invoke(expected: string, supplied?: string) {
  let statusCode = 200;
  let body: unknown;
  let nextCalled = false;
  const request = { header: (name: string) => name === 'X-Gateway-Service-Token' ? supplied : undefined } as Request;
  const response = {
    status(code: number) { statusCode = code; return this; },
    json(value: unknown) { body = value; return this; },
  } as unknown as Response;
  const next = (() => { nextCalled = true; }) as NextFunction;

  requireServiceToken(expected)(request, response, next);
  return { statusCode, body, nextCalled };
}

test('rejects missing and invalid internal service tokens', () => {
  const expected = 'gateway-service-token-1234567890123456';
  assert.deepEqual(invoke(expected), {
    statusCode: 401,
    body: { error: 'Internal service authentication required' },
    nextCalled: false,
  });
  assert.deepEqual(invoke(expected, 'wrong-token'), {
    statusCode: 401,
    body: { error: 'Internal service authentication required' },
    nextCalled: false,
  });
});

test('allows the configured internal service token without exposing it', () => {
  const expected = 'gateway-service-token-1234567890123456';
  const result = invoke(expected, expected);
  assert.equal(result.statusCode, 200);
  assert.equal(result.body, undefined);
  assert.equal(result.nextCalled, true);
});
