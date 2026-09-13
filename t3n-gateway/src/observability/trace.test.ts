import assert from 'node:assert/strict';
import test from 'node:test';
import type { NextFunction, Request, Response } from 'express';
import { TRACE_HEADER, traceRequest } from './trace.js';

function invoke(supplied?: string) {
  let returnedHeader = '';
  let nextCalled = false;
  const request = {
    header: (name: string) => name === TRACE_HEADER ? supplied : undefined,
  } as unknown as Request;
  const response = {
    locals: {},
    setHeader: (name: string, value: string) => {
      if (name === TRACE_HEADER) returnedHeader = value;
      return response;
    },
  } as unknown as Response;
  const next = (() => { nextCalled = true; }) as NextFunction;

  traceRequest(request, response, next);
  return { returnedHeader, traceId: response.locals.traceId as string, nextCalled };
}

test('preserves a valid bounded trace id', () => {
  const result = invoke('trace-safe_1234');
  assert.equal(result.traceId, 'trace-safe_1234');
  assert.equal(result.returnedHeader, 'trace-safe_1234');
  assert.equal(result.nextCalled, true);
});

test('generates a trace id when missing', () => {
  const result = invoke();
  assert.match(result.traceId, /^[0-9a-f-]{36}$/);
  assert.equal(result.returnedHeader, result.traceId);
});

test('replaces malformed or oversized input instead of reflecting it', () => {
  const malicious = `trace\r\nX-Forged:secret-${'x'.repeat(256)}`;
  const result = invoke(malicious);
  assert.match(result.traceId, /^[0-9a-f-]{36}$/);
  assert.notEqual(result.traceId, malicious);
  assert.equal(result.returnedHeader, result.traceId);
});
