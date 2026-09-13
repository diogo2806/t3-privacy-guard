import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

export const TRACE_HEADER = 'X-Trace-Id';
const SAFE_TRACE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$/;
const SAFE_METADATA = /[^A-Za-z0-9._:-]/g;

export function traceRequest(request: Request, response: Response, next: NextFunction): void {
  const supplied = request.header(TRACE_HEADER)?.trim() ?? '';
  const traceId = SAFE_TRACE_ID.test(supplied) ? supplied : randomUUID();
  response.locals.traceId = traceId;
  response.setHeader(TRACE_HEADER, traceId);
  next();
}

export function logTraceStage(response: Response, stage: string, requestId: unknown, state: string): void {
  const traceId = typeof response.locals.traceId === 'string' ? response.locals.traceId : randomUUID();
  const safeRequestId = typeof requestId === 'string' ? requestId.replace(SAFE_METADATA, '_').slice(0, 128) : undefined;
  console.info(JSON.stringify({
    event: 'execution_trace',
    traceId,
    requestId: safeRequestId,
    stage: stage.replace(SAFE_METADATA, '_').slice(0, 64),
    state: state.replace(SAFE_METADATA, '_').slice(0, 32),
  }));
}
