import { timingSafeEqual } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function requireServiceToken(expectedToken: string) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const supplied = request.header('X-Gateway-Service-Token') ?? '';
    if (!supplied || !safeEqual(supplied, expectedToken)) {
      response.status(401).json({ error: 'Internal service authentication required' });
      return;
    }
    next();
  };
}

export function requireBearerServiceToken(expectedToken: string) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const authorization = request.header('Authorization') ?? '';
    const match = /^Bearer\s+([^\s]+)$/i.exec(authorization);
    const supplied = match?.[1] ?? '';
    if (!supplied || !safeEqual(supplied, expectedToken)) {
      response.set('WWW-Authenticate', 'Bearer realm="t3-privacy-guard-mcp"');
      response.status(401).json({ error: 'MCP bearer authentication required' });
      return;
    }
    next();
  };
}
