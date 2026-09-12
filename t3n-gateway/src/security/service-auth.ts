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
