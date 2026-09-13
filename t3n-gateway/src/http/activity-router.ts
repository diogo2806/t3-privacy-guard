import { Router, type Request } from 'express';
import { requireServiceToken } from '../security/service-auth.js';
import type { ActivityLogService } from '../t3n/activity-log-service.js';

const MAX_LIMIT = 200;

function queryInteger(request: Request, name: string, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number | undefined {
  const raw = request.query[name];
  if (raw == null || raw === '') return undefined;
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) throw new Error(`${name} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${name} is outside the allowed range`);
  return value;
}

export function createActivityRouter(service: ActivityLogService, serviceToken: string): Router {
  const router = Router();

  router.get('/', requireServiceToken(serviceToken), async (request, response) => {
    try {
      const beforeSeq = queryInteger(request, 'beforeSeq', 0);
      const fromMs = queryInteger(request, 'fromMs', 0);
      const toMs = queryInteger(request, 'toMs', 0);
      const limit = queryInteger(request, 'limit', 1, MAX_LIMIT) ?? 100;
      if (fromMs != null && toMs != null && fromMs > toMs) {
        response.status(400).json({ error: 'Activity time range is invalid' });
        return;
      }
      response.json(await service.read({ beforeSeq, fromMs, toMs, limit }));
    } catch (error) {
      if (error instanceof Error && (error.message.includes('integer') || error.message.includes('range'))) {
        response.status(400).json({ error: 'Activity query is invalid' });
        return;
      }
      response.status(503).json({ error: 'T3N activity log is unavailable' });
    }
  });

  return router;
}
