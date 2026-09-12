import { Router } from 'express';
import type { T3nSession } from '../t3n/session.js';

export function createStatusRouter(session: T3nSession): Router {
  const router = Router();

  router.get('/status', (_request, response) => {
    const status = session.getStatus();
    response.status(status.ready ? 200 : 503).json(status);
  });

  router.post('/reconnect', async (_request, response) => {
    try {
      await session.connect();
      response.json(session.getStatus());
    } catch {
      response.status(503).json(session.getStatus());
    }
  });

  return router;
}
