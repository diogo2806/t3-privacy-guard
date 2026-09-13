import { Router } from 'express';
import type { DelegationGrantRequest, DelegationService } from '../agent/delegation-service.js';
import type { ExecutorSession } from '../agent/executor-session.js';
import { requireServiceToken } from '../security/service-auth.js';

export function createExecutorRouter(
  executorSession: ExecutorSession,
  delegationService: DelegationService,
  serviceToken: string,
): Router {
  const router = Router();
  const privileged = requireServiceToken(serviceToken);

  router.get('/status', (_request, response) => {
    const status = executorSession.getExecutorStatus();
    response.status(status.ready ? 200 : 503).json(status);
  });

  router.post('/connect', privileged, async (_request, response) => {
    try {
      await executorSession.connect();
      response.json(executorSession.getExecutorStatus());
    } catch {
      response.status(503).json({ ...executorSession.getExecutorStatus(), error: 'Protected executor connection failed' });
    }
  });

  router.post('/delegations', privileged, async (request, response) => {
    try {
      const body = request.body as DelegationGrantRequest;
      await delegationService.grant(body);
      response.status(201).json(await delegationService.status(body.contractId));
    } catch {
      response.status(400).json({ error: 'Executor delegation could not be applied' });
    }
  });

  router.get('/delegations/:contractId', async (request, response) => {
    try {
      response.json(await delegationService.status(request.params.contractId));
    } catch {
      response.status(503).json({ error: 'Executor delegation status is unavailable' });
    }
  });

  router.delete('/delegations/:contractId', privileged, async (request, response) => {
    try {
      const state = await delegationService.revoke(request.params.contractId);
      response.json({ state, contractId: request.params.contractId, executorDid: executorSession.getExecutorDid() });
    } catch {
      response.status(400).json({ error: 'Executor delegation could not be revoked' });
    }
  });

  return router;
}
