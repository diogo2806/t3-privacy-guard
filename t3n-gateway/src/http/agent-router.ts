import { Router } from 'express';
import type { AgentCardRegistrationService } from '../agent/agent-card.js';
import type { AgentSession } from '../agent/agent-session.js';
import type { DelegationGrantRequest, DelegationService } from '../agent/delegation-service.js';
import { requireServiceToken } from '../security/service-auth.js';

export function createAgentRouter(
  agentSession: AgentSession,
  delegationService: DelegationService,
  registrationService: AgentCardRegistrationService,
  serviceToken: string,
): Router {
  const router = Router();
  const privileged = requireServiceToken(serviceToken);

  router.get('/status', async (_request, response) => {
    const status = agentSession.getStatus();
    const registration = await registrationService.verify();
    response.status(status.ready ? 200 : 503).json({ ...status, ...registration });
  });

  router.post('/connect', privileged, async (_request, response) => {
    try {
      await agentSession.connect();
      response.json({ ...agentSession.getStatus(), ...await registrationService.verify() });
    } catch {
      response.status(503).json({ ...agentSession.getStatus(), error: 'Agent connection failed' });
    }
  });

  router.post('/delegations', privileged, async (request, response) => {
    try {
      const body = request.body as DelegationGrantRequest;
      await delegationService.grant(body);
      response.status(201).json(await delegationService.status(body.contractId));
    } catch {
      response.status(400).json({ error: 'Delegation could not be applied' });
    }
  });

  router.get('/delegations/:contractId', async (request, response) => {
    try {
      response.json(await delegationService.status(request.params.contractId));
    } catch {
      response.status(503).json({ error: 'Delegation status is unavailable' });
    }
  });

  router.delete('/delegations/:contractId', privileged, async (request, response) => {
    try {
      const state = await delegationService.revoke(request.params.contractId);
      response.json({ state, contractId: request.params.contractId, agentDid: agentSession.getAgentDid() });
    } catch {
      response.status(400).json({ error: 'Delegation could not be revoked' });
    }
  });

  return router;
}
