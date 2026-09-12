import { Router } from 'express';
import type { PolicyEvaluationRequest, PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';

export function createContractRouter(service: PrivacyGuardContractService): Router {
  const router = Router();

  router.get('/identity', async (_request, response) => {
    try {
      response.json({ contractId: await service.canonicalContractId(), functionName: 'evaluate-action' });
    } catch {
      response.status(503).json({ error: 'T3N contract identity is unavailable' });
    }
  });

  router.post('/evaluate', async (request, response) => {
    try {
      const input = request.body as Omit<PolicyEvaluationRequest, 'agent_did'>;
      const decision = await service.evaluate(input);
      response.json(decision);
    } catch {
      response.status(503).json({ error: 'Policy evaluation is unavailable' });
    }
  });

  return router;
}
