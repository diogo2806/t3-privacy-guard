import { Router } from 'express';
import type { PolicyEvaluationRequest, PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';

export function createContractRouter(service: PrivacyGuardContractService): Router {
  const router = Router();

  router.get('/identity', async (_request, response) => {
    try {
      response.json({
        contractId: await service.canonicalContractId(),
        functions: ['evaluate-action', 'execute-remediation'],
      });
    } catch {
      response.status(503).json({ error: 'T3N contract identity is unavailable' });
    }
  });

  router.post('/evaluate', async (request, response) => {
    try {
      response.json(await service.evaluate(request.body as Omit<PolicyEvaluationRequest, 'agent_did'>));
    } catch {
      response.status(503).json({ error: 'Policy evaluation is unavailable' });
    }
  });

  router.post('/remediate', async (request, response) => {
    try {
      response.json(await service.remediate(request.body as Omit<PolicyEvaluationRequest, 'agent_did' | 'host'>));
    } catch {
      response.status(503).json({ error: 'Protected remediation could not be completed' });
    }
  });

  return router;
}
