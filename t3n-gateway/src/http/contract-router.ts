import { Router } from 'express';
import type { PolicyEvaluationRequest, PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import type { RemediationAuthorizationVerifier, RemediationBody } from '../security/remediation-authorization.js';
import { requireServiceToken } from '../security/service-auth.js';

export function createContractRouter(
  service: PrivacyGuardContractService,
  verifier: RemediationAuthorizationVerifier,
  serviceToken: string,
): Router {
  const router = Router();

  router.get('/identity', async (_request, response) => {
    try {
      response.json(await service.identity());
    } catch {
      response.status(503).json({ error: 'Registered T3N contract is unavailable' });
    }
  });

  router.post('/evaluate', async (request, response) => {
    try {
      response.json(await service.evaluate(request.body as Omit<PolicyEvaluationRequest, 'agent_did'>));
    } catch {
      response.status(503).json({ error: 'Policy evaluation is unavailable' });
    }
  });

  router.post('/remediate', requireServiceToken(serviceToken), async (request, response) => {
    const capability = request.header('X-Remediation-Capability') ?? '';
    try {
      const body = request.body as RemediationBody;
      verifier.verifyAndConsume(capability, body);
      response.json(await service.remediate({
        request_id: body.request_id,
        action: body.action,
        resource: body.resource,
        purpose: body.purpose,
        fields: body.fields,
      }));
    } catch (error) {
      const code = error instanceof Error ? error.message : 'UNKNOWN';
      if (code === 'CAPABILITY_REPLAY') {
        response.status(409).json({ error: 'Remediation authorization proof was already consumed' });
      } else if (code.startsWith('CAPABILITY_')) {
        response.status(403).json({ error: 'Remediation authorization proof is invalid or unavailable' });
      } else {
        response.status(503).json({ error: 'Protected remediation could not be completed' });
      }
    }
  });

  return router;
}
