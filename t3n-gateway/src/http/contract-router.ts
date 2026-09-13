import { Router } from 'express';
import type { PolicyDecisionType, PolicyEvaluationRequest, PrivacyGuardContractService, RemediationVerificationRequest } from '../contract/privacy-guard-contract.js';
import { logTraceStage, traceRequest } from '../observability/trace.js';
import type { RemediationAuthorizationVerifier, RemediationBody } from '../security/remediation-authorization.js';
import { requireServiceToken } from '../security/service-auth.js';

function policyTraceState(decision: PolicyDecisionType): string {
  if (decision === 'ALLOW') return 'ACCEPTED';
  if (decision === 'REDACT') return 'REDACTED';
  return 'DENIED';
}

export function createContractRouter(
  service: PrivacyGuardContractService,
  verifier: RemediationAuthorizationVerifier,
  serviceToken: string,
): Router {
  const router = Router();

  router.get('/identity', async (_request, response) => {
    try { response.json(await service.identity()); }
    catch { response.status(503).json({ error: 'Registered T3N contract is unavailable' }); }
  });

  router.post('/evaluate', requireServiceToken(serviceToken), traceRequest, async (request, response) => {
    const requestId = request.body?.request_id;
    try {
      const result = await service.evaluate(request.body as Omit<PolicyEvaluationRequest, 'agent_did'>);
      logTraceStage(response, 'T3N_TEE_EVALUATION', requestId, policyTraceState(result.decision));
      response.json(result);
    } catch {
      logTraceStage(response, 'T3N_TEE_EVALUATION', requestId, 'UNAVAILABLE');
      response.status(503).json({ error: 'Policy evaluation is unavailable' });
    }
  });

  router.post('/remediate', requireServiceToken(serviceToken), traceRequest, async (request, response) => {
    const capability = request.header('X-Remediation-Capability') ?? '';
    const requestId = request.body?.request_id;
    try {
      const body = request.body as RemediationBody;
      verifier.verifyAndConsume(capability, body);
      const result = await service.remediate({
        request_id: body.request_id,
        action: body.action,
        resource: body.resource,
        purpose: body.purpose,
        fields: body.fields,
        private_refs: body.private_refs ?? [],
        policy_version: body.policy_version,
        policy_hash: body.policy_hash,
      }, body.executor_did);
      logTraceStage(response, 'PROTECTED_EGRESS', requestId, 'ACCEPTED');
      response.json(result);
    } catch (error) {
      const code = error instanceof Error ? error.message : 'UNKNOWN';
      if (code === 'CAPABILITY_REPLAY') response.status(409).json({ error: 'Remediation authorization proof was already consumed' });
      else if (code.startsWith('CAPABILITY_')) response.status(403).json({ error: 'Remediation authorization proof is invalid or unavailable' });
      else response.status(503).json({ error: 'Protected remediation could not be accepted under the approved policy' });
      logTraceStage(response, 'PROTECTED_EGRESS', requestId, code.startsWith('CAPABILITY_') ? 'DENIED' : 'UNAVAILABLE');
    }
  });

  router.post('/verify-remediation', requireServiceToken(serviceToken), traceRequest, async (request, response) => {
    const requestId = request.body?.request_id;
    try {
      const body = request.body as RemediationVerificationRequest;
      if (!body?.request_id || !body?.operation_id || body.expected_state !== 'REVOKED') {
        logTraceStage(response, 'EXTERNAL_VERIFICATION', requestId, 'FAILED');
        response.status(400).json({ error: 'Verification request is invalid' });
        return;
      }
      const result = await service.verifyRemediation(body);
      logTraceStage(response, 'EXTERNAL_VERIFICATION', requestId, result.status);
      response.json(result);
    } catch {
      logTraceStage(response, 'EXTERNAL_VERIFICATION', requestId, 'UNAVAILABLE');
      response.status(503).json({ error: 'External remediation state could not be verified' });
    }
  });

  return router;
}
