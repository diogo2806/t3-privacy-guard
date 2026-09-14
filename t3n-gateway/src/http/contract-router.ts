import { Router } from 'express';
import type { EnterpriseIntegrationReadinessService } from '../contract/enterprise-integration-readiness.js';
import type { PolicyDecisionType, PolicyEvaluationRequest, PrivacyGuardContractService, RemediationVerificationRequest } from '../contract/privacy-guard-contract.js';
import { logTraceStage, traceRequest } from '../observability/trace.js';
import type { RemediationAuthorizationVerifier, RemediationBody } from '../security/remediation-authorization.js';
import { requireServiceToken } from '../security/service-auth.js';

function policyTraceState(decision: PolicyDecisionType): string {
  if (decision === 'ALLOW') return 'ACCEPTED';
  if (decision === 'REDACT') return 'REDACTED';
  return 'DENIED';
}

function validVerificationContract(body: RemediationVerificationRequest): boolean {
  return ((body.action == null || body.action === 'revoke-credential') && body.expected_state === 'REVOKED')
    || (body.action === 'notify-security' && body.expected_state === 'DELIVERED');
}

export function createContractRouter(
  service: PrivacyGuardContractService,
  verifier: RemediationAuthorizationVerifier,
  serviceToken: string,
  enterpriseIntegrationReadiness: EnterpriseIntegrationReadinessService,
): Router {
  const router = Router();

  router.get('/identity', async (_request, response) => {
    try { response.json(await service.identity()); }
    catch { response.status(503).json({ error: 'Registered T3N contract is unavailable' }); }
  });

  router.get('/enterprise-integration-readiness', async (_request, response) => {
    response.json(await enterpriseIntegrationReadiness.status());
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
        incident_id: body.incident_id,
        action_id: body.action_id,
        decision_id: body.decision_id,
        request_id: body.request_id,
        action: body.action,
        resource: body.resource,
        purpose: body.purpose,
        approved_host: body.approved_host,
        fields: body.fields,
        normal_payload: body.normal_payload,
        private_refs: body.private_refs ?? [],
        policy_version: body.policy_version,
        policy_hash: body.policy_hash,
        executor_did: body.executor_did,
        authorization_proof: capability,
      }, body.executor_did);
      logTraceStage(response, 'PROTECTED_EGRESS', requestId, 'ACCEPTED');
      response.json(result);
    } catch (error) {
      const code = error instanceof Error ? error.message : 'UNKNOWN';
      const destinationChanged = code.includes('EXECUTION_DESTINATION_CHANGED');
      if (code === 'CAPABILITY_REPLAY') response.status(409).json({ error: 'Remediation authorization proof was already consumed' });
      else if (code.startsWith('CAPABILITY_')) response.status(403).json({ error: 'Remediation authorization proof is invalid or unavailable' });
      else if (destinationChanged) response.status(409).json({
        code: 'EXECUTION_DESTINATION_CHANGED',
        error: 'Protected destination changed after approval; create a new action, evaluate it, and authorize the intended destination again',
      });
      else response.status(503).json({ error: 'Protected remediation could not be accepted under the approved policy' });
      logTraceStage(response, 'PROTECTED_EGRESS', requestId, code.startsWith('CAPABILITY_') || destinationChanged ? 'DENIED' : 'UNAVAILABLE');
    }
  });

  router.post('/verify-remediation', requireServiceToken(serviceToken), traceRequest, async (request, response) => {
    const requestId = request.body?.request_id;
    try {
      const body = request.body as RemediationVerificationRequest;
      if (!body?.request_id || !body?.operation_id || !validVerificationContract(body)) {
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
