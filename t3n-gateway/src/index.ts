import express from 'express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { A2aEvaluationService } from './agent/a2a-service.js';
import { AgentCardRegistry } from './agent/agent-card.js';
import { AgentService } from './agent/agent-service.js';
import { AgentSession } from './agent/agent-session.js';
import {
  DelegationService,
  EXECUTOR_DELEGATION_REQUIREMENTS,
  PROPOSAL_DELEGATION_REQUIREMENTS,
} from './agent/delegation-service.js';
import { ExecutorSession } from './agent/executor-session.js';
import { OpenAiCompatibleProvider } from './agent/openai-compatible-provider.js';
import { readGatewayConfig } from './config/env.js';
import { EnterpriseIntegrationReadinessService } from './contract/enterprise-integration-readiness.js';
import { PrivacyGuardContractService } from './contract/privacy-guard-contract.js';
import { createA2aRouter } from './http/a2a-router.js';
import { createActivityRouter } from './http/activity-router.js';
import { createAgentRouter } from './http/agent-router.js';
import { createAiAgentRouter } from './http/ai-agent-router.js';
import { createContractRouter } from './http/contract-router.js';
import { createEvidenceRouter } from './http/evidence-router.js';
import { createExecutorRouter } from './http/executor-router.js';
import { createStatusRouter } from './http/status-router.js';
import { createPrivacyGuardMcpHandler } from './mcp/privacy-tools.js';
import { reconcileRuntimeProvisioning } from './provisioning/runtime-provisioning.js';
import { RemediationAuthorizationVerifier } from './security/remediation-authorization.js';
import { sanitizeError } from './security/sanitize.js';
import { requireBearerServiceToken, requireServiceToken } from './security/service-auth.js';
import { TrustManifestFloorStore } from './security/trust-manifest-floor-store.js';
import { ActivityLogService } from './t3n/activity-log-service.js';
import { PrincipalIdentityGuard } from './t3n/principal-identity.js';
import { T3nSession } from './t3n/session.js';

const config = readGatewayConfig();
const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const principalIdentityGuard = new PrincipalIdentityGuard();
const tenantSession = new T3nSession(config, trustFloorStore, principalIdentityGuard);
const agentSession = new AgentSession(
  config,
  trustFloorStore,
  config.agentApiKey,
  'Proposal agent',
  undefined,
  principalIdentityGuard,
  'proposal-agent',
);
const executorSession = new ExecutorSession(config, trustFloorStore, principalIdentityGuard);
const agentCardRegistry = new AgentCardRegistry(agentSession, undefined, undefined, config.a2aPublicUrl);
const activityLogService = new ActivityLogService(tenantSession);
const delegationService = new DelegationService(tenantSession, agentSession, PROPOSAL_DELEGATION_REQUIREMENTS);
const executorDelegationService = new DelegationService(tenantSession, executorSession, EXECUTOR_DELEGATION_REQUIREMENTS);
const contractService = new PrivacyGuardContractService(config, tenantSession, agentSession, executorSession, activityLogService);
const enterpriseIntegrationReadiness = new EnterpriseIntegrationReadinessService(tenantSession, executorDelegationService, contractService);
const remediationVerifier = new RemediationAuthorizationVerifier(
  config.remediationAuthorizationPublicKeySpki,
  config.remediationAuthorizationKeyId,
  config.remediationReplayStorePath,
);
const aiProvider = config.aiProvider === 'openai-compatible' && config.aiApiUrl && config.aiApiKey && config.aiModel
  ? new OpenAiCompatibleProvider({ apiUrl: config.aiApiUrl, apiKey: config.aiApiKey, model: config.aiModel })
  : null;
const aiAgentService = new AgentService(aiProvider);
const a2aEvaluationService = new A2aEvaluationService(aiAgentService, contractService, agentSession);
const privacyGuardMcpHandler = createPrivacyGuardMcpHandler(contractService);
const privacyGuardMcpNodeHandler = toNodeHandler(privacyGuardMcpHandler);
const app = express();

app.disable('x-powered-by');
if (config.a2aPublicUrl) app.use(createA2aRouter(a2aEvaluationService, config.a2aPublicUrl));
app.use(express.json({ limit: '256kb' }));
app.get('/health', (_request, response) => response.json({ status: 'UP', service: 't3n-gateway' }));
app.all('/mcp', requireBearerServiceToken(config.gatewayServiceToken), (request, response) => {
  void privacyGuardMcpNodeHandler(request, response, request.body);
});
app.use('/internal', requireServiceToken(config.gatewayServiceToken));
app.use('/internal/t3n', createStatusRouter(tenantSession));
app.use('/internal/t3n/activity', createActivityRouter(activityLogService, config.gatewayServiceToken));
app.use('/internal/evidence', createEvidenceRouter());
app.use('/internal/agent', createAgentRouter(agentSession, delegationService, agentCardRegistry, config.gatewayServiceToken));
app.use('/internal/executor', createExecutorRouter(executorSession, executorDelegationService, config.gatewayServiceToken));
app.use('/internal/ai-agent', createAiAgentRouter(aiAgentService, config.gatewayServiceToken));
app.use('/internal/contracts/privacy-guard', createContractRouter(contractService, remediationVerifier, config.gatewayServiceToken, enterpriseIntegrationReadiness));

app.listen(config.port, '0.0.0.0', () => console.info(`t3n-gateway listening on port ${config.port}`));

const runtimeSecrets = [
  config.apiKey,
  config.agentApiKey ?? '',
  config.executorApiKey ?? '',
  config.gatewayServiceToken,
  config.aiApiKey ?? '',
  process.env.SECURITY_API_KEY ?? '',
];

void reconcileRuntimeProvisioning(
  config,
  tenantSession,
  agentSession,
  executorSession,
  delegationService,
  executorDelegationService,
  contractService,
  agentCardRegistry,
).then((result) => {
  if (!result.enabled) return;
  console.info(`T3N runtime provisioning reconciled: ${JSON.stringify(result)}`);
}).catch((error) => {
  const safe = sanitizeError(error, runtimeSecrets);
  console.error(`T3N runtime provisioning remains incomplete [${safe.category}]: ${safe.message}`);
});

void tenantSession.connect().catch((error) => {
  const safe = sanitizeError(error, runtimeSecrets);
  console.error(`Initial T3N tenant connection failed [${safe.category}]: ${safe.message}`);
});
if (config.agentApiKey) {
  void agentSession.connect().catch((error) => {
    const safe = sanitizeError(error, runtimeSecrets);
    console.error(`Initial T3N proposal-agent connection failed [${safe.category}]: ${safe.message}`);
  });
}
if (config.executorApiKey) {
  void executorSession.connect().catch((error) => {
    const safe = sanitizeError(error, runtimeSecrets);
    console.error(`Initial T3N protected-executor connection failed [${safe.category}]: ${safe.message}`);
  });
}
