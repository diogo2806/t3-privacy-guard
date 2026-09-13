import express from 'express';
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
import { PrivacyGuardContractService } from './contract/privacy-guard-contract.js';
import { createA2aRouter } from './http/a2a-router.js';
import { createActivityRouter } from './http/activity-router.js';
import { createAgentRouter } from './http/agent-router.js';
import { createAiAgentRouter } from './http/ai-agent-router.js';
import { createContractRouter } from './http/contract-router.js';
import { createExecutorRouter } from './http/executor-router.js';
import { createStatusRouter } from './http/status-router.js';
import { RemediationAuthorizationVerifier } from './security/remediation-authorization.js';
import { sanitizeError } from './security/sanitize.js';
import { requireServiceToken } from './security/service-auth.js';
import { TrustManifestFloorStore } from './security/trust-manifest-floor-store.js';
import { ActivityLogService } from './t3n/activity-log-service.js';
import { T3nSession } from './t3n/session.js';

const config = readGatewayConfig();
const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const tenantSession = new T3nSession(config, trustFloorStore);
const agentSession = new AgentSession(config, trustFloorStore);
const executorSession = new ExecutorSession(config, trustFloorStore);
const agentCardRegistry = new AgentCardRegistry(agentSession, undefined, undefined, config.a2aPublicUrl);
const activityLogService = new ActivityLogService(tenantSession);
const delegationService = new DelegationService(tenantSession, agentSession, PROPOSAL_DELEGATION_REQUIREMENTS);
const executorDelegationService = new DelegationService(tenantSession, executorSession, EXECUTOR_DELEGATION_REQUIREMENTS);
const contractService = new PrivacyGuardContractService(config, tenantSession, agentSession, executorSession, activityLogService);
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
const app = express();

app.disable('x-powered-by');
if (config.a2aPublicUrl) app.use(createA2aRouter(a2aEvaluationService, config.a2aPublicUrl));
app.use(express.json({ limit: '256kb' }));
app.get('/health', (_request, response) => response.json({ status: 'UP', service: 't3n-gateway' }));
app.use('/internal', requireServiceToken(config.gatewayServiceToken));
app.use('/internal/t3n', createStatusRouter(tenantSession));
app.use('/internal/t3n/activity', createActivityRouter(activityLogService, config.gatewayServiceToken));
app.use('/internal/agent', createAgentRouter(agentSession, delegationService, agentCardRegistry, config.gatewayServiceToken));
app.use('/internal/executor', createExecutorRouter(executorSession, executorDelegationService, config.gatewayServiceToken));
app.use('/internal/ai-agent', createAiAgentRouter(aiAgentService, config.gatewayServiceToken));
app.use('/internal/contracts/privacy-guard', createContractRouter(contractService, remediationVerifier, config.gatewayServiceToken));

app.listen(config.port, '0.0.0.0', () => console.info(`t3n-gateway listening on port ${config.port}`));

void tenantSession.connect().catch((error) => {
  const safe = sanitizeError(error, [config.apiKey, config.gatewayServiceToken, config.aiApiKey ?? '']);
  console.error(`Initial T3N tenant connection failed [${safe.category}]: ${safe.message}`);
});
if (config.agentApiKey) {
  void agentSession.connect().catch((error) => {
    const safe = sanitizeError(error, [config.agentApiKey ?? '', config.executorApiKey ?? '', config.gatewayServiceToken, config.aiApiKey ?? '']);
    console.error(`Initial T3N proposal-agent connection failed [${safe.category}]: ${safe.message}`);
  });
}
if (config.executorApiKey) {
  void executorSession.connect().catch((error) => {
    const safe = sanitizeError(error, [config.executorApiKey ?? '', config.agentApiKey ?? '', config.gatewayServiceToken, config.aiApiKey ?? '']);
    console.error(`Initial T3N protected-executor connection failed [${safe.category}]: ${safe.message}`);
  });
}
