import express from 'express';
import { AgentCardRegistrationService } from './agent/agent-card.js';
import { AgentService } from './agent/agent-service.js';
import { AgentSession } from './agent/agent-session.js';
import { DelegationService } from './agent/delegation-service.js';
import { OpenAiCompatibleProvider } from './agent/openai-compatible-provider.js';
import { readGatewayConfig } from './config/env.js';
import { PrivacyGuardContractService } from './contract/privacy-guard-contract.js';
import { createActivityRouter } from './http/activity-router.js';
import { createAgentRouter } from './http/agent-router.js';
import { createAiAgentRouter } from './http/ai-agent-router.js';
import { createContractRouter } from './http/contract-router.js';
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
const agentRegistrationService = new AgentCardRegistrationService(agentSession, config.network);
const activityLogService = new ActivityLogService(tenantSession);
const delegationService = new DelegationService(tenantSession, agentSession);
const contractService = new PrivacyGuardContractService(config, tenantSession, agentSession, activityLogService);
const remediationVerifier = new RemediationAuthorizationVerifier(config.remediationCapabilityKey, config.remediationReplayStorePath);
const aiProvider = config.aiProvider === 'openai-compatible' && config.aiApiUrl && config.aiApiKey && config.aiModel
  ? new OpenAiCompatibleProvider({ apiUrl: config.aiApiUrl, apiKey: config.aiApiKey, model: config.aiModel })
  : null;
const aiAgentService = new AgentService(aiProvider);
const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));
app.get('/health', (_request, response) => response.json({ status: 'UP', service: 't3n-gateway' }));
app.use('/internal', requireServiceToken(config.gatewayServiceToken));
app.use('/internal/t3n', createStatusRouter(tenantSession));
app.use('/internal/t3n/activity', createActivityRouter(activityLogService, config.gatewayServiceToken));
app.use('/internal/agent', createAgentRouter(agentSession, delegationService, agentRegistrationService, config.gatewayServiceToken));
app.use('/internal/ai-agent', createAiAgentRouter(aiAgentService, config.gatewayServiceToken));
app.use('/internal/contracts/privacy-guard', createContractRouter(contractService, remediationVerifier, config.gatewayServiceToken));

app.listen(config.port, '0.0.0.0', () => console.info(`t3n-gateway listening on port ${config.port}`));

void tenantSession.connect().catch((error) => {
  const safe = sanitizeError(error, [config.apiKey, config.gatewayServiceToken, config.remediationCapabilityKey, config.aiApiKey ?? '']);
  console.error(`Initial T3N tenant connection failed [${safe.category}]: ${safe.message}`);
});
if (config.agentApiKey) {
  void agentSession.connect().catch((error) => {
    const safe = sanitizeError(error, [config.agentApiKey ?? '', config.gatewayServiceToken, config.remediationCapabilityKey, config.aiApiKey ?? '']);
    console.error(`Initial T3N agent connection failed [${safe.category}]: ${safe.message}`);
  });
}
