import express from 'express';
import { AgentSession } from './agent/agent-session.js';
import { DelegationService } from './agent/delegation-service.js';
import { readGatewayConfig } from './config/env.js';
import { PrivacyGuardContractService } from './contract/privacy-guard-contract.js';
import { createAgentRouter } from './http/agent-router.js';
import { createContractRouter } from './http/contract-router.js';
import { createStatusRouter } from './http/status-router.js';
import { RemediationAuthorizationVerifier } from './security/remediation-authorization.js';
import { sanitizeError } from './security/sanitize.js';
import { T3nSession } from './t3n/session.js';

const config = readGatewayConfig();
const tenantSession = new T3nSession(config);
const agentSession = new AgentSession(config);
const delegationService = new DelegationService(tenantSession, agentSession);
const contractService = new PrivacyGuardContractService(config, tenantSession, agentSession);
const remediationVerifier = new RemediationAuthorizationVerifier(
  config.remediationCapabilityKey,
  config.remediationReplayStorePath,
);
const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));
app.get('/health', (_request, response) => response.json({ status: 'UP', service: 't3n-gateway' }));
app.use('/internal/t3n', createStatusRouter(tenantSession));
app.use('/internal/agent', createAgentRouter(agentSession, delegationService, config.gatewayServiceToken));
app.use('/internal/contracts/privacy-guard', createContractRouter(contractService, remediationVerifier, config.gatewayServiceToken));

app.listen(config.port, '0.0.0.0', () => console.info(`t3n-gateway listening on port ${config.port}`));

void tenantSession.connect().catch((error) => {
  const safe = sanitizeError(error, [config.apiKey, config.gatewayServiceToken, config.remediationCapabilityKey]);
  console.error(`Initial T3N tenant connection failed [${safe.category}]: ${safe.message}`);
});
if (config.agentApiKey) {
  void agentSession.connect().catch((error) => {
    const safe = sanitizeError(error, [config.agentApiKey ?? '', config.gatewayServiceToken, config.remediationCapabilityKey]);
    console.error(`Initial T3N agent connection failed [${safe.category}]: ${safe.message}`);
  });
}
