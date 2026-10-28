import express, { Router, type Express } from 'express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { AgentService } from '../agent/agent-service.js';
import { OpenAiCompatibleProvider } from '../agent/openai-compatible-provider.js';
import type { SelfHostedGatewayConfig } from '../config/env.js';
import { createActivityRouter } from '../http/activity-router.js';
import { createAiAgentRouter } from '../http/ai-agent-router.js';
import { createContractRouter } from '../http/contract-router.js';
import { createEvidenceRouter } from '../http/evidence-router.js';
import { createPrivacyGuardMcpHandler } from '../mcp/privacy-tools.js';
import { RemediationAuthorizationVerifier } from '../security/remediation-authorization.js';
import { requireBearerServiceToken, requireServiceToken } from '../security/service-auth.js';
import type { PrincipalKind, SelfHostedRuntime } from './self-hosted-runtime.js';

/**
 * The same internal API the backend already uses, served from guard-runtime. Paths keep their historical /t3n/
 * names so the backend needs no change to switch runtimes. Agent Card publication and A2A are T3N features and
 * are not exposed here.
 */
export function createSelfHostedApp(
  config: SelfHostedGatewayConfig,
  runtime: SelfHostedRuntime,
  remediationVerifier: Pick<RemediationAuthorizationVerifier, 'verifyAndConsume'> = new RemediationAuthorizationVerifier(
    config.remediationAuthorizationPublicKeySpki,
    config.remediationAuthorizationKeyId,
    config.remediationReplayStorePath,
  ),
): Express {
  const aiProvider = config.aiProvider === 'openai-compatible' && config.aiApiUrl && config.aiApiKey && config.aiModel
    ? new OpenAiCompatibleProvider({ apiUrl: config.aiApiUrl, apiKey: config.aiApiKey, model: config.aiModel })
    : null;
  const aiAgentService = new AgentService(aiProvider);
  const mcpHandler = createPrivacyGuardMcpHandler({
    identity: () => runtime.identity(),
    evaluate: (request) => runtime.evaluate(request),
    verifyRemediation: (request) => runtime.verifyRemediation(request),
  });
  const mcpNodeHandler = toNodeHandler(mcpHandler);
  const app = express();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));
  app.get('/health', (_request, response) => response.json({ status: 'UP', service: 't3n-gateway', trustRuntime: 'selfhosted' }));
  app.all('/mcp', requireBearerServiceToken(config.gatewayServiceToken), (request, response) => {
    void mcpNodeHandler(request, response, request.body);
  });
  app.use('/internal', requireServiceToken(config.gatewayServiceToken));
  app.use('/internal/t3n', tenantRouter(runtime));
  app.use('/internal/t3n/activity', createActivityRouter({ read: (query) => runtime.activity(query) }, config.gatewayServiceToken));
  app.use('/internal/evidence', createEvidenceRouter());
  app.use('/internal/agent', principalRouter(runtime, 'proposal'));
  app.use('/internal/executor', principalRouter(runtime, 'executor'));
  app.use('/internal/ai-agent', createAiAgentRouter(aiAgentService, config.gatewayServiceToken));
  app.use('/internal/contracts/privacy-guard', createContractRouter(
    runtime,
    remediationVerifier,
    config.gatewayServiceToken,
    { status: () => runtime.readiness() },
    runtime,
  ));
  return app;
}

function tenantRouter(runtime: SelfHostedRuntime): Router {
  const router = Router();
  router.get('/status', async (_request, response) => {
    const status = await runtime.tenantStatus();
    response.status(status.ready ? 200 : 503).json(status);
  });
  return router;
}

function principalRouter(runtime: SelfHostedRuntime, kind: PrincipalKind): Router {
  const router = Router();
  router.get('/status', async (_request, response) => {
    const status = await runtime.principalStatus(kind);
    response.status(status.ready ? 200 : 503).json(status);
  });
  router.get('/delegations/:contractId', async (_request, response) => {
    response.json(await runtime.delegationStatus(kind));
  });
  if (kind === 'proposal') {
    // No public registry exists outside T3N; report the agent as not registered rather than unavailable.
    router.get('/registration', async (_request, response) => {
      const now = new Date().toISOString();
      response.json({
        agentDid: runtime.proposalAgentId,
        state: 'NOT_REGISTERED',
        cardUri: null,
        cardSha256: null,
        verifiedAt: now,
        services: [],
        a2aConfigured: false,
        a2aPublicUrl: null,
        a2aConfigurationCheckedAt: now,
      });
    });
  }
  return router;
}
