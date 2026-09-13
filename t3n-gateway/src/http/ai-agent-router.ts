import { Router } from 'express';
import type { AgentService } from '../agent/agent-service.js';
import { logTraceStage, traceRequest } from '../observability/trace.js';
import { SensitivePromptError } from '../security/prompt-privacy-guard.js';
import { requireServiceToken } from '../security/service-auth.js';

export function createAiAgentRouter(agentService: AgentService, serviceToken: string): Router {
  const router = Router();

  router.post('/propose', requireServiceToken(serviceToken), traceRequest, async (request, response) => {
    try {
      const prompt = typeof request.body?.prompt === 'string' ? request.body.prompt : '';
      const result = await agentService.propose(prompt);
      logTraceStage(response, 'AI_PROVIDER_PROPOSAL', undefined, 'RECEIVED');
      response.json(result);
    } catch (error) {
      const code = error instanceof Error ? error.message : 'UNKNOWN';
      if (error instanceof SensitivePromptError) {
        logTraceStage(response, 'AI_PROVIDER_PROPOSAL', undefined, 'DENIED');
        response.status(422).json({
          error: 'SENSITIVE_PROMPT_REJECTED',
          message: 'Remove literal private values and refer to them by an approved logical category.',
          categories: error.categories,
        });
      } else if (code === 'AI_PROVIDER_DISABLED') {
        logTraceStage(response, 'AI_PROVIDER_PROPOSAL', undefined, 'UNAVAILABLE');
        response.status(503).json({ error: 'AI agent provider is not configured' });
      } else if (code.startsWith('AGENT_PROMPT_') || code.startsWith('AGENT_PROPOSAL_') || code.startsWith('AGENT_TOOL_')) {
        logTraceStage(response, 'AI_PROVIDER_PROPOSAL', undefined, 'FAILED');
        response.status(422).json({ error: 'AI agent returned an invalid or unsafe structured proposal' });
      } else {
        logTraceStage(response, 'AI_PROVIDER_PROPOSAL', undefined, 'UNAVAILABLE');
        response.status(503).json({ error: 'AI agent provider is unavailable' });
      }
    }
  });

  return router;
}
