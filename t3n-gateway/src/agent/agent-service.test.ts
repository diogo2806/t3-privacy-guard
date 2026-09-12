import assert from 'node:assert/strict';
import test from 'node:test';
import type { AgentProvider } from './agent-provider.js';
import { AgentService } from './agent-service.js';

test('disabled provider fails closed', async () => {
  await assert.rejects(() => new AgentService(null).propose('revoke credential'), /AI_PROVIDER_DISABLED/);
});

test('provider proposal is returned without adding authority or plaintext fields', async () => {
  const provider: AgentProvider = {
    async propose() {
      return {
        provider: 'test-provider', model: 'test-model',
        proposal: {
          action: 'notify-security', resource: 'incident:test', purpose: 'incident-notification', host: 'postman-echo.com',
          fields: ['incident_id'], private_refs: ['verified_email'],
        },
      };
    },
  };
  const result = await new AgentService(provider).propose('notify verified contact');
  assert.equal(result.provider, 'test-provider');
  assert.deepEqual(result.proposal.private_refs, ['verified_email']);
  assert.equal(JSON.stringify(result).includes('{{profile.'), false);
});

test('empty and oversized prompts are rejected before provider execution', async () => {
  const provider: AgentProvider = { async propose() { throw new Error('should-not-run'); } };
  await assert.rejects(() => new AgentService(provider).propose('   '), /AGENT_PROMPT_INVALID/);
  await assert.rejects(() => new AgentService(provider).propose('x'.repeat(4_001)), /AGENT_PROMPT_INVALID/);
});
