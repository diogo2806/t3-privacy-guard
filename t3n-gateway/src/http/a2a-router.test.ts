import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import express from 'express';
import type { AddressInfo } from 'node:net';
import type { A2aEvaluationService } from '../agent/a2a-service.js';
import { SensitivePromptError } from '../security/prompt-privacy-guard.js';
import { createA2aRouter } from './a2a-router.js';

const PUBLIC_URL = 'https://guard.example/a2a';
const AGENT_DID = 'did:t3n:0123456789abcdef0123456789abcdef01234567';

function successService(onPrompt?: (prompt: string) => void): A2aEvaluationService {
  return {
    evaluate: async (prompt: string) => {
      onPrompt?.(prompt);
      return {
        proposal: {
          action: 'notify-user',
          resource: 'incident:synthetic',
          purpose: 'incident-response',
          host: null,
          fields: ['incident_id'],
          private_refs: ['verified_email'],
        },
        decision: 'ALLOW',
        reasonCode: 'POLICY_ALLOW',
        policyVersion: '1.2.3',
        policyHash: 'a'.repeat(64),
        agentDid: AGENT_DID,
      };
    },
  } as unknown as A2aEvaluationService;
}

async function withServer<T>(service: A2aEvaluationService, run: (baseUrl: string) => Promise<T>): Promise<T> {
  const app = express();
  app.use(createA2aRouter(service, PUBLIC_URL));
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address() as AddressInfo;
  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    server.close();
    await once(server, 'close');
  }
}

function requestBody(prompt = 'Evaluate this synthetic incident.') {
  return {
    jsonrpc: '2.0',
    id: 'rpc-1',
    method: 'SendMessage',
    params: {
      message: {
        messageId: 'message-1',
        role: 'ROLE_USER',
        parts: [{ text: prompt, mediaType: 'text/plain' }],
      },
    },
  };
}

async function post(baseUrl: string, body: unknown, version = '1.0') {
  return fetch(`${baseUrl}/a2a`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'A2A-Version': version },
    body: JSON.stringify(body),
  });
}

test('well-known Agent Card advertises only the synchronous evaluation skill', async () => {
  await withServer(successService(), async (baseUrl) => {
    const response = await fetch(`${baseUrl}/.well-known/agent-card.json`);
    assert.equal(response.status, 200);
    const card = await response.json() as Record<string, unknown>;
    assert.equal(card.name, 'T3 Privacy Guard');
    assert.deepEqual(card.supportedInterfaces, [{ url: PUBLIC_URL, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }]);
    assert.deepEqual(card.capabilities, { streaming: false, pushNotifications: false, extendedAgentCard: false });
    const serialized = JSON.stringify(card);
    assert.match(serialized, /A2A evaluation service/);
    assert.match(serialized, /not exposed through A2A/);
    assert.doesNotMatch(serialized, /api[_-]?key|private[_-]?key|executor_did|execute-remediation|x402/i);
  });
});

test('SendMessage returns proposal plus minimal T3N decision provenance without remediation capability', async () => {
  let observedPrompt = '';
  await withServer(successService((prompt) => { observedPrompt = prompt; }), async (baseUrl) => {
    const response = await post(baseUrl, requestBody());
    assert.equal(response.status, 200);
    const body = await response.json() as Record<string, unknown>;
    assert.equal(body.jsonrpc, '2.0');
    assert.equal(body.id, 'rpc-1');
    const serialized = JSON.stringify(body);
    assert.match(serialized, /POLICY_ALLOW/);
    assert.match(serialized, new RegExp(AGENT_DID));
    assert.doesNotMatch(serialized, /requires_human_authorization|capability|execute-remediation|verify-remediation|pii_did/i);
    assert.equal(observedPrompt, 'Evaluate this synthetic incident.');
  });
});

test('strict request schema rejects client-supplied identity, decision and capability fields', async () => {
  let calls = 0;
  await withServer(successService(() => { calls += 1; }), async (baseUrl) => {
    for (const forbidden of ['agent_did', 'pii_did', 'decision', 'capability']) {
      const body = requestBody() as Record<string, unknown>;
      body.params = { ...(body.params as object), [forbidden]: 'attacker-controlled' };
      const response = await post(baseUrl, body);
      assert.equal(response.status, 400, forbidden);
    }
    assert.equal(calls, 0);
  });
});

test('sensitive prompt rejection is sanitized and does not echo the literal', async () => {
  const service = {
    evaluate: async () => { throw new SensitivePromptError(['EMAIL_LITERAL']); },
  } as unknown as A2aEvaluationService;
  const literal = 'private.user@example.com';

  await withServer(service, async (baseUrl) => {
    const response = await post(baseUrl, requestBody(`email=${literal}`));
    assert.equal(response.status, 400);
    const text = await response.text();
    assert.match(text, /SENSITIVE_PROMPT_REJECTED/);
    assert.doesNotMatch(text, new RegExp(literal.replace('.', '\\.')));
  });
});

test('v1 endpoint rejects legacy method, missing version and oversized body', async () => {
  await withServer(successService(), async (baseUrl) => {
    const legacy = requestBody() as Record<string, unknown>;
    legacy.method = 'message/send';
    assert.equal((await post(baseUrl, legacy)).status, 400);

    const missingVersion = await fetch(`${baseUrl}/a2a`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody()),
    });
    assert.equal(missingVersion.status, 400);

    const oversized = requestBody('x'.repeat(17_000));
    assert.equal((await post(baseUrl, oversized)).status, 413);
  });
});
