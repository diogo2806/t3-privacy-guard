import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { toNodeHandler } from '@modelcontextprotocol/node';
import express from 'express';
import { requireBearerServiceToken } from '../security/service-auth.js';
import {
  createPrivacyGuardMcpHandler,
  PRIVACY_CONTRACT_IDENTITY_INPUT_SCHEMA,
  PRIVACY_EVALUATE_ACTION_INPUT_SCHEMA,
  PRIVACY_GUARD_MCP_TOOL_NAMES,
  PRIVACY_VERIFY_REMEDIATION_INPUT_SCHEMA,
  type PrivacyGuardMcpContract,
} from './privacy-tools.js';

const SERVICE_TOKEN = 'mcp-test-service-token';

function successContract(overrides: Partial<PrivacyGuardMcpContract> = {}): PrivacyGuardMcpContract {
  return {
    identity: async () => ({
      contractId: 'z:tenant:privacy-guard',
      contractVersion: '1.2.3',
    }),
    evaluate: async (request) => ({
      request_id: request.request_id,
      decision: 'ALLOW',
      reason_code: 'POLICY_ALLOW',
      reason: 'Synthetic test decision',
      allowed_fields: [...request.fields],
      redacted_fields: [],
      allowed_private_refs: [...(request.private_refs ?? [])],
      redacted_private_refs: [],
      policy_version: '1.2.3',
      policy_hash: 'a'.repeat(64),
      requires_human_authorization: false,
    }),
    verifyRemediation: async (request) => ({
      request_id: request.request_id,
      status: 'VERIFIED',
      observed_state: request.expected_state,
      recipient_resolved: request.action === 'notify-security' ? true : null,
      payload_proof: null,
    }),
    ...overrides,
  };
}

async function withServer<T>(contract: PrivacyGuardMcpContract, run: (baseUrl: string) => Promise<T>): Promise<T> {
  const mcpHandler = createPrivacyGuardMcpHandler(contract);
  const nodeHandler = toNodeHandler(mcpHandler);
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.all('/mcp', requireBearerServiceToken(SERVICE_TOKEN), (request, response) => {
    void nodeHandler(request, response, request.body);
  });

  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address() as AddressInfo;
  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await mcpHandler.close();
    server.close();
    await once(server, 'close');
  }
}

async function withClient<T>(contract: PrivacyGuardMcpContract, run: (client: Client) => Promise<T>): Promise<T> {
  return withServer(contract, async (baseUrl) => {
    const client = new Client(
      { name: 'privacy-guard-test-client', version: '1.0.0' },
      { versionNegotiation: { mode: 'auto' } },
    );
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      authProvider: { token: async () => SERVICE_TOKEN },
    });
    await client.connect(transport);
    try {
      return await run(client);
    } finally {
      await client.close();
    }
  });
}

function parseTextResult(result: unknown): unknown {
  const candidate = result as { content?: Array<{ type?: string; text?: string }> };
  const first = candidate.content?.[0];
  assert.equal(first?.type, 'text');
  assert.equal(typeof first?.text, 'string');
  return JSON.parse(first?.text ?? 'null');
}

test('MCP input schemas reject non-objects, extra fields, limits and invalid enums', () => {
  assert.equal(PRIVACY_CONTRACT_IDENTITY_INPUT_SCHEMA.safeParse(null).success, false);
  assert.equal(PRIVACY_CONTRACT_IDENTITY_INPUT_SCHEMA.safeParse({ execute_remediation: true }).success, false);
  assert.equal(PRIVACY_EVALUATE_ACTION_INPUT_SCHEMA.safeParse('not-an-object').success, false);
  assert.equal(PRIVACY_EVALUATE_ACTION_INPUT_SCHEMA.safeParse({
    request_id: 'request-1',
    action: 'read',
    resource: 'record:1',
    purpose: 'support',
    fields: Array.from({ length: 65 }, (_, index) => `field-${index}`),
  }).success, false);
  assert.equal(PRIVACY_VERIFY_REMEDIATION_INPUT_SCHEMA.safeParse({
    request_id: 'request-1',
    operation_id: 'operation-1',
    action: 'delete-everything',
    expected_state: 'UNKNOWN',
  }).success, false);
});

test('remote MCP endpoint requires the gateway bearer token', async () => {
  await withServer(successContract(), async (baseUrl) => {
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(response.status, 401);
    assert.match(response.headers.get('WWW-Authenticate') ?? '', /^Bearer\b/);
    assert.match(await response.text(), /MCP bearer authentication required/);
  });
});

test('official client negotiates the modern protocol and discovers exactly three least-privilege tools', async () => {
  await withClient(successContract(), async (client) => {
    assert.equal(client.getProtocolEra(), 'modern');
    const { tools } = await client.listTools();
    const discovered = tools.map((tool) => tool.name).sort();
    assert.deepEqual(discovered, [...PRIVACY_GUARD_MCP_TOOL_NAMES].sort());
    assert.doesNotMatch(JSON.stringify(tools), /execute[-_]remediation/i);
  });
});

test('valid MCP calls dispatch to contract identity, evaluation and verification only', async () => {
  let identityCalls = 0;
  let evaluateCalls = 0;
  let verifyCalls = 0;
  let observedEvaluation: unknown;
  let observedVerification: unknown;
  const base = successContract();
  const contract = successContract({
    identity: async () => {
      identityCalls += 1;
      return base.identity();
    },
    evaluate: async (request) => {
      evaluateCalls += 1;
      observedEvaluation = request;
      return base.evaluate(request);
    },
    verifyRemediation: async (request) => {
      verifyCalls += 1;
      observedVerification = request;
      return base.verifyRemediation(request);
    },
  });

  await withClient(contract, async (client) => {
    const identity = parseTextResult(await client.callTool({
      name: 'privacy.contract_identity',
      arguments: {},
    })) as Record<string, unknown>;
    assert.equal(identity.contractId, 'z:tenant:privacy-guard');

    const evaluation = parseTextResult(await client.callTool({
      name: 'privacy.evaluate_action',
      arguments: {
        request_id: 'request-1',
        action: 'read',
        resource: 'record:1',
        purpose: 'support',
        host: 'guard.example',
        fields: ['display_name'],
        private_refs: ['verified_email'],
      },
    })) as Record<string, unknown>;
    assert.equal(evaluation.decision, 'ALLOW');

    const verification = parseTextResult(await client.callTool({
      name: 'privacy.verify_remediation',
      arguments: {
        request_id: 'request-2',
        operation_id: 'operation-1',
        action: 'revoke-credential',
        expected_state: 'REVOKED',
      },
    })) as Record<string, unknown>;
    assert.equal(verification.status, 'VERIFIED');
  });

  assert.equal(identityCalls, 1);
  assert.equal(evaluateCalls, 1);
  assert.equal(verifyCalls, 1);
  assert.deepEqual(observedEvaluation, {
    request_id: 'request-1',
    action: 'read',
    resource: 'record:1',
    purpose: 'support',
    host: 'guard.example',
    fields: ['display_name'],
    private_refs: ['verified_email'],
  });
  assert.deepEqual(observedVerification, {
    request_id: 'request-2',
    operation_id: 'operation-1',
    action: 'revoke-credential',
    expected_state: 'REVOKED',
  });
});

test('invalid tool arguments fail before contract dispatch and privileged tools are unreachable', async () => {
  let evaluateCalls = 0;
  let verifyCalls = 0;
  const base = successContract();
  const contract = successContract({
    evaluate: async (request) => {
      evaluateCalls += 1;
      return base.evaluate(request);
    },
    verifyRemediation: async (request) => {
      verifyCalls += 1;
      return base.verifyRemediation(request);
    },
  });

  await withClient(contract, async (client) => {
    const oversized = await client.callTool({
      name: 'privacy.evaluate_action',
      arguments: {
        request_id: 'request-1',
        action: 'read',
        resource: 'record:1',
        purpose: 'support',
        fields: Array.from({ length: 65 }, (_, index) => `field-${index}`),
      },
    });
    assert.equal(oversized.isError, true);
    assert.match(JSON.stringify(oversized), /Invalid arguments for tool privacy\.evaluate_action/);

    const invalidEnum = await client.callTool({
      name: 'privacy.verify_remediation',
      arguments: {
        request_id: 'request-2',
        operation_id: 'operation-1',
        action: 'delete-everything',
        expected_state: 'UNKNOWN',
      },
    });
    assert.equal(invalidEnum.isError, true);

    await assert.rejects(
      () => client.callTool({ name: 'execute-remediation', arguments: {} }),
      /not found/i,
    );
    await assert.rejects(
      () => client.callTool({ name: 'privacy.execute_remediation', arguments: {} }),
      /not found/i,
    );
  });

  assert.equal(evaluateCalls, 0);
  assert.equal(verifyCalls, 0);
});

test('contract failures return a sanitized fail-closed result without secret material', async () => {
  const secret = 't3n_key_sensitive.synthetic-secret';
  const contract = successContract({
    evaluate: async () => {
      throw new Error(`T3N_API_KEY=${secret}; Authorization: Bearer ${secret}`);
    },
  });

  await withClient(contract, async (client) => {
    const result = await client.callTool({
      name: 'privacy.evaluate_action',
      arguments: {
        request_id: 'request-secret',
        action: 'read',
        resource: 'record:secret',
        purpose: 'support',
        fields: ['display_name'],
      },
    });
    assert.equal(result.isError, true);
    const serialized = JSON.stringify(result);
    assert.match(serialized, /Privacy Guard MCP operation failed closed/);
    assert.doesNotMatch(serialized, /t3n_key_|synthetic-secret|T3N_API_KEY|Authorization|Bearer/i);
  });
});
