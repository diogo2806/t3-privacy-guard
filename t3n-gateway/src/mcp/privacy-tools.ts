import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import type { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';

export type PrivacyGuardMcpContract = Pick<
  PrivacyGuardContractService,
  'identity' | 'evaluate' | 'verifyRemediation'
>;

export const PRIVACY_GUARD_MCP_TOOL_NAMES = Object.freeze([
  'privacy.contract_identity',
  'privacy.evaluate_action',
  'privacy.verify_remediation',
] as const);

export const PRIVACY_CONTRACT_IDENTITY_INPUT_SCHEMA = z.object({}).strict();

export const PRIVACY_EVALUATE_ACTION_INPUT_SCHEMA = z.object({
  request_id: z.string().min(1).max(128),
  action: z.string().min(1).max(80),
  resource: z.string().min(1).max(256),
  purpose: z.string().min(1).max(80),
  host: z.string().min(1).max(253).optional(),
  fields: z.array(z.string().min(1).max(80)).max(64),
  private_refs: z.array(z.string().min(1).max(80)).max(8).optional(),
}).strict();

export const PRIVACY_VERIFY_REMEDIATION_INPUT_SCHEMA = z.object({
  request_id: z.string().min(1).max(128),
  operation_id: z.string().min(1).max(128),
  action: z.enum(['revoke-credential', 'notify-security']),
  expected_state: z.enum(['REVOKED', 'DELIVERED']),
}).strict();

function textResult(value: unknown) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(value) }],
  };
}

function failClosedResult() {
  return {
    content: [{ type: 'text' as const, text: 'Privacy Guard MCP operation failed closed' }],
    isError: true,
  };
}

export function createPrivacyGuardMcpServer(contracts: PrivacyGuardMcpContract): McpServer {
  const server = new McpServer(
    { name: 't3-privacy-guard', version: '0.2.0' },
    { capabilities: { tools: {} } },
  );

  server.registerTool(
    'privacy.contract_identity',
    {
      description: 'Return the canonical deployed Privacy Guard contract id and current version.',
      inputSchema: PRIVACY_CONTRACT_IDENTITY_INPUT_SCHEMA,
    },
    async () => {
      try {
        return textResult(await contracts.identity());
      } catch {
        return failClosedResult();
      }
    },
  );

  server.registerTool(
    'privacy.evaluate_action',
    {
      description: 'Evaluate an AI-proposed action under the active T3N privacy policy. This tool never authorizes remediation.',
      inputSchema: PRIVACY_EVALUATE_ACTION_INPUT_SCHEMA,
    },
    async (request) => {
      try {
        return textResult(await contracts.evaluate(request));
      } catch {
        return failClosedResult();
      }
    },
  );

  server.registerTool(
    'privacy.verify_remediation',
    {
      description: 'Independently read back an already accepted remediation. This tool cannot execute or authorize remediation.',
      inputSchema: PRIVACY_VERIFY_REMEDIATION_INPUT_SCHEMA,
    },
    async (request) => {
      try {
        return textResult(await contracts.verifyRemediation(request));
      } catch {
        return failClosedResult();
      }
    },
  );

  return server;
}

export function createPrivacyGuardMcpHandler(contracts: PrivacyGuardMcpContract) {
  return createMcpHandler(() => createPrivacyGuardMcpServer(contracts));
}
