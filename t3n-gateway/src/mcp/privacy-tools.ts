import type { PrivacyGuardContractService, RemediationVerificationRequest } from '../contract/privacy-guard-contract.js';

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

export interface McpToolResult {
  readonly content: Array<{ readonly type: 'text'; readonly text: string }>;
  readonly isError?: boolean;
}

export const PRIVACY_GUARD_MCP_TOOLS: readonly McpToolDefinition[] = Object.freeze([
  {
    name: 'privacy.evaluate_action',
    description: 'Evaluate an AI-proposed action under the active T3N privacy policy. This tool never authorizes remediation.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['request_id', 'action', 'resource', 'purpose', 'fields'],
      properties: {
        request_id: { type: 'string', minLength: 1, maxLength: 128 },
        action: { type: 'string', minLength: 1, maxLength: 80 },
        resource: { type: 'string', minLength: 1, maxLength: 256 },
        purpose: { type: 'string', minLength: 1, maxLength: 80 },
        host: { type: 'string', minLength: 1, maxLength: 253 },
        fields: { type: 'array', maxItems: 64, items: { type: 'string', minLength: 1, maxLength: 80 } },
        private_refs: { type: 'array', maxItems: 8, items: { type: 'string', minLength: 1, maxLength: 80 } },
      },
    },
  },
  {
    name: 'privacy.verify_remediation',
    description: 'Independently read back an already accepted remediation. This tool cannot execute or authorize remediation.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['request_id', 'operation_id', 'action', 'expected_state'],
      properties: {
        request_id: { type: 'string', minLength: 1, maxLength: 128 },
        operation_id: { type: 'string', minLength: 1, maxLength: 128 },
        action: { enum: ['revoke-credential', 'notify-security'] },
        expected_state: { enum: ['REVOKED', 'DELIVERED'] },
      },
    },
  },
  {
    name: 'privacy.contract_identity',
    description: 'Return the canonical deployed Privacy Guard contract id and current version.',
    inputSchema: { type: 'object', additionalProperties: false, properties: {} },
  },
]);

function textResult(value: unknown): McpToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value) }] };
}

export class PrivacyGuardMcpTools {
  constructor(private readonly contracts: PrivacyGuardContractService) {}

  list(): readonly McpToolDefinition[] {
    return PRIVACY_GUARD_MCP_TOOLS;
  }

  async call(name: string, args: unknown): Promise<McpToolResult> {
    if (!args || typeof args !== 'object' || Array.isArray(args)) {
      return { content: [{ type: 'text', text: 'Invalid MCP tool arguments' }], isError: true };
    }
    const body = args as Record<string, unknown>;
    try {
      if (name === 'privacy.contract_identity') return textResult(await this.contracts.identity());
      if (name === 'privacy.evaluate_action') {
        return textResult(await this.contracts.evaluate({
          request_id: String(body.request_id ?? ''),
          action: String(body.action ?? ''),
          resource: String(body.resource ?? ''),
          purpose: String(body.purpose ?? ''),
          host: body.host == null ? undefined : String(body.host),
          fields: Array.isArray(body.fields) ? body.fields.map(String) : [],
          private_refs: Array.isArray(body.private_refs) ? body.private_refs.map(String) : [],
        }));
      }
      if (name === 'privacy.verify_remediation') {
        return textResult(await this.contracts.verifyRemediation({
          request_id: String(body.request_id ?? ''),
          operation_id: String(body.operation_id ?? ''),
          action: String(body.action ?? '') as RemediationVerificationRequest['action'],
          expected_state: String(body.expected_state ?? '') as RemediationVerificationRequest['expected_state'],
        }));
      }
      return { content: [{ type: 'text', text: 'Unknown MCP tool' }], isError: true };
    } catch {
      return { content: [{ type: 'text', text: 'Privacy Guard MCP operation failed closed' }], isError: true };
    }
  }
}
