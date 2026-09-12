export interface AgentProposal {
  action: string;
  resource: string;
  purpose: string;
  host?: string | null;
  fields: string[];
}

const ALLOWED_KEYS = new Set(['action', 'resource', 'purpose', 'host', 'fields']);
const FORBIDDEN_KEYS = new Set(['decision', 'allow', 'override', 'approved', 'credential', 'secret', 'apiKey', 'api_key', 'agent_did', 'pii_did']);

function stringField(value: unknown, name: string, max = 200): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`AGENT_PROPOSAL_INVALID_${name.toUpperCase()}`);
  return value.trim();
}

export function validateAgentProposal(value: unknown): AgentProposal {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('AGENT_PROPOSAL_INVALID');
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (FORBIDDEN_KEYS.has(key) || !ALLOWED_KEYS.has(key)) throw new Error('AGENT_PROPOSAL_FORBIDDEN_FIELD');
  }
  if (!Array.isArray(record.fields) || record.fields.length > 20) throw new Error('AGENT_PROPOSAL_INVALID_FIELDS');
  const fields = record.fields.map((field) => stringField(field, 'field', 80));
  const host = record.host == null ? null : stringField(record.host, 'host', 253);
  return {
    action: stringField(record.action, 'action', 80),
    resource: stringField(record.resource, 'resource', 200),
    purpose: stringField(record.purpose, 'purpose', 120),
    host,
    fields,
  };
}
