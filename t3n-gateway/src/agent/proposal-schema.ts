export interface AgentProposal {
  action: string;
  resource: string;
  purpose: string;
  host?: string | null;
  fields: string[];
  private_refs: string[];
}

const ALLOWED_KEYS = new Set(['action', 'resource', 'purpose', 'host', 'fields', 'private_refs']);
const FORBIDDEN_KEYS = new Set(['decision', 'allow', 'override', 'approved', 'credential', 'secret', 'apiKey', 'api_key', 'agent_did', 'pii_did']);
const KNOWN_PRIVATE_REFS = new Set(['verified_email']);

function stringField(value: unknown, name: string, max = 200): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`AGENT_PROPOSAL_INVALID_${name.toUpperCase()}`);
  return value.trim();
}

function privateRef(value: unknown): string {
  const ref = stringField(value, 'private_ref', 64).toLowerCase();
  if (ref.includes('{{') || ref.includes('}}') || ref.startsWith('profile.') || !/^[a-z][a-z0-9_]*$/.test(ref)) {
    throw new Error('AGENT_PROPOSAL_RAW_PLACEHOLDER_FORBIDDEN');
  }
  if (!KNOWN_PRIVATE_REFS.has(ref)) throw new Error('AGENT_PROPOSAL_PRIVATE_REFERENCE_UNKNOWN');
  return ref;
}

export function validateAgentProposal(value: unknown): AgentProposal {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('AGENT_PROPOSAL_INVALID');
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (FORBIDDEN_KEYS.has(key) || !ALLOWED_KEYS.has(key)) throw new Error('AGENT_PROPOSAL_FORBIDDEN_FIELD');
  }
  if (!Array.isArray(record.fields) || record.fields.length > 20) throw new Error('AGENT_PROPOSAL_INVALID_FIELDS');
  const privateRefsInput = record.private_refs ?? [];
  if (!Array.isArray(privateRefsInput) || privateRefsInput.length > 4) throw new Error('AGENT_PROPOSAL_INVALID_PRIVATE_REFS');
  const fields = record.fields.map((field) => stringField(field, 'field', 80));
  const privateRefs = privateRefsInput.map(privateRef);
  const host = record.host == null ? null : stringField(record.host, 'host', 253);
  return {
    action: stringField(record.action, 'action', 80),
    resource: stringField(record.resource, 'resource', 200),
    purpose: stringField(record.purpose, 'purpose', 120),
    host,
    fields,
    private_refs: privateRefs,
  };
}
