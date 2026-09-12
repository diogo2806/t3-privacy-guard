import { createHash } from 'node:crypto';

const FORBIDDEN_SECRET_FIELDS = new Set(['api_key', 'card_number', 'credential', 'cpf', 'password', 'private_key', 'secret', 'ssn', 'token']);
const KNOWN_PRIVATE_REFS = new Set(['verified_email']);

export interface OperationalActionPolicy {
  purpose: string;
  allowed_fields: string[];
  allowed_hosts: string[];
  allowed_private_refs: string[];
  requires_host: boolean;
  requires_human_authorization: boolean;
}

export interface OperationalPolicyDocument {
  version: string;
  actions: Record<string, OperationalActionPolicy>;
}

export interface CanonicalOperationalPolicy {
  document: OperationalPolicyDocument;
  canonicalJson: string;
  hash: string;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function normalizeList(value: unknown, label: string, maxItems: number, maxLength: number): string[] {
  if (!Array.isArray(value) || value.length > maxItems) throw new Error(`${label} is invalid`);
  const output = value.map((item) => {
    if (typeof item !== 'string') throw new Error(`${label} must contain strings`);
    const normalized = item.trim().toLowerCase();
    if (!normalized || normalized.length > maxLength) throw new Error(`${label} contains an invalid value`);
    return normalized;
  });
  if (new Set(output).size !== output.length) throw new Error(`${label} contains duplicate normalized values`);
  return output.sort();
}

function validHost(host: string): boolean {
  return host.length <= 253 && !/[\s/:@]/.test(host);
}

export function canonicalizeOperationalPolicy(input: unknown): CanonicalOperationalPolicy {
  const root = asRecord(input, 'policy');
  if (Object.keys(root).some((key) => !['version', 'actions'].includes(key))) throw new Error('policy contains unknown properties');
  const version = typeof root.version === 'string' ? root.version.trim() : '';
  if (!version || version.length > 64 || !/^[A-Za-z0-9._:-]+$/.test(version)) throw new Error('policy version is invalid');
  const actionsInput = asRecord(root.actions, 'policy.actions');
  const entries = Object.entries(actionsInput);
  if (entries.length < 1 || entries.length > 16) throw new Error('policy action count is invalid');

  const actions: Record<string, OperationalActionPolicy> = {};
  for (const [rawAction, rawRule] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    const action = rawAction.trim().toLowerCase();
    if (!action || action.length > 80 || action !== rawAction.trim()) throw new Error('policy action name is not canonical');
    const rule = asRecord(rawRule, `policy.actions.${action}`);
    const allowedKeys = ['purpose', 'allowed_fields', 'allowed_hosts', 'allowed_private_refs', 'requires_host', 'requires_human_authorization'];
    if (Object.keys(rule).some((key) => !allowedKeys.includes(key))) throw new Error(`policy action ${action} contains unknown properties`);
    const purpose = typeof rule.purpose === 'string' ? rule.purpose.trim().toLowerCase() : '';
    if (!purpose || purpose.length > 80) throw new Error(`policy action ${action} has invalid purpose`);
    const allowedFields = normalizeList(rule.allowed_fields ?? [], `${action}.allowed_fields`, 64, 80);
    if (allowedFields.some((field) => FORBIDDEN_SECRET_FIELDS.has(field))) throw new Error(`policy action ${action} attempts to allow a forbidden secret field`);
    const allowedHosts = normalizeList(rule.allowed_hosts ?? [], `${action}.allowed_hosts`, 16, 253);
    if (allowedHosts.some((host) => !validHost(host))) throw new Error(`policy action ${action} contains invalid host`);
    const allowedPrivateRefs = normalizeList(rule.allowed_private_refs ?? [], `${action}.allowed_private_refs`, 8, 80);
    if (allowedPrivateRefs.some((ref) => !KNOWN_PRIVATE_REFS.has(ref))) throw new Error(`policy action ${action} contains unknown private reference`);
    if (typeof rule.requires_host !== 'boolean' || typeof rule.requires_human_authorization !== 'boolean') throw new Error(`policy action ${action} requires explicit boolean flags`);
    if (rule.requires_host && allowedHosts.length === 0) throw new Error(`policy action ${action} requires a host but has no allowlist`);
    if (!rule.requires_host && allowedHosts.length > 0) throw new Error(`policy action ${action} cannot declare hosts without egress`);
    actions[action] = {
      purpose,
      allowed_fields: allowedFields,
      allowed_hosts: allowedHosts,
      allowed_private_refs: allowedPrivateRefs,
      requires_host: rule.requires_host,
      requires_human_authorization: rule.requires_human_authorization,
    };
  }

  const document: OperationalPolicyDocument = { version, actions };
  const canonicalJson = JSON.stringify(document);
  const hash = createHash('sha256').update(canonicalJson).digest('hex');
  return { document, canonicalJson, hash };
}
