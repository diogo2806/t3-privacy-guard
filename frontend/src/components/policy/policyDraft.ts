import type { PolicyActionRule, PolicyDocument } from '../../services/privacyGuardApi';

export const VERIFIED_EMAIL = 'verified_email';

/** Editable form of one action rule: lists are free text, one value per line or comma. */
export interface DraftAction {
  key: string;
  name: string;
  purpose: string;
  fields: string;
  hosts: string;
  verifiedEmail: boolean;
  requiresHost: boolean;
  requiresHumanAuthorization: boolean;
}

export interface PolicyDraft { version: string; actions: DraftAction[]; }

export type PolicyChangeKind = 'added' | 'removed' | 'changed';

export interface PolicyActionDiff { action: string; kind: PolicyChangeKind; details: string[]; }

let draftKey = 0;
function nextKey(): string {
  draftKey += 1;
  return `draft-action-${draftKey}`;
}

export function splitList(value: string): string[] {
  return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
}

export function toDraft(document: PolicyDocument, version = suggestNextVersion(document.version)): PolicyDraft {
  return {
    version,
    actions: Object.entries(document.actions).map(([name, rule]) => ({
      key: nextKey(),
      name,
      purpose: rule.purpose,
      fields: rule.allowed_fields.join(', '),
      hosts: rule.allowed_hosts.join(', '),
      verifiedEmail: rule.allowed_private_refs.includes(VERIFIED_EMAIL),
      requiresHost: rule.requires_host,
      requiresHumanAuthorization: rule.requires_human_authorization,
    })),
  };
}

export function emptyDraftAction(): DraftAction {
  return { key: nextKey(), name: '', purpose: '', fields: '', hosts: '', verifiedEmail: false, requiresHost: false, requiresHumanAuthorization: true };
}

/** guard-runtime normalizes and sorts on its side; this only shapes the document it validates. */
export function fromDraft(draft: PolicyDraft): PolicyDocument {
  const actions: Record<string, PolicyActionRule> = {};
  for (const action of draft.actions) {
    actions[action.name.trim()] = {
      purpose: action.purpose.trim(),
      allowed_fields: splitList(action.fields),
      allowed_hosts: action.requiresHost ? splitList(action.hosts) : [],
      allowed_private_refs: action.verifiedEmail ? [VERIFIED_EMAIL] : [],
      requires_host: action.requiresHost,
      requires_human_authorization: action.requiresHumanAuthorization,
    };
  }
  return { version: draft.version.trim(), actions };
}

/** Problems the form can catch before asking guard-runtime, which remains the authority on validity. */
export function draftProblems(draft: PolicyDraft): string[] {
  const problems: string[] = [];
  if (!draft.version.trim()) problems.push('Give the new version a name.');
  const names = draft.actions.map((action) => action.name.trim());
  if (names.some((name) => !name)) problems.push('Every action needs a name.');
  if (new Set(names).size !== names.length) problems.push('Action names must be unique.');
  if (draft.actions.length === 0) problems.push('The policy needs at least one action.');
  return problems;
}

function listChanges(label: string, before: string[], after: string[]): string[] {
  const added = after.filter((value) => !before.includes(value));
  const removed = before.filter((value) => !after.includes(value));
  const details: string[] = [];
  if (added.length) details.push(`${label} added: ${added.join(', ')}`);
  if (removed.length) details.push(`${label} removed: ${removed.join(', ')}`);
  return details;
}

function normalizedList(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean))].sort();
}

export function diffPolicies(current: PolicyDocument, candidate: PolicyDocument): PolicyActionDiff[] {
  const names = [...new Set([...Object.keys(current.actions), ...Object.keys(candidate.actions)])].sort();
  const diffs: PolicyActionDiff[] = [];
  for (const name of names) {
    const before = current.actions[name];
    const after = candidate.actions[name];
    if (!before && after) { diffs.push({ action: name, kind: 'added', details: [] }); continue; }
    if (before && !after) { diffs.push({ action: name, kind: 'removed', details: [] }); continue; }
    if (!before || !after) continue;
    const details = [
      ...(before.purpose.trim().toLowerCase() !== after.purpose.trim().toLowerCase() ? [`purpose: ${before.purpose} → ${after.purpose}`] : []),
      ...listChanges('fields', normalizedList(before.allowed_fields), normalizedList(after.allowed_fields)),
      ...listChanges('hosts', normalizedList(before.allowed_hosts), normalizedList(after.allowed_hosts)),
      ...listChanges('private references', normalizedList(before.allowed_private_refs), normalizedList(after.allowed_private_refs)),
      ...(before.requires_host !== after.requires_host ? [`destination host ${after.requires_host ? 'now required' : 'no longer required'}`] : []),
      ...(before.requires_human_authorization !== after.requires_human_authorization
        ? [`human authorization ${after.requires_human_authorization ? 'now required' : 'no longer required'}`] : []),
    ];
    if (details.length) diffs.push({ action: name, kind: 'changed', details });
  }
  return diffs;
}

/** "local-2026-10-28.1" → "local-2026-10-28.2"; a version without a trailing number gets ".2". */
export function suggestNextVersion(version: string): string {
  const match = /^(.*?)(\d+)$/.exec(version);
  if (!match) return `${version}.2`;
  return `${match[1]}${Number(match[2]) + 1}`;
}
