import { describe, expect, it } from 'vitest';
import type { PolicyDocument } from '../../services/privacyGuardApi';
import { diffPolicies, draftProblems, emptyDraftAction, fromDraft, splitList, suggestNextVersion, toDraft } from './policyDraft';

const POLICY: PolicyDocument = {
  version: 'local-2026-10-28.1',
  actions: {
    'notify-security': {
      purpose: 'incident-notification', allowed_fields: ['incident_id', 'severity'], allowed_hosts: ['app'],
      allowed_private_refs: ['verified_email'], requires_host: true, requires_human_authorization: true,
    },
    'create-incident': {
      purpose: 'incident-recording', allowed_fields: ['incident_id'], allowed_hosts: [], allowed_private_refs: [],
      requires_host: false, requires_human_authorization: false,
    },
  },
};

describe('policyDraft', () => {
  it('round-trips a policy through the editable draft with the next version suggested', () => {
    const draft = toDraft(POLICY);

    expect(draft.version).toBe('local-2026-10-28.2');
    expect(fromDraft({ ...draft, version: POLICY.version })).toEqual(POLICY);
  });

  it('splits lists on commas and new lines and drops hosts when no destination is used', () => {
    expect(splitList(' incident_id,\nseverity , ,summary ')).toEqual(['incident_id', 'severity', 'summary']);
    const draft = toDraft(POLICY);
    draft.actions[0] = { ...draft.actions[0], requiresHost: false };

    expect(fromDraft(draft).actions['notify-security'].allowed_hosts).toEqual([]);
  });

  it('describes field, host, reference and flag changes per action', () => {
    const draft = toDraft(POLICY);
    draft.actions[0] = { ...draft.actions[0], fields: 'incident_id, summary', hosts: 'app, security.example', verifiedEmail: false, requiresHumanAuthorization: false };
    draft.actions = draft.actions.filter((action) => action.name !== 'create-incident');
    draft.actions.push({ ...emptyDraftAction(), name: 'isolate-account', purpose: 'incident-remediation' });

    expect(diffPolicies(POLICY, fromDraft(draft))).toEqual([
      { action: 'create-incident', kind: 'removed', details: [] },
      { action: 'isolate-account', kind: 'added', details: [] },
      {
        action: 'notify-security',
        kind: 'changed',
        details: [
          'fields added: summary',
          'fields removed: severity',
          'hosts added: security.example',
          'private references removed: verified_email',
          'human authorization no longer required',
        ],
      },
    ]);
  });

  it('ignores case and order differences that guard-runtime normalizes away', () => {
    const draft = toDraft(POLICY);
    draft.actions[0] = { ...draft.actions[0], fields: 'SEVERITY, incident_id' };

    expect(diffPolicies(POLICY, fromDraft(draft))).toEqual([]);
  });

  it('flags drafts the runtime would reject for obvious reasons', () => {
    const draft = toDraft(POLICY);
    expect(draftProblems(draft)).toEqual([]);
    expect(draftProblems({ version: ' ', actions: [] })).toEqual(['Give the new version a name.', 'The policy needs at least one action.']);
    expect(draftProblems({ ...draft, actions: [...draft.actions, { ...draft.actions[0], key: 'copy' }] })).toContain('Action names must be unique.');
  });

  it('suggests the next version from a trailing number', () => {
    expect(suggestNextVersion('local-2026-10-28.1')).toBe('local-2026-10-28.2');
    expect(suggestNextVersion('v9')).toBe('v10');
    expect(suggestNextVersion('release')).toBe('release.2');
  });
});
