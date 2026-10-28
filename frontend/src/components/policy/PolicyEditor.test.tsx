import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PrivacyGuardApiError, privacyGuardApi, type PolicyDocument, type PolicyHistoryEntry, type PolicyView } from '../../services/privacyGuardApi';
import { PolicyEditor } from './PolicyEditor';

const HASH = 'a'.repeat(64);
const DOCUMENT: PolicyDocument = {
  version: 'v1',
  actions: {
    'revoke-credential': {
      purpose: 'incident-remediation', allowed_fields: ['credential_id', 'incident_id', 'reason'], allowed_hosts: ['app'],
      allowed_private_refs: [], requires_host: true, requires_human_authorization: true,
    },
  },
};
const VIEW: PolicyView = { administrationConfigured: true, managed: true, state: 'AVAILABLE', version: 'v1', hash: HASH, document: DOCUMENT };
const HISTORY: PolicyHistoryEntry[] = [
  { sequence: 2, operation: 'publish', version: 'v1', hash: HASH, caller: 'agent:policy-admin', requestedBy: 'alice', timestamp: '2026-10-28T12:00:00Z' },
  { sequence: 1, operation: 'seed', version: 'v0', hash: 'b'.repeat(64), caller: 'seed-file', timestamp: '2026-10-28T11:00:00Z' },
];

function mockApi(view: PolicyView = VIEW, history: PolicyHistoryEntry[] = HISTORY) {
  vi.spyOn(privacyGuardApi, 'policy').mockResolvedValue(view);
  vi.spyOn(privacyGuardApi, 'policyHistory').mockResolvedValue(history);
}

describe('PolicyEditor', () => {
  afterEach(() => vi.restoreAllMocks());

  it('shows the active version and history read-only to auditors', async () => {
    mockApi();
    render(<PolicyEditor canEdit={false} onSessionExpired={vi.fn()} />);

    expect(await screen.findByText('Your role can read the policy. Publishing and rollback need the POLICY_ADMIN role.')).toBeInTheDocument();
    expect(screen.getByLabelText('Action name')).toBeDisabled();
    expect(screen.queryByRole('button', { name: /publish version/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /roll back/i })).not.toBeInTheDocument();
    expect(screen.getByText(/requested by alice/)).toBeInTheDocument();
  });

  it('explains how to enable editing when guard-runtime keeps policy as a file', async () => {
    mockApi({ ...VIEW, managed: false }, []);
    render(<PolicyEditor canEdit onSessionExpired={vi.fn()} />);

    expect(await screen.findByText(/Set GUARD_RUNTIME_POLICY_DIR/)).toBeInTheDocument();
    expect(privacyGuardApi.policyHistory).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /publish version/i })).not.toBeInTheDocument();
  });

  it('lets a policy admin review, validate and publish a change with the current hash', async () => {
    mockApi();
    const validate = vi.spyOn(privacyGuardApi, 'validatePolicy').mockResolvedValue({ valid: true, version: 'v2', hash: 'c'.repeat(64) });
    const publish = vi.spyOn(privacyGuardApi, 'publishPolicy').mockResolvedValue({ changed: true, version: 'v2', hash: 'c'.repeat(64), previousVersion: 'v1', previousHash: HASH });
    const user = userEvent.setup();
    render(<PolicyEditor canEdit onSessionExpired={vi.fn()} />);

    const publishButton = await screen.findByRole('button', { name: 'Publish version v2' });
    expect(publishButton).toBeDisabled();
    const fields = screen.getByLabelText('Allowed fields');
    await user.clear(fields);
    await user.type(fields, 'credential_id, incident_id');

    const review = screen.getByRole('heading', { name: 'Changes against version v1' }).parentElement as HTMLElement;
    expect(within(review).getByText('fields removed: reason')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Validate' }));
    expect(await screen.findByText(/guard-runtime accepts version v2/)).toBeInTheDocument();
    expect(validate.mock.calls[0]?.[0].actions['revoke-credential'].allowed_fields).toEqual(['credential_id', 'incident_id']);

    await user.click(publishButton);
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));
    expect(publish.mock.calls[0]?.[0].version).toBe('v2');
    expect(publish.mock.calls[0]?.[1]).toBe(HASH);
    expect(await screen.findByText('Version v2 is now the active policy.')).toBeInTheDocument();
  });

  it('shows the runtime reason when a change is refused', async () => {
    mockApi();
    vi.spyOn(privacyGuardApi, 'validatePolicy').mockResolvedValue({ valid: false, reason: 'policy attempts to allow a contract-forbidden secret field' });
    const user = userEvent.setup();
    render(<PolicyEditor canEdit onSessionExpired={vi.fn()} />);

    await user.type(await screen.findByLabelText('Allowed fields'), ', api_key');
    await user.click(screen.getByRole('button', { name: 'Validate' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('guard-runtime rejects this policy: policy attempts to allow a contract-forbidden secret field');
  });

  it('rolls back to an earlier version but not to the active one', async () => {
    mockApi();
    const rollback = vi.spyOn(privacyGuardApi, 'rollbackPolicy').mockResolvedValue({ changed: true, version: 'v0', hash: 'b'.repeat(64) });
    const user = userEvent.setup();
    render(<PolicyEditor canEdit onSessionExpired={vi.fn()} />);

    expect(await screen.findByRole('button', { name: 'Roll back to version v0' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Roll back to version v1' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Roll back to version v0' }));

    await waitFor(() => expect(rollback).toHaveBeenCalledWith('v0', HASH));
  });

  it('surfaces a concurrent change and hands an expired session back', async () => {
    mockApi();
    vi.spyOn(privacyGuardApi, 'publishPolicy').mockRejectedValue(new PrivacyGuardApiError('The policy changed since you opened it. Reload and apply your changes again.', 409));
    const user = userEvent.setup();
    render(<PolicyEditor canEdit onSessionExpired={vi.fn()} />);

    await user.type(await screen.findByLabelText('Allowed fields'), ', summary');
    await user.click(screen.getByRole('button', { name: 'Publish version v2' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The policy changed since you opened it.');

    vi.restoreAllMocks();
    vi.spyOn(privacyGuardApi, 'policy').mockRejectedValue(new PrivacyGuardApiError('expired', 401));
    const expired = vi.fn();
    render(<PolicyEditor canEdit onSessionExpired={expired} />);
    await waitFor(() => expect(expired).toHaveBeenCalled());
  });
});
