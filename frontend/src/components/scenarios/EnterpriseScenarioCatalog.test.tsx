import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { EnterpriseScenarioCatalog } from './EnterpriseScenarioCatalog';

describe('EnterpriseScenarioCatalog', () => {
  it('renders the four task-oriented scenarios and identifies their execution boundary', () => {
    render(<EnterpriseScenarioCatalog selectedScenarioId="credential-compromised" busy={false} onSelect={vi.fn()} />);

    expect(screen.getByRole('button', { name: /Credential compromised/i })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: /Account takeover/i })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: /Record security incident/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Notify security contact/i })).toBeInTheDocument();
    expect(screen.getByText(/These are demonstration presets, not permissions/i)).toBeInTheDocument();
    expect(screen.getAllByText('Policy evaluation only')).toHaveLength(3);
    expect(screen.getByText('Protected execution implemented')).toBeInTheDocument();
  });

  it('selects a preset without running analysis automatically', async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<EnterpriseScenarioCatalog selectedScenarioId="credential-compromised" busy={false} onSelect={onSelect} />);

    await user.click(screen.getByRole('button', { name: /Account takeover/i }));

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith('account-takeover');
  });

  it('prevents scenario changes while another operation is busy', () => {
    render(<EnterpriseScenarioCatalog selectedScenarioId="credential-compromised" busy onSelect={vi.fn()} />);

    expect(screen.getByRole('button', { name: /Credential compromised/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Account takeover/i })).toBeDisabled();
  });
});
