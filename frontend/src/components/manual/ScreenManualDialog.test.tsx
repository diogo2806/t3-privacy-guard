import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { ScreenManualDialog } from './ScreenManualDialog';

describe('ScreenManualDialog', () => {
  it('traps focus and explains fixed effective authorization, A2A, privacy and evidence provenance', async () => {
    const user = userEvent.setup();
    render(<div><button type="button">Outside action</button><ScreenManualDialog /></div>);

    const trigger = screen.getByRole('button', { name: 'Open Screen Manual' });
    expect(trigger).toHaveAttribute('title', 'Manual da Tela / Screen Manual');
    expect(trigger).toHaveTextContent('Manual da Tela');
    await user.click(trigger);

    const dialog = screen.getByRole('dialog', { name: 'Incident Response Dashboard' });
    const closeButton = screen.getByRole('button', { name: 'Close Screen Manual' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByText('Identidade, Member grant e autorização efetiva')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/checkDelegation.*cliente autenticado do próprio principal/i);
    expect(dialog).toHaveTextContent(/evaluate-action.*execute-remediation.*verify-remediation/i);
    expect(dialog).toHaveTextContent(/Confirmed.*Denied.*Unknown/i);
    expect(screen.getByText('Readiness')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Proposal evaluation.*Protected remediation/i);
    expect(screen.getByText('Agent Card e A2A público')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/A2A.*avaliação pública/i);
    expect(dialog).toHaveTextContent(/PII-free/i);
    expect(screen.getByText('Proof & evidence')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Source commit.*Source tree/i);
    expect(dialog).toHaveTextContent(/COMPLETED/i);
    expect(closeButton).toHaveFocus();

    await user.tab();
    expect(closeButton).toHaveFocus();
    screen.getByRole('button', { name: 'Outside action' }).focus();
    expect(closeButton).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    expect(trigger).toHaveFocus();
  });

  it('closes from the backdrop, restores focus and can be reopened without duplicate handlers', async () => {
    const user = userEvent.setup();
    render(<ScreenManualDialog />);
    const trigger = screen.getByRole('button', { name: 'Open Screen Manual' });
    await user.click(trigger);
    const backdrop = screen.getByRole('presentation');
    await user.pointer([{ target: backdrop, keys: '[MouseLeft>]' }, { keys: '[/MouseLeft]' }]);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    expect(trigger).toHaveFocus();
    await user.click(trigger);
    expect(screen.getByRole('button', { name: 'Close Screen Manual' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
