import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { ScreenManualDialog } from './ScreenManualDialog';

describe('ScreenManualDialog', () => {
  it('traps focus and distinguishes Member grant from effective T3N authorization', async () => {
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
    expect(screen.getByText(/Member grant.*não é apresentado como prova suficiente/i)).toBeInTheDocument();
    expect(screen.getByText(/checkDelegation\(\).*cliente autenticado do próprio principal/i)).toBeInTheDocument();
    expect(screen.getByText(/Confirmed.*authorised=true/i)).toBeInTheDocument();
    expect(screen.getByText(/Denied e Unknown sempre falham fechado/i)).toBeInTheDocument();
    expect(screen.getByText(/Proposal Agent e Protected Executor têm checks independentes/i)).toBeInTheDocument();
    expect(screen.getByText('Policy e decisão')).toBeInTheDocument();
    expect(screen.getByText('Dados privados e retenção')).toBeInTheDocument();
    expect(screen.getByText('Audit provenance e T3N Activity Log')).toBeInTheDocument();
    expect(screen.getByText('Proof & evidence')).toBeInTheDocument();
    expect(screen.getByText(/COMPLETED/i)).toBeInTheDocument();
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
