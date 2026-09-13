import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { ScreenManualDialog } from './ScreenManualDialog';

describe('ScreenManualDialog', () => {
  it('traps keyboard focus, explains the enterprise trust journey, closes with Escape and restores focus', async () => {
    const user = userEvent.setup();
    render(
      <div>
        <button type="button">Outside action</button>
        <ScreenManualDialog />
      </div>,
    );

    const trigger = screen.getByRole('button', { name: 'Open Screen Manual' });
    expect(trigger).toHaveAttribute('title', 'Manual da Tela / Screen Manual');
    expect(trigger).toHaveTextContent('Manual da Tela');

    await user.click(trigger);
    const dialog = screen.getByRole('dialog', { name: 'Incident Response Dashboard' });
    const closeButton = screen.getByRole('button', { name: 'Close Screen Manual' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByText('What this screen is for')).toBeInTheDocument();
    expect(screen.getByText('Enterprise scenarios')).toBeInTheDocument();
    expect(screen.getByText(/Credential compromised/i)).toBeInTheDocument();
    expect(screen.getByText(/Account takeover/i)).toBeInTheDocument();
    expect(screen.getByText(/Record security incident/i)).toBeInTheDocument();
    expect(screen.getByText(/Notify security contact/i)).toBeInTheDocument();
    expect(screen.getByText(/verified_email/i)).toBeInTheDocument();
    expect(screen.getByText(/ALLOW does not mean executed/i)).toBeInTheDocument();
    expect(screen.getByText(/COMPLETED appears only after independent read-back/i)).toBeInTheDocument();
    expect(screen.getByText(/Protection demo/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Proof & evidence/i).length).toBeGreaterThan(0);
    expect(closeButton).toHaveFocus();

    await user.tab();
    expect(closeButton).toHaveFocus();

    await user.tab({ shift: true });
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
