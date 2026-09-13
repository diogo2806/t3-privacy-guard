import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { ScreenManualDialog } from './ScreenManualDialog';

describe('ScreenManualDialog', () => {
  it('traps keyboard focus, closes with Escape and restores focus to the trigger', async () => {
    const user = userEvent.setup();
    render(
      <div>
        <button type="button">Outside action</button>
        <ScreenManualDialog />
      </div>,
    );

    const trigger = screen.getByRole('button', { name: 'Open Screen Manual' });
    expect(trigger).toHaveAttribute('title', 'Manual da Tela / Screen Manual');

    await user.click(trigger);
    const dialog = screen.getByRole('dialog', { name: 'Incident Response Dashboard' });
    const closeButton = screen.getByRole('button', { name: 'Close Screen Manual' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
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

  it('documents all enterprise scenarios, trust rollback protection and the real execution boundary', async () => {
    const user = userEvent.setup();
    render(<ScreenManualDialog />);

    await user.click(screen.getByRole('button', { name: 'Open Screen Manual' }));

    expect(screen.getByText(/Credential compromised/)).toBeInTheDocument();
    expect(screen.getByText(/Account takeover/)).toBeInTheDocument();
    expect(screen.getByText(/Record security incident/)).toBeInTheDocument();
    expect(screen.getByText(/Notify security contact/)).toBeInTheDocument();
    expect(screen.getByText(/verified_email/)).toBeInTheDocument();
    expect(screen.getByText(/only current scenario with protected execution/i)).toBeInTheDocument();
    expect(screen.getByText(/Policy evaluation only/i)).toBeInTheDocument();
    expect(screen.getByText(/Rollback floor PERSISTED/i)).toBeInTheDocument();
    expect(screen.getByText(/TRUST FLOOR CORRUPTED/i)).toBeInTheDocument();
  });
});
