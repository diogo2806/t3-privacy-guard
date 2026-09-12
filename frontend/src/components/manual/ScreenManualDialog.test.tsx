import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { ScreenManualDialog } from './ScreenManualDialog';

describe('ScreenManualDialog', () => {
  it('opens, closes and restores focus to the Screen Manual trigger', async () => {
    const user = userEvent.setup();
    render(<ScreenManualDialog />);

    const trigger = screen.getByRole('button', { name: 'Open Screen Manual' });
    expect(trigger).toHaveAttribute('title', 'Manual da Tela / Screen Manual');

    await user.click(trigger);
    expect(screen.getByRole('dialog', { name: 'Incident Response Dashboard' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Close Screen Manual' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    await new Promise((resolve) => requestAnimationFrame(resolve));
    expect(trigger).toHaveFocus();
  });
});
