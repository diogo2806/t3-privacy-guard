import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { DashboardTabs } from './DashboardTabs';

describe('DashboardTabs', () => {
  it('uses native buttons that receive keyboard focus in product order', async () => {
    const user = userEvent.setup();
    render(<DashboardTabs active="demo" onChange={vi.fn()} />);

    await user.tab();
    expect(screen.getByRole('button', { name: 'Protection flow' })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Evidence' })).toHaveFocus();
  });

  it('marks the active area and emits the selected view', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<DashboardTabs active="demo" onChange={onChange} />);

    expect(screen.getByRole('button', { name: 'Protection flow' })).toHaveAttribute('aria-current', 'page');
    await user.click(screen.getByRole('button', { name: 'Evidence' }));
    expect(onChange).toHaveBeenCalledWith('evidence');
  });
});
