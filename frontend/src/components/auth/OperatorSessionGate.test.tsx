import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { OperatorSessionGate } from './OperatorSessionGate';

describe('OperatorSessionGate', () => {
  it('keeps T3N credentials out of the operator login copy and clears the password after submit', async () => {
    const user = userEvent.setup();
    const onLogin = vi.fn(async () => undefined);
    render(
      <OperatorSessionGate
        session={{ authenticated: false }}
        loading={false}
        busy={false}
        error={null}
        onLogin={onLogin}
        onLogout={vi.fn(async () => undefined)}
      />,
    );

    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    await user.type(username, 'operator');
    await user.type(password, 'secret-value');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(onLogin).toHaveBeenCalledWith({ username: 'operator', password: 'secret-value' });
    expect(password).toHaveValue('');
    expect(screen.getByText(/T3N tenant and agent credentials are never used/i)).toBeInTheDocument();
  });

  it('shows a signed-in operator and exposes sign out', () => {
    render(
      <OperatorSessionGate
        session={{ authenticated: true, username: 'operator' }}
        loading={false}
        busy={false}
        error={null}
        onLogin={vi.fn(async () => undefined)}
        onLogout={vi.fn(async () => undefined)}
      />,
    );

    expect(screen.getByText('operator')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
  });

  it('announces the backend cooldown and disables only sign-in submission', () => {
    render(
      <OperatorSessionGate
        session={{ authenticated: false }}
        loading={false}
        busy={false}
        error={null}
        retryAfterSeconds={30}
        onLogin={vi.fn(async () => undefined)}
        onLogout={vi.fn(async () => undefined)}
      />,
    );

    expect(screen.getByRole('alert')).toHaveTextContent('Too many failed attempts. Try again in 30 seconds.');
    expect(screen.getByRole('button', { name: 'Try again in 30s' })).toBeDisabled();
    expect(screen.getByLabelText('Username')).not.toBeDisabled();
    expect(screen.getByLabelText('Password')).not.toBeDisabled();
  });
});
