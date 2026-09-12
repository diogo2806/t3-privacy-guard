import { FormEvent, useState } from 'react';
import { LogIn, LogOut, UserRoundCheck } from 'lucide-react';
import type { OperatorSession } from '../../services/privacyGuardApi';

interface Props {
  session: OperatorSession | null;
  loading: boolean;
  busy: boolean;
  error: string | null;
  onLogin: (credentials: { username: string; password: string }) => Promise<void>;
  onLogout: () => Promise<void>;
}

export function OperatorSessionGate({ session, loading, busy, error, onLogin, onLogout }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    await onLogin({ username, password });
    setPassword('');
  };

  if (loading) {
    return <section className="auth-panel" aria-live="polite">Checking operator session…</section>;
  }

  if (session?.authenticated) {
    return (
      <section className="operator-session-bar" aria-label="Operator session">
        <div className="operator-session-identity">
          <UserRoundCheck aria-hidden="true" />
          <div><span>Operator session</span><strong>{session.username ?? 'authenticated'}</strong></div>
        </div>
        <button type="button" className="button button-ghost" onClick={() => void onLogout()} disabled={busy}>
          <LogOut aria-hidden="true" />Sign out
        </button>
      </section>
    );
  }

  return (
    <section className="auth-panel" aria-labelledby="operator-login-title">
      <div>
        <p className="eyebrow">Application access</p>
        <h2 id="operator-login-title">Operator sign in</h2>
        <p className="auth-help">Use the application operator credentials. T3N tenant and agent credentials are never used for this login.</p>
      </div>
      <form className="auth-form" onSubmit={(event) => void submit(event)}>
        <label>Username<input name="username" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required disabled={busy} /></label>
        <label>Password<input name="password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required disabled={busy} /></label>
        {error && <div className="feedback feedback-error" role="alert">{error}</div>}
        <button type="submit" className="button button-primary" disabled={busy || !username.trim() || !password}>
          <LogIn aria-hidden="true" />{busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </section>
  );
}
