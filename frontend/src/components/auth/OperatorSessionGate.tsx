import { FormEvent, useEffect, useState } from 'react';
import { LogIn, LogOut, UserRoundCheck } from 'lucide-react';
import type { OperatorSession } from '../../services/privacyGuardApi';

interface Props {
  session: OperatorSession | null;
  loading: boolean;
  busy: boolean;
  error: string | null;
  retryAfterSeconds?: number;
  onLogin: (credentials: { username: string; password: string }) => Promise<void>;
  onLogout: () => Promise<void>;
}

export function OperatorSessionGate({ session, loading, busy, error, retryAfterSeconds = 0, onLogin, onLogout }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [cooldownSeconds, setCooldownSeconds] = useState(0);

  useEffect(() => {
    setCooldownSeconds(Math.max(0, Math.floor(retryAfterSeconds)));
  }, [retryAfterSeconds]);

  useEffect(() => {
    if (cooldownSeconds <= 0) return undefined;
    const timer = window.setTimeout(() => setCooldownSeconds((current) => Math.max(0, current - 1)), 1000);
    return () => window.clearTimeout(timer);
  }, [cooldownSeconds]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (cooldownSeconds > 0) return;
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

  const rateLimited = cooldownSeconds > 0;
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
        {rateLimited ? (
          <div className="feedback feedback-error" role="alert" aria-live="assertive">Too many failed attempts. Try again in {cooldownSeconds} {cooldownSeconds === 1 ? 'second' : 'seconds'}.</div>
        ) : error ? (
          <div className="feedback feedback-error" role="alert">{error}</div>
        ) : null}
        <button type="submit" className="button button-primary" disabled={busy || rateLimited || !username.trim() || !password}>
          <LogIn aria-hidden="true" />{busy ? 'Signing in…' : rateLimited ? `Try again in ${cooldownSeconds}s` : 'Sign in'}
        </button>
      </form>
    </section>
  );
}
