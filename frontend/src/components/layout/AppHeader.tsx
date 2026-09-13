import { ShieldCheck } from 'lucide-react';
import { ScreenManualDialog } from '../manual/ScreenManualDialog';

export function AppHeader() {
  return (
    <header className="app-header">
      <div className="brand-lockup">
        <span className="brand-icon" aria-hidden="true"><ShieldCheck /></span>
        <div>
          <p className="eyebrow">Terminal 3 Network</p>
          <h1>T3 Privacy Guard</h1>
          <p className="header-subtitle">AI proposes actions. T3N policy controls what may execute.</p>
          <p className="header-supporting-copy">Critical actions still require human authorization and independent verification.</p>
        </div>
      </div>
      <ScreenManualDialog />
    </header>
  );
}
