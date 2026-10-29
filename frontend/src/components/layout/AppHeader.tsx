import { PrivacyGuardMark } from '../brand/PrivacyGuardMark';
import { ScreenManualDialog } from '../manual/ScreenManualDialog';

export function AppHeader() {
  return (
    <header className="app-header">
      <div className="brand-lockup">
        <PrivacyGuardMark />
        <div>
          <p className="eyebrow">Self-hosted guard runtime</p>
          <h1>Privacy Guard</h1>
          <p className="header-subtitle"><strong>Keep authority outside the model.</strong></p>
          <p className="header-supporting-copy">AI proposes. Policy decides. Humans authorize. Independent verification proves completion.</p>
        </div>
      </div>
      <ScreenManualDialog />
    </header>
  );
}
