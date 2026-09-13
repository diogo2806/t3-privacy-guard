import { AlertTriangle, KeyRound, ShieldCheck, ShieldQuestion, Trash2 } from 'lucide-react';
import type { AuditIntegrity, AuditIntegrityState } from '../../services/privacyGuardApi';

const COPY: Record<AuditIntegrityState, { label: string; guidance: string; tone: string }> = {
  VERIFIED: {
    label: 'Integrity verified',
    guidance: 'The retained local events passed HMAC, sequence and chain-head verification.',
    tone: 'verified',
  },
  BROKEN: {
    label: 'Integrity broken',
    guidance: 'Audit history may have been modified or is incomplete. Do not use this local trail as proof until investigated.',
    tone: 'broken',
  },
  KEY_MISMATCH: {
    label: 'Integrity key unavailable',
    guidance: 'A required audit key version is unavailable or the stored key identifier was changed. Protected execution remains blocked.',
    tone: 'warning',
  },
  LEGACY_UNVERIFIED: {
    label: 'Legacy history unverified',
    guidance: 'Authenticated events are checked, but older retained events predate local HMAC protection and cannot be retroactively verified.',
    tone: 'warning',
  },
  PURGED: {
    label: 'Not available after retention purge',
    guidance: 'Audit content was removed by the retention policy. Purged events are not presented as verified.',
    tone: 'neutral',
  },
  NOT_AVAILABLE: {
    label: 'Integrity not available',
    guidance: 'There is no retained local audit proof available for verification.',
    tone: 'neutral',
  },
};

function StateIcon({ state }: { state: AuditIntegrityState }) {
  if (state === 'VERIFIED') return <ShieldCheck aria-hidden="true" />;
  if (state === 'BROKEN') return <AlertTriangle aria-hidden="true" />;
  if (state === 'KEY_MISMATCH') return <KeyRound aria-hidden="true" />;
  if (state === 'PURGED') return <Trash2 aria-hidden="true" />;
  return <ShieldQuestion aria-hidden="true" />;
}

export function AuditIntegrityStatus({ integrity }: { integrity: AuditIntegrity }) {
  const copy = COPY[integrity.state];
  return (
    <div className={`audit-integrity audit-integrity-${copy.tone}`} role={integrity.state === 'BROKEN' || integrity.state === 'KEY_MISMATCH' ? 'alert' : 'status'}>
      <div className="audit-integrity-icon"><StateIcon state={integrity.state} /></div>
      <div className="audit-integrity-content">
        <div className="audit-integrity-heading">
          <span>Local audit integrity</span>
          <strong>{copy.label}</strong>
        </div>
        <p>{copy.guidance}</p>
        <p className="audit-integrity-meta">Checked events: {integrity.eventsChecked} · Integrity version: {integrity.version ?? 'not available'}</p>
      </div>
    </div>
  );
}
