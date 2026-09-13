import { AlertTriangle, KeyRound, ShieldCheck, ShieldQuestion, Trash2 } from 'lucide-react';
import type { AuditIntegrity, AuditIntegrityState } from '../../services/privacyGuardApi';

const COPY: Record<AuditIntegrityState, { label: string; guidance: string; className: string }> = {
  VERIFIED: {
    label: 'Integrity verified',
    guidance: 'The retained local events passed HMAC, sequence, link and authenticated chain-head verification.',
    className: '',
  },
  BROKEN: {
    label: 'Integrity broken',
    guidance: 'The local audit may have been modified or become incomplete. Protected changes are blocked until this is investigated.',
    className: 'audit-provenance-note-error',
  },
  KEY_MISMATCH: {
    label: 'Verification key unavailable',
    guidance: 'A key version required to verify retained audit history is unavailable or no longer matches the authenticated chain.',
    className: 'audit-provenance-note-warning',
  },
  LEGACY_UNVERIFIED: {
    label: 'Legacy events unverified',
    guidance: 'Older events predate HMAC protection. They are preserved as legacy history and are not presented as cryptographically verified.',
    className: 'audit-provenance-note-warning',
  },
  PURGED: {
    label: 'Removed by retention',
    guidance: 'Audit content was removed by the incident retention policy and is not presented as verified.',
    className: '',
  },
  NOT_AVAILABLE: {
    label: 'Integrity not available',
    guidance: 'No retained local audit proof is available for verification.',
    className: 'audit-provenance-note-warning',
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
  const role = integrity.state === 'BROKEN' || integrity.state === 'KEY_MISMATCH' ? 'alert' : 'status';
  return (
    <div className={`audit-provenance-note ${copy.className}`.trim()} role={role} aria-label={`Local audit integrity: ${copy.label}`}>
      <div className="audit-source-heading">
        <StateIcon state={integrity.state} />
        <div>
          <h3>Local audit integrity · {copy.label}</h3>
          <p>{copy.guidance}</p>
        </div>
      </div>
      <small>Checked events: {integrity.eventsChecked} · Integrity version: {integrity.version ?? 'not available'}</small>
    </div>
  );
}
