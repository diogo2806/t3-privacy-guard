import { Bot, Cpu, ShieldCheck } from 'lucide-react';
import type { AgentAnalysis } from '../../services/privacyGuardApi';
import { InlineNotice } from '../ui/InlineNotice';
import { SectionHeader } from '../ui/SectionHeader';
import { Surface } from '../ui/Surface';

const privateRefLabel: Record<string, string> = {
  verified_email: 'Verified email',
};

export function AgentProposalPanel({ analysis }: { analysis: AgentAnalysis | null }) {
  if (!analysis) return null;
  const proposal = analysis.action;
  const hasPrivateRefs = proposal.privateRefs.length > 0;
  return (
    <Surface className="agent-proposal-card" aria-labelledby="agent-proposal-title">
      <SectionHeader eyebrow="Model output, not authority" title="Latest agent proposal" titleId="agent-proposal-title" icon={<Bot aria-hidden="true" />} />
      <div className="agent-provider-meta"><Cpu aria-hidden="true" /><span>{analysis.provider} · {analysis.model}</span></div>
      <dl className="detail-grid">
        <div><dt>Action</dt><dd>{proposal.action}</dd></div>
        <div><dt>Resource</dt><dd>{proposal.resource}</dd></div>
        <div><dt>Purpose</dt><dd>{proposal.purpose}</dd></div>
        <div><dt>Host</dt><dd>{proposal.host || 'No egress'}</dd></div>
      </dl>
      <div className="field-list"><span>Requested fields</span>{proposal.fields.map((field) => <code key={field}>{field}</code>)}</div>
      {hasPrivateRefs && (
        <div className="private-reference-panel" aria-label="Privacy-preserving private data references">
          <div className="private-reference-heading"><ShieldCheck aria-hidden="true" /><strong>Privacy-preserving action</strong></div>
          <div className="field-list"><span>Required private data</span>{proposal.privateRefs.map((ref) => <code key={ref}>{privateRefLabel[ref] ?? ref}</code>)}</div>
          <dl className="privacy-boundary-grid">
            <div><dt>Plaintext visible to agent</dt><dd>NO</dd></div>
            <div><dt>Plaintext visible to Java</dt><dd>NO</dd></div>
            <div><dt>Resolved by T3N at egress</dt><dd>YES, when protected execution runs</dd></div>
          </dl>
          <p className="card-copy">The agent received a logical reference, not the private value. The application never renders the resolved plaintext.</p>
        </div>
      )}
      <InlineNotice className="agent-authority-note">This card shows the most recent provider response. Persisted action and audit history distinguish each proposal in the incident. The model proposes field names only; it cannot supply the operational values that are executed. Synthetic normal values are created and persisted by the trusted backend, while T3N decides which of those values may reach protected egress.</InlineNotice>
    </Surface>
  );
}
