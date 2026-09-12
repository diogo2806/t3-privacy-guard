import { Bot, Cpu, ShieldCheck } from 'lucide-react';
import type { AgentAnalysis } from '../../services/privacyGuardApi';

const privateRefLabel: Record<string, string> = {
  verified_email: 'Verified email',
};

export function AgentProposalPanel({ analysis }: { analysis: AgentAnalysis | null }) {
  if (!analysis) return null;
  const proposal = analysis.action;
  const hasPrivateRefs = proposal.privateRefs.length > 0;
  return (
    <section className="card agent-proposal-card" aria-labelledby="agent-proposal-title">
      <div className="card-heading compact">
        <div className="section-icon"><Bot aria-hidden="true" /></div>
        <div><p className="eyebrow">Model output, not authority</p><h2 id="agent-proposal-title">Agent proposal</h2></div>
      </div>
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
      <p className="inline-notice agent-authority-note">This proposal cannot set a decision, DID, capability, placeholder literal or secret. The T3N TEE decision shown below is authoritative.</p>
    </section>
  );
}
