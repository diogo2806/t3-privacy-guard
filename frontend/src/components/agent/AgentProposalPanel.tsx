import { Bot, Cpu } from 'lucide-react';
import type { AgentAnalysis } from '../../services/privacyGuardApi';

export function AgentProposalPanel({ analysis }: { analysis: AgentAnalysis | null }) {
  if (!analysis) return null;
  const proposal = analysis.action;
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
      <p className="inline-notice agent-authority-note">This proposal cannot set a decision, DID, capability or secret. The T3N TEE decision shown below is authoritative.</p>
    </section>
  );
}
