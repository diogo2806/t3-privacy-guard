import { FileCheck2, RefreshCw, ShieldCheck, ShieldX, CircleDashed } from 'lucide-react';
import type { EvidenceBundle, EvidenceScenario } from '../../services/privacyGuardApi';

interface Props { evidence: EvidenceBundle | null; loading: boolean; error: string | null; onRefresh: () => void; }

function ScenarioIcon({ scenario }: { scenario: EvidenceScenario }) {
  if (scenario.status === 'PASS') return <ShieldCheck aria-hidden="true" />;
  if (scenario.status === 'FAIL') return <ShieldX aria-hidden="true" />;
  return <CircleDashed aria-hidden="true" />;
}

export function EvidenceCenter({ evidence, loading, error, onRefresh }: Props) {
  if (loading) return <section className="card evidence-empty" aria-live="polite">Loading evidence…</section>;
  if (error || !evidence) {
    return (
      <section className="card evidence-empty" aria-label="Evidence status">
        <FileCheck2 aria-hidden="true" />
        <h2>Evidence</h2>
        <p>{error ?? 'No live T3N evidence has been generated yet.'}</p>
        <button className="button button-secondary" type="button" onClick={onRefresh}><RefreshCw aria-hidden="true" />Refresh evidence</button>
      </section>
    );
  }

  return (
    <section className="evidence-layout" aria-label="T3N testnet evidence">
      <div className="card">
        <div className="card-heading compact"><span className="section-icon"><FileCheck2 aria-hidden="true" /></span><div><p className="eyebrow">Evidence summary</p><h2>T3N testnet execution</h2></div></div>
        <dl className="evidence-metadata">
          <div><dt>Source</dt><dd>{evidence.metadata.source}</dd></div>
          <div><dt>Generated</dt><dd>{new Date(evidence.metadata.generatedAt).toLocaleString()}</dd></div>
          <div><dt>SDK</dt><dd>{evidence.metadata.sdkVersion}</dd></div>
          <div><dt>Network</dt><dd>{evidence.metadata.network}</dd></div>
          <div><dt>Contract</dt><dd><code>{evidence.metadata.contractId}</code></dd></div>
          <div><dt>Version</dt><dd>{evidence.metadata.contractVersion}</dd></div>
          <div className="evidence-wide"><dt>WASM SHA-256</dt><dd><code>{evidence.metadata.wasmSha256}</code></dd></div>
          <div className="evidence-wide"><dt>Tenant DID</dt><dd><code>{evidence.metadata.tenantDid}</code></dd></div>
          <div className="evidence-wide"><dt>Agent DID</dt><dd><code>{evidence.metadata.agentDid}</code></dd></div>
        </dl>
      </div>

      <div className="card">
        <div className="evidence-toolbar">
          <div><p className="eyebrow">Security scenarios</p><h2>Observed outcomes</h2></div>
          <button className="button button-ghost" type="button" onClick={onRefresh}><RefreshCw aria-hidden="true" />Refresh evidence</button>
        </div>
        <div className="evidence-totals" aria-label="Evidence totals">
          <span className="evidence-total evidence-pass">{evidence.totals.pass} PASS</span>
          <span className="evidence-total evidence-fail">{evidence.totals.fail} FAIL</span>
          <span className="evidence-total evidence-not-run">{evidence.totals.notRun} NOT RUN</span>
        </div>
        <ul className="evidence-list">
          {evidence.scenarios.map((scenario) => (
            <li key={scenario.id} className={`evidence-row evidence-row-${scenario.status.toLowerCase().replace('_', '-')}`}>
              <ScenarioIcon scenario={scenario} />
              <div><strong>{scenario.id}</strong><span>Expected: {scenario.expected}</span>{scenario.actual && <span>Observed: {scenario.actual}</span>}</div>
              <span className="evidence-status">{scenario.status.replace('_', ' ')}</span>
            </li>
          ))}
        </ul>
        <p className="evidence-disclaimer">PASS means the observed result matched the expected security outcome. NOT RUN means the scenario was not executed in this evidence bundle; it is never counted as PASS.</p>
      </div>
    </section>
  );
}
