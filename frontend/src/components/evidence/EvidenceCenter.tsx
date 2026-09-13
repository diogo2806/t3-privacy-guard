import { CircleDashed, FileCheck2, RefreshCw, ShieldCheck, ShieldX } from 'lucide-react';
import type { AgentRegistrationState, EvidenceBundle, EvidenceScenario } from '../../services/privacyGuardApi';

interface Props { evidence: EvidenceBundle | null; loading: boolean; error: string | null; onRefresh: () => void; }

function ScenarioIcon({ scenario }: { scenario: EvidenceScenario }) {
  if (scenario.status === 'PASS') return <ShieldCheck aria-hidden="true" />;
  if (scenario.status === 'FAIL') return <ShieldX aria-hidden="true" />;
  return <CircleDashed aria-hidden="true" />;
}

function registrationLabel(state: AgentRegistrationState): string {
  if (state === 'REGISTERED') return 'REGISTERED';
  if (state === 'NOT_REGISTERED') return 'NOT REGISTERED';
  if (state === 'MISMATCH') return 'CARD/DID MISMATCH';
  return 'UNAVAILABLE';
}

function EvidenceMeaning() {
  return (
    <section className="card evidence-meaning" aria-labelledby="evidence-meaning-title">
      <div className="card-heading compact"><span className="section-icon"><FileCheck2 aria-hidden="true" /></span><div><p className="eyebrow">What this proves</p><h2 id="evidence-meaning-title">Observed security outcomes on T3N testnet</h2></div></div>
      <p>This evidence bundle shows which security outcomes were actually observed on T3N testnet. <strong>PASS</strong> is observed proof, <strong>FAIL</strong> is an observed mismatch, and <strong>NOT RUN</strong> is not counted as proof.</p>
    </section>
  );
}

export function EvidenceCenter({ evidence, loading, error, onRefresh }: Props) {
  if (loading) return <div className="evidence-layout"><EvidenceMeaning /><section className="card evidence-empty" aria-live="polite">Loading evidence…</section></div>;
  if (error || !evidence) {
    return (
      <div className="evidence-layout">
        <EvidenceMeaning />
        <section className="card evidence-empty" aria-label="Evidence status">
          <FileCheck2 aria-hidden="true" />
          <h2>Proof &amp; evidence</h2>
          <p>{error ?? 'No live T3N evidence has been generated yet.'}</p>
          <button className="button button-secondary" type="button" onClick={onRefresh}><RefreshCw aria-hidden="true" />Refresh evidence</button>
        </section>
      </div>
    );
  }

  const trustAnchorState = evidence.metadata.trustAnchorVerified ? 'VERIFIED' : 'NOT VERIFIED';
  const rollbackFloorState = evidence.metadata.trustManifestFloorPersisted ? 'PERSISTED' : 'NOT PERSISTED';
  const registrationOk = evidence.metadata.agentRegistrationState === 'REGISTERED';
  const sourceTreeState = evidence.metadata.sourceTreeClean ? 'CLEAN' : 'DIRTY';
  const a2aObserved = registrationOk && evidence.metadata.agentCardServices.includes('A2A');

  return (
    <section className="evidence-layout" aria-label="T3N testnet evidence">
      <EvidenceMeaning />

      <div className="card">
        <div className="card-heading compact"><span className="section-icon"><FileCheck2 aria-hidden="true" /></span><div><p className="eyebrow">Technical evidence metadata</p><h2>T3N testnet execution</h2></div></div>
        <dl className="evidence-metadata">
          <div><dt>Source</dt><dd>{evidence.metadata.source}</dd></div>
          <div><dt>Generated</dt><dd>{new Date(evidence.metadata.generatedAt).toLocaleString()}</dd></div>
          <div className="evidence-wide"><dt>Source commit</dt><dd><code>{evidence.metadata.sourceCommitSha}</code></dd></div>
          <div><dt>Source tree</dt><dd><span className={`status-pill ${evidence.metadata.sourceTreeClean ? 'status-pill-ok' : 'status-pill-off'}`}>{sourceTreeState}</span></dd></div>
          <div><dt>SDK</dt><dd>{evidence.metadata.sdkVersion}</dd></div>
          <div><dt>Network</dt><dd>{evidence.metadata.network}</dd></div>
          <div><dt>Trust anchor</dt><dd>{trustAnchorState}</dd></div>
          <div><dt>Rollback floor</dt><dd>{rollbackFloorState}</dd></div>
          <div><dt>Trust manifest version</dt><dd>{evidence.metadata.trustManifestVersion}</dd></div>
          <div><dt>Agent onboarding</dt><dd><span className={`status-pill ${registrationOk ? 'status-pill-ok' : 'status-pill-off'}`}>{registrationLabel(evidence.metadata.agentRegistrationState)}</span></dd></div>
          <div><dt>A2A service in resolved card</dt><dd><span className={`status-pill ${a2aObserved ? 'status-pill-ok' : 'status-pill-off'}`}>{a2aObserved ? 'OBSERVED' : 'NOT OBSERVED'}</span></dd></div>
          <div><dt>Card check</dt><dd>{new Date(evidence.metadata.agentCardVerifiedAt).toLocaleString()}</dd></div>
          <div><dt>Contract version</dt><dd>{evidence.metadata.contractVersion}</dd></div>
          <div><dt>Policy version</dt><dd>{evidence.metadata.policyVersion}</dd></div>
          <div className="evidence-wide"><dt>Agent Card URI</dt><dd><code>{evidence.metadata.agentCardUri ?? 'Not resolved'}</code></dd></div>
          <div className="evidence-wide"><dt>Agent Card SHA-256</dt><dd><code>{evidence.metadata.agentCardSha256 ?? 'Not available'}</code></dd></div>
          <div><dt>Agent Card services</dt><dd>{evidence.metadata.agentCardServices.length ? evidence.metadata.agentCardServices.join(', ') : 'None verified'}</dd></div>
          <div className="evidence-wide"><dt>Contract</dt><dd><code>{evidence.metadata.contractId}</code></dd></div>
          <div className="evidence-wide"><dt>Policy SHA-256</dt><dd><code>{evidence.metadata.policyHash}</code></dd></div>
          <div className="evidence-wide"><dt>WASM SHA-256</dt><dd><code>{evidence.metadata.wasmSha256}</code></dd></div>
          <div className="evidence-wide"><dt>Tenant DID</dt><dd><code>{evidence.metadata.tenantDid}</code></dd></div>
          <div className="evidence-wide"><dt>Proposal Agent DID</dt><dd><code>{evidence.metadata.agentDid}</code></dd></div>
          <div className="evidence-wide"><dt>Protected Executor DID</dt><dd><code>{evidence.metadata.executorDid}</code></dd></div>
        </dl>
        <p className="evidence-disclaimer">This identifies the public source revision used to generate this evidence bundle. WASM and policy hashes remain the executed artifact identities. CLEAN means the Git working tree was clean when evidence generation started; DIRTY is disclosed explicitly and is not treated as verified source.</p>
        <p className="evidence-disclaimer">Policy version/hash identify the canonical operational policy used by this evidence run. Trust anchor VERIFIED means the T3N signed manifest established the cluster trust boundary for these authenticated sessions. Rollback floor PERSISTED means the accepted manifest version was stored across gateway restarts. These are policy/trust provenance signals, not a claim of per-request hardware attestation.</p>
        <p className="evidence-disclaimer">The Proposal Agent DID is the policy-evaluation principal. The Protected Executor DID is a separate authenticated T3N principal used only for privileged execution and verification after human authorization. Agent registration remains discoverability evidence; delegated authority is proven separately.</p>
        <p className="evidence-disclaimer">A2A OBSERVED means the resolved T3N Agent Card advertised the A2A evaluation service during this evidence run. It does not by itself prove that the public endpoint was reachable or live-tested. Protected remediation is not exposed through A2A.</p>
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
