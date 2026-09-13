import { CircleDashed, FileCheck2, RefreshCw, ShieldCheck, ShieldX } from 'lucide-react';
import type { AgentRegistrationState, EvidenceBundle, EvidenceScenario } from '../../services/privacyGuardApi';
import { Button } from '../ui/Button';
import { SectionHeader } from '../ui/SectionHeader';
import { Surface } from '../ui/Surface';

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

function scenarioLabel(id: string): string {
  const labels: Record<string, string> = {
    'LIVE-PROPOSAL-CANNOT-EXECUTE': 'Proposal agent blocked from protected execution',
    'LIVE-EXECUTOR-REQUIRES-HUMAN-PROOF': 'Executor credential alone blocked by the T3N human-proof boundary',
  };
  return labels[id] ?? id.replace(/^LIVE-/, '').replaceAll('-', ' ').replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());
}

function EvidenceMeaning() {
  return (
    <Surface className="evidence-meaning" aria-labelledby="evidence-meaning-title">
      <SectionHeader eyebrow="What this proves" title="Observed security outcomes on T3N testnet" titleId="evidence-meaning-title" icon={<FileCheck2 aria-hidden="true" />} />
      <p>This bundle reports observed outcomes only. <strong>PASS</strong> is observed proof, <strong>FAIL</strong> is an observed mismatch, and <strong>NOT RUN</strong> is not proof and is never counted as PASS.</p>
    </Surface>
  );
}

export function EvidenceCenter({ evidence, loading, error, onRefresh }: Props) {
  if (loading) return <div className="evidence-layout"><EvidenceMeaning /><Surface className="evidence-empty" aria-live="polite">Loading evidence…</Surface></div>;
  if (error || !evidence) {
    return (
      <div className="evidence-layout">
        <EvidenceMeaning />
        <Surface className="evidence-empty" aria-label="Evidence status">
          <FileCheck2 aria-hidden="true" />
          <h2>Evidence</h2>
          <p>{error ?? 'No live T3N evidence has been generated yet.'}</p>
          <Button variant="secondary" onClick={onRefresh}><RefreshCw aria-hidden="true" />Refresh evidence</Button>
        </Surface>
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

      <Surface className="evidence-summary" aria-labelledby="evidence-summary-title">
        <div className="evidence-toolbar">
          <div><p className="eyebrow">Evidence summary</p><h2 id="evidence-summary-title">Execution proof at a glance</h2></div>
          <Button variant="ghost" onClick={onRefresh}><RefreshCw aria-hidden="true" />Refresh evidence</Button>
        </div>
        <div className="evidence-summary-totals" aria-label="Evidence totals">
          <div className="evidence-summary-metric evidence-pass" data-testid="evidence-pass-total"><strong>{evidence.totals.pass}</strong><span>PASS</span></div>
          <div className="evidence-summary-metric evidence-fail" data-testid="evidence-fail-total"><strong>{evidence.totals.fail}</strong><span>FAIL</span></div>
          <div className="evidence-summary-metric evidence-not-run" data-testid="evidence-not-run-total"><strong>{evidence.totals.notRun}</strong><span>NOT RUN</span></div>
          <div className="evidence-summary-metric" data-testid="evidence-network"><strong>{evidence.metadata.network.toUpperCase()}</strong><span>Network</span></div>
        </div>
        <dl className="evidence-executive-facts">
          <div><dt>Source tree</dt><dd data-testid="evidence-source-tree"><span className={`status-pill ${evidence.metadata.sourceTreeClean ? 'status-pill-ok' : 'status-pill-off'}`}>{sourceTreeState}</span></dd></div>
          <div><dt>Trust anchor</dt><dd><span className={`status-pill ${evidence.metadata.trustAnchorVerified ? 'status-pill-ok' : 'status-pill-off'}`}>{trustAnchorState}</span></dd></div>
          <div><dt>Policy</dt><dd>{evidence.metadata.policyVersion}</dd></div>
          <div><dt>Generated</dt><dd data-testid="evidence-generated-at">{new Date(evidence.metadata.generatedAt).toLocaleString()}</dd></div>
        </dl>
      </Surface>

      <Surface aria-labelledby="observed-outcomes-title">
        <div className="evidence-toolbar">
          <div><p className="eyebrow">Security scenarios</p><h2 id="observed-outcomes-title">Observed outcomes</h2></div>
        </div>
        <ul className="evidence-list">
          {evidence.scenarios.map((scenario) => (
            <li key={scenario.id} className={`evidence-row evidence-row-${scenario.status.toLowerCase().replace('_', '-')}`} data-testid={`evidence-scenario-${scenario.id}`}>
              <ScenarioIcon scenario={scenario} />
              <div className="evidence-row-copy">
                <strong>{scenarioLabel(scenario.id)}</strong>
                <code>{scenario.id}</code>
                <span>Expected: {scenario.expected}</span>
                {scenario.actual && <span>Observed: {scenario.actual}</span>}
              </div>
              <span className="evidence-status">{scenario.status.replace('_', ' ')}</span>
            </li>
          ))}
        </ul>
        <p className="evidence-disclaimer"><strong>NOT RUN is not proof.</strong> It remains visible and is never included in the PASS total. The human-proof negative uses the real Protected Executor DID and demonstrates that Executor authority alone is insufficient; valid proof issuance stays inside the authenticated backend flow.</p>
      </Surface>

      <Surface className="evidence-provenance" aria-labelledby="technical-provenance-title">
        <SectionHeader eyebrow="Technical provenance" title="Inspect source, trust, identities and policy" titleId="technical-provenance-title" icon={<FileCheck2 aria-hidden="true" />} />

        <details className="evidence-provenance-group">
          <summary>Source &amp; build</summary>
          <dl className="evidence-metadata">
            <div><dt>Source</dt><dd>{evidence.metadata.source}</dd></div>
            <div><dt>Generated</dt><dd>{new Date(evidence.metadata.generatedAt).toLocaleString()}</dd></div>
            <div className="evidence-wide"><dt>Source commit</dt><dd data-testid="evidence-source-commit"><code>{evidence.metadata.sourceCommitSha}</code></dd></div>
            <div><dt>Source tree</dt><dd>{sourceTreeState}</dd></div>
            <div><dt>SDK</dt><dd>{evidence.metadata.sdkVersion}</dd></div>
          </dl>
          <p className="evidence-disclaimer">CLEAN is a reproducible working-tree state, not an independent source audit. WASM and policy hashes remain the executed artifact identities.</p>
        </details>

        <details className="evidence-provenance-group">
          <summary>Trust &amp; network</summary>
          <dl className="evidence-metadata">
            <div><dt>Network</dt><dd>{evidence.metadata.network}</dd></div>
            <div><dt>Trust anchor</dt><dd>{trustAnchorState}</dd></div>
            <div><dt>Rollback floor</dt><dd>{rollbackFloorState}</dd></div>
            <div><dt>Trust manifest version</dt><dd>{evidence.metadata.trustManifestVersion}</dd></div>
          </dl>
          <p className="evidence-disclaimer">Trust provenance establishes the cluster trust boundary for authenticated sessions. It is not per-request hardware attestation.</p>
        </details>

        <details className="evidence-provenance-group">
          <summary>Identities &amp; discoverability</summary>
          <dl className="evidence-metadata">
            <div><dt>Agent onboarding</dt><dd><span className={`status-pill ${registrationOk ? 'status-pill-ok' : 'status-pill-off'}`}>{registrationLabel(evidence.metadata.agentRegistrationState)}</span></dd></div>
            <div><dt>A2A service in resolved card</dt><dd><span className={`status-pill ${a2aObserved ? 'status-pill-ok' : 'status-pill-off'}`}>{a2aObserved ? 'OBSERVED' : 'NOT OBSERVED'}</span></dd></div>
            <div><dt>Card check</dt><dd>{new Date(evidence.metadata.agentCardVerifiedAt).toLocaleString()}</dd></div>
            <div><dt>Agent Card services</dt><dd>{evidence.metadata.agentCardServices.length ? evidence.metadata.agentCardServices.join(', ') : 'None verified'}</dd></div>
            <div className="evidence-wide"><dt>Agent Card URI</dt><dd><code>{evidence.metadata.agentCardUri ?? 'Not resolved'}</code></dd></div>
            <div className="evidence-wide"><dt>Agent Card SHA-256</dt><dd><code>{evidence.metadata.agentCardSha256 ?? 'Not available'}</code></dd></div>
            <div className="evidence-wide"><dt>Tenant DID</dt><dd data-testid="evidence-tenant-did"><code>{evidence.metadata.tenantDid}</code></dd></div>
            <div className="evidence-wide"><dt>Proposal Agent DID</dt><dd data-testid="evidence-proposal-agent-did"><code>{evidence.metadata.agentDid}</code></dd></div>
            <div className="evidence-wide"><dt>Protected Executor DID</dt><dd data-testid="evidence-protected-executor-did"><code>{evidence.metadata.executorDid}</code></dd></div>
          </dl>
          <p className="evidence-disclaimer">Agent Card and A2A are discoverability evidence; they do not grant delegated authority. A2A OBSERVED means the resolved card advertised the service, not that public reachability was proved. Protected remediation is not exposed through A2A.</p>
        </details>

        <details className="evidence-provenance-group">
          <summary>Contract &amp; policy</summary>
          <dl className="evidence-metadata">
            <div><dt>Contract version</dt><dd data-testid="evidence-contract-version">{evidence.metadata.contractVersion}</dd></div>
            <div><dt>Policy version</dt><dd>{evidence.metadata.policyVersion}</dd></div>
            <div className="evidence-wide"><dt>Contract</dt><dd data-testid="evidence-contract-id"><code>{evidence.metadata.contractId}</code></dd></div>
            <div className="evidence-wide"><dt>Policy SHA-256</dt><dd><code>{evidence.metadata.policyHash}</code></dd></div>
            <div className="evidence-wide"><dt>WASM SHA-256</dt><dd data-testid="evidence-wasm-sha256"><code>{evidence.metadata.wasmSha256}</code></dd></div>
          </dl>
          <p className="evidence-disclaimer">Policy version/hash identify the canonical operational policy used by this run. The Proposal Agent evaluates policy; the separate Protected Executor performs privileged execution and verification only after the one-time human proof is verified at both the gateway and the T3N contract boundary.</p>
        </details>
      </Surface>
    </section>
  );
}
