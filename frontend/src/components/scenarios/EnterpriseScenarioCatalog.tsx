import { BellRing, Check, ClipboardPlus, KeyRound, ShieldAlert } from 'lucide-react';
import { SectionHeader } from '../ui/SectionHeader';
import { Surface } from '../ui/Surface';
import type { EnterpriseScenarioDefinition, EnterpriseScenarioId } from './scenarioDefinitions';
import { ENTERPRISE_SCENARIOS } from './scenarioDefinitions';

interface Props {
  selectedId: EnterpriseScenarioId;
  busy: boolean;
  onSelect: (scenario: EnterpriseScenarioDefinition) => void;
}

const icons = {
  'credential-compromised': KeyRound,
  'account-takeover': ShieldAlert,
  'record-security-incident': ClipboardPlus,
  'notify-security-contact': BellRing,
} as const;

export function EnterpriseScenarioCatalog({ selectedId, busy, onSelect }: Props) {
  const selected = ENTERPRISE_SCENARIOS.find((scenario) => scenario.id === selectedId) ?? ENTERPRISE_SCENARIOS[0];

  return (
    <Surface className="scenario-catalog" aria-labelledby="enterprise-scenarios-title">
      <SectionHeader eyebrow="Scenario" title="Choose the business risk" titleId="enterprise-scenarios-title" icon={<ShieldAlert aria-hidden="true" />} />
      <p className="card-copy">Selecting a scenario prepares synthetic input only. It never grants permission or executes an action.</p>
      <div className="scenario-catalog-grid" role="list" aria-label="Enterprise demonstration scenarios">
        {ENTERPRISE_SCENARIOS.map((scenario) => {
          const Icon = icons[scenario.id];
          const active = scenario.id === selectedId;
          return (
            <div key={scenario.id} role="listitem" className="scenario-list-item">
              <button type="button" className={`scenario-card${active ? ' scenario-card-selected' : ''}`} aria-pressed={active} onClick={() => onSelect(scenario)} disabled={busy}>
                <span className="scenario-card-icon"><Icon aria-hidden="true" /></span>
                <span className="scenario-card-copy"><strong>{scenario.title}</strong><code>{scenario.technicalAction}</code></span>
                {active && <Check className="scenario-card-check" aria-label="Selected scenario" />}
              </button>
            </div>
          );
        })}
      </div>
      <details className="scenario-explainer" aria-live="polite">
        <summary>Business context and success definition</summary>
        <strong>{selected.title}</strong>
        <p>{selected.description}</p>
        <p>{selected.demonstrates}</p>
        <dl className="scenario-business-context">
          <div><dt>Business risk</dt><dd>{selected.businessRisk}</dd></div>
          <div><dt>Protected asset</dt><dd>{selected.protectedAsset}</dd></div>
          <div><dt>Target business outcome</dt><dd>{selected.businessOutcome}</dd></div>
          <div><dt>Success definition</dt><dd>{selected.successDefinition}</dd></div>
        </dl>
      </details>
    </Surface>
  );
}
