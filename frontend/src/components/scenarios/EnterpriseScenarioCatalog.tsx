import { BellRing, Check, ClipboardPlus, KeyRound, ShieldAlert } from 'lucide-react';
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
    <section className="card scenario-catalog" aria-labelledby="enterprise-scenarios-title">
      <div className="card-heading compact">
        <div className="section-icon"><ShieldAlert aria-hidden="true" /></div>
        <div><p className="eyebrow">Business applicability</p><h2 id="enterprise-scenarios-title">Choose an enterprise scenario</h2></div>
      </div>
      <p className="card-copy">These are safe demonstration presets, not permissions. Selecting one only prepares synthetic input; the real AI proposal still goes through the independent T3N policy.</p>
      <div className="scenario-catalog-grid" role="list" aria-label="Enterprise demonstration scenarios">
        {ENTERPRISE_SCENARIOS.map((scenario) => {
          const Icon = icons[scenario.id];
          const active = scenario.id === selectedId;
          return (
            <div key={scenario.id} role="listitem" className="scenario-list-item">
              <button
                type="button"
                className={`scenario-card${active ? ' scenario-card-selected' : ''}`}
                aria-pressed={active}
                onClick={() => onSelect(scenario)}
                disabled={busy}
              >
                <span className="scenario-card-icon"><Icon aria-hidden="true" /></span>
                <span className="scenario-card-copy">
                  <strong>{scenario.title}</strong>
                  <span>{scenario.description}</span>
                  <code>{scenario.technicalAction}</code>
                </span>
                {active && <Check className="scenario-card-check" aria-label="Selected scenario" />}
              </button>
            </div>
          );
        })}
      </div>
      <div className="scenario-explainer" aria-live="polite">
        <strong>Selected: {selected.title}</strong>
        <p>{selected.demonstrates}</p>
      </div>
    </section>
  );
}
