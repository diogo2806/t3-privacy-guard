import { Building2, LockKeyhole, ShieldCheck } from 'lucide-react';
import {
  ENTERPRISE_SCENARIOS,
  getEnterpriseScenario,
  type EnterpriseScenarioId,
} from './scenarioDefinitions';

interface Props {
  selectedScenarioId: EnterpriseScenarioId;
  busy: boolean;
  onSelect: (scenarioId: EnterpriseScenarioId) => void;
}

export function EnterpriseScenarioCatalog({ selectedScenarioId, busy, onSelect }: Props) {
  const selected = getEnterpriseScenario(selectedScenarioId);

  return (
    <section className="card scenario-catalog" aria-labelledby="enterprise-scenarios-title">
      <div className="card-heading compact">
        <div className="section-icon"><Building2 aria-hidden="true" /></div>
        <div><p className="eyebrow">Enterprise scenarios</p><h2 id="enterprise-scenarios-title">Choose a scenario</h2></div>
      </div>
      <p className="card-copy">These are demonstration presets, not permissions. Selecting one only prepares synthetic content; the T3N Rust/WASM policy remains the authorization authority.</p>
      <div className="scenario-grid" role="group" aria-label="Enterprise scenario presets">
        {ENTERPRISE_SCENARIOS.map((scenario) => {
          const active = scenario.id === selectedScenarioId;
          return (
            <button
              key={scenario.id}
              type="button"
              className={`scenario-card${active ? ' scenario-card-selected' : ''}`}
              aria-pressed={active}
              disabled={busy}
              onClick={() => onSelect(scenario.id)}
            >
              <span className="scenario-card-heading">
                <strong>{scenario.title}</strong>
                {scenario.executionMode === 'protected'
                  ? <ShieldCheck aria-label="Protected execution available" />
                  : <LockKeyhole aria-label="Policy evaluation only" />}
              </span>
              <span className="scenario-card-description">{scenario.description}</span>
              <span className="scenario-card-meta">Policy action: <code>{scenario.technicalAction}</code></span>
              <span className="scenario-card-mode">{scenario.executionMode === 'protected' ? 'Protected execution implemented' : 'Policy evaluation only'}</span>
            </button>
          );
        })}
      </div>
      <div className="scenario-objective" role="status" aria-live="polite">
        <strong>Selected: {selected.title}</strong>
        <p>{selected.demonstration}</p>
      </div>
    </section>
  );
}
