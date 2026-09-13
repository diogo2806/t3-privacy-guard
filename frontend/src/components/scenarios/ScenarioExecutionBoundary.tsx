import { Info } from 'lucide-react';
import type { EnterpriseScenarioDefinition } from './scenarioDefinitions';

interface Props {
  scenario: EnterpriseScenarioDefinition;
  proposedAction?: string | null;
}

export function ScenarioExecutionBoundary({ scenario, proposedAction }: Props) {
  if (scenario.executionMode === 'protected' && (!proposedAction || proposedAction === scenario.technicalAction)) return null;

  const mismatch = Boolean(proposedAction && proposedAction !== scenario.technicalAction);
  return (
    <section className="card scenario-execution-boundary" aria-labelledby="scenario-execution-title">
      <div className="card-heading compact">
        <div className="section-icon"><Info aria-hidden="true" /></div>
        <div><p className="eyebrow">Execution boundary</p><h2 id="scenario-execution-title">Policy evaluation only</h2></div>
      </div>
      <p className="card-copy">
        {mismatch
          ? `The agent proposed ${proposedAction}, which differs from this scenario preset. The proposal is shown as returned and T3N decides it normally; protected execution is not offered for the mismatched proposal.`
          : 'This scenario currently demonstrates the real agent proposal and T3N policy decision only. A protected external executor and independent read-back are not implemented for this action, so the interface does not invent authorization or execution steps.'}
      </p>
    </section>
  );
}
