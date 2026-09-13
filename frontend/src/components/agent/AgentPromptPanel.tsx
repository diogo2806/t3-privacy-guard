import { Bot, PlayCircle, RotateCcw, ShieldAlert } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  CREDENTIAL_ATTACK_PROMPT,
  CREDENTIAL_SAFE_PROMPT,
} from '../scenarios/scenarioDefinitions';

export const ATTACK_PROMPT = CREDENTIAL_ATTACK_PROMPT;
export const SAFE_PROMPT = CREDENTIAL_SAFE_PROMPT;

interface Props {
  busy: boolean;
  presetPrompt: string;
  scenarioTitle: string;
  showCredentialAttackControls?: boolean;
  privacyError?: string | null;
  onAnalyze: (prompt: string) => void;
}

export function AgentPromptPanel({
  busy,
  presetPrompt,
  scenarioTitle,
  showCredentialAttackControls = false,
  privacyError,
  onAnalyze,
}: Props) {
  const [prompt, setPrompt] = useState(presetPrompt);

  useEffect(() => {
    setPrompt(presetPrompt);
  }, [presetPrompt]);

  return (
    <section className="card agent-prompt-card" aria-labelledby="agent-prompt-title">
      <div className="card-heading compact">
        <div className="section-icon"><Bot aria-hidden="true" /></div>
        <div><p className="eyebrow">Untrusted input</p><h2 id="agent-prompt-title">AI agent prompt</h2></div>
      </div>
      <p className="card-copy"><strong>Scenario: {scenarioTitle}.</strong> The preset is editable demonstration content only. The model may propose a different action, and T3N independently decides the proposal that is actually returned.</p>
      <p className="card-copy"><strong>Do not paste private values or secrets.</strong> Use approved logical references such as “verified email”. Sensitive literals are rejected server-side before any external AI provider is called.</p>
      <label className="agent-prompt-label" htmlFor="agent-prompt">Prompt</label>
      <textarea id="agent-prompt" className="agent-prompt-input" rows={5} maxLength={4000} value={prompt} onChange={(event) => setPrompt(event.target.value)} disabled={busy} aria-describedby={privacyError ? 'agent-prompt-privacy-error' : undefined} />
      {privacyError && <div id="agent-prompt-privacy-error" className="feedback feedback-error" role="alert" aria-live="assertive">{privacyError}</div>}
      <div className="agent-prompt-actions">
        <button type="button" className="button button-secondary" onClick={() => setPrompt(presetPrompt)} disabled={busy}><RotateCcw aria-hidden="true" />Reload scenario prompt</button>
        {showCredentialAttackControls && <button type="button" className="button button-secondary" onClick={() => setPrompt(ATTACK_PROMPT)} disabled={busy}><ShieldAlert aria-hidden="true" />Load credential attack prompt</button>}
        <button type="button" className="button button-primary" onClick={() => onAnalyze(prompt)} disabled={busy || !prompt.trim()}><PlayCircle aria-hidden="true" />Ask agent</button>
        {showCredentialAttackControls && <button type="button" className="button button-danger" onClick={() => onAnalyze(ATTACK_PROMPT)} disabled={busy}><PlayCircle aria-hidden="true" />Run credential attack</button>}
      </div>
    </section>
  );
}
