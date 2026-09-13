import { Bot, PlayCircle } from 'lucide-react';
import { Button } from '../ui/Button';
import { SectionHeader } from '../ui/SectionHeader';
import { Surface } from '../ui/Surface';

interface Props {
  busy: boolean;
  prompt: string;
  privacyError?: string | null;
  onPromptChange: (prompt: string) => void;
  onAnalyze: (prompt: string) => void;
}

export function AgentPromptPanel({ busy, prompt, privacyError, onPromptChange, onAnalyze }: Props) {
  return (
    <Surface className="agent-prompt-card" aria-labelledby="agent-prompt-title">
      <SectionHeader eyebrow="Untrusted agent input" title="Analyze a proposed action" titleId="agent-prompt-title" icon={<Bot aria-hidden="true" />} />
      <p className="card-copy">The scenario prepares synthetic input only. The model can propose an action; T3N independently decides whether that proposal may continue.</p>
      <details className="technical-disclosure">
        <summary>Prompt privacy guidance</summary>
        <p className="card-copy"><strong>Do not paste private values or secrets.</strong> High-confidence sensitive literals are blocked before a remote AI provider, but free text is not a complete PII scanner. Use approved logical references such as “verified email”.</p>
      </details>
      <label className="agent-prompt-label" htmlFor="agent-prompt">Prompt</label>
      <textarea id="agent-prompt" className="agent-prompt-input" rows={5} maxLength={4000} value={prompt} onChange={(event) => onPromptChange(event.target.value)} disabled={busy} aria-describedby={privacyError ? 'agent-prompt-privacy-error' : undefined} />
      {privacyError && <div id="agent-prompt-privacy-error" className="feedback feedback-error" role="alert" aria-live="assertive">{privacyError}</div>}
      <div className="agent-prompt-actions">
        <Button variant="primary" onClick={() => onAnalyze(prompt)} disabled={busy || !prompt.trim()}><PlayCircle aria-hidden="true" />Analyze with agent</Button>
      </div>
    </Surface>
  );
}
