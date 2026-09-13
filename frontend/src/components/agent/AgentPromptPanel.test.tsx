import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { AgentPromptPanel } from './AgentPromptPanel';

const PROMPT = 'Record synthetic incident demo-42 without private values.';

describe('AgentPromptPanel', () => {
  it('submits the currently selected or edited prompt through Ask agent', async () => {
    const user = userEvent.setup();
    const onAnalyze = vi.fn();
    const onPromptChange = vi.fn();
    render(<AgentPromptPanel busy={false} prompt={PROMPT} onPromptChange={onPromptChange} onAnalyze={onAnalyze} />);

    expect(screen.getByLabelText('Prompt')).toHaveValue(PROMPT);
    await user.click(screen.getByRole('button', { name: 'Ask agent' }));
    expect(onAnalyze).toHaveBeenCalledWith(PROMPT);
  });

  it('reports edits to the parent without executing analysis automatically', async () => {
    const user = userEvent.setup();
    const onAnalyze = vi.fn();
    const onPromptChange = vi.fn();
    render(<AgentPromptPanel busy={false} prompt={PROMPT} onPromptChange={onPromptChange} onAnalyze={onAnalyze} />);

    await user.type(screen.getByLabelText('Prompt'), ' updated');
    expect(onPromptChange).toHaveBeenCalled();
    expect(onAnalyze).not.toHaveBeenCalled();
  });

  it('describes the pre-provider guard as high-confidence but deliberately incomplete', () => {
    render(<AgentPromptPanel busy={false} prompt={PROMPT} onPromptChange={vi.fn()} onAnalyze={vi.fn()} />);
    expect(screen.getByText(/Do not paste private values or secrets/i)).toBeInTheDocument();
    expect(screen.getByText(/High-confidence sensitive literals are blocked before a remote AI provider/i)).toBeInTheDocument();
    expect(screen.getByText(/free text is not a complete PII scanner/i)).toBeInTheDocument();
    expect(screen.queryByText(/PII-free|certified safe/i)).not.toBeInTheDocument();
  });

  it('renders sanitized rejection guidance without requiring the rejected value', () => {
    render(<AgentPromptPanel busy={false} prompt={PROMPT} privacyError="Sensitive literal detected. Remove private values and use an approved logical reference such as verified email instead." onPromptChange={vi.fn()} onAnalyze={vi.fn()} />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent(/Sensitive literal detected/i);
    expect(alert).not.toHaveTextContent('@example.com');
  });
});
