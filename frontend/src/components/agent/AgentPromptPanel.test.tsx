import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { AgentPromptPanel, ATTACK_PROMPT, SAFE_PROMPT } from './AgentPromptPanel';

describe('AgentPromptPanel', () => {
  it('sends the documented attack prompt through the real agent action', async () => {
    const user = userEvent.setup();
    const onAnalyze = vi.fn();
    render(<AgentPromptPanel busy={false} onAnalyze={onAnalyze} />);

    expect(screen.getByLabelText('Prompt')).toHaveValue(ATTACK_PROMPT);
    await user.click(screen.getByRole('button', { name: 'Run attack scenario' }));
    expect(onAnalyze).toHaveBeenCalledWith(ATTACK_PROMPT);
  });

  it('loads a legitimate prompt without bypassing Ask agent', async () => {
    const user = userEvent.setup();
    const onAnalyze = vi.fn();
    render(<AgentPromptPanel busy={false} onAnalyze={onAnalyze} />);

    await user.click(screen.getByRole('button', { name: 'Load safe prompt' }));
    expect(screen.getByLabelText('Prompt')).toHaveValue(SAFE_PROMPT);
    expect(onAnalyze).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Ask agent' }));
    expect(onAnalyze).toHaveBeenCalledWith(SAFE_PROMPT);
  });

  it('warns before submission that literal private values are blocked before the external provider', () => {
    render(<AgentPromptPanel busy={false} onAnalyze={vi.fn()} />);
    expect(screen.getByText(/Do not paste private values or secrets/i)).toBeInTheDocument();
    expect(screen.getByText(/rejected server-side before any external AI provider is called/i)).toBeInTheDocument();
  });

  it('renders sanitized rejection guidance without requiring the rejected value', () => {
    render(<AgentPromptPanel busy={false} privacyError="Sensitive literal detected. Remove private values and use an approved logical reference such as verified email instead." onAnalyze={vi.fn()} />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent(/Sensitive literal detected/i);
    expect(alert).not.toHaveTextContent('@example.com');
  });
});
