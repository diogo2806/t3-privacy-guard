import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { AgentPromptPanel, ATTACK_PROMPT, SAFE_PROMPT } from './AgentPromptPanel';

const defaultProps = {
  busy: false,
  presetPrompt: SAFE_PROMPT,
  scenarioTitle: 'Credential compromised',
  onAnalyze: vi.fn(),
};

describe('AgentPromptPanel', () => {
  it('loads the selected scenario prompt without automatically calling the agent', () => {
    const onAnalyze = vi.fn();
    render(<AgentPromptPanel {...defaultProps} onAnalyze={onAnalyze} />);

    expect(screen.getByLabelText('Prompt')).toHaveValue(SAFE_PROMPT);
    expect(screen.getByText(/Scenario: Credential compromised/i)).toBeInTheDocument();
    expect(onAnalyze).not.toHaveBeenCalled();
  });

  it('sends the editable prompt through Ask agent', async () => {
    const user = userEvent.setup();
    const onAnalyze = vi.fn();
    render(<AgentPromptPanel {...defaultProps} onAnalyze={onAnalyze} />);

    const prompt = screen.getByLabelText('Prompt');
    await user.clear(prompt);
    await user.type(prompt, 'Synthetic operator-edited prompt');
    await user.click(screen.getByRole('button', { name: 'Ask agent' }));

    expect(onAnalyze).toHaveBeenCalledWith('Synthetic operator-edited prompt');
  });

  it('reloads the current scenario preset without bypassing Ask agent', async () => {
    const user = userEvent.setup();
    const onAnalyze = vi.fn();
    render(<AgentPromptPanel {...defaultProps} onAnalyze={onAnalyze} />);

    const prompt = screen.getByLabelText('Prompt');
    await user.clear(prompt);
    await user.type(prompt, 'Changed');
    await user.click(screen.getByRole('button', { name: 'Reload scenario prompt' }));

    expect(prompt).toHaveValue(SAFE_PROMPT);
    expect(onAnalyze).not.toHaveBeenCalled();
  });

  it('exposes the credential attack controls only for the credential scenario', async () => {
    const user = userEvent.setup();
    const onAnalyze = vi.fn();
    const { rerender } = render(<AgentPromptPanel {...defaultProps} showCredentialAttackControls onAnalyze={onAnalyze} />);

    await user.click(screen.getByRole('button', { name: 'Load credential attack prompt' }));
    expect(screen.getByLabelText('Prompt')).toHaveValue(ATTACK_PROMPT);
    await user.click(screen.getByRole('button', { name: 'Run credential attack' }));
    expect(onAnalyze).toHaveBeenCalledWith(ATTACK_PROMPT);

    rerender(<AgentPromptPanel {...defaultProps} scenarioTitle="Account takeover" presetPrompt="Isolate synthetic account" onAnalyze={onAnalyze} />);
    expect(screen.queryByRole('button', { name: 'Load credential attack prompt' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Run credential attack' })).not.toBeInTheDocument();
  });

  it('resets the editable prompt when a different scenario preset is selected', () => {
    const onAnalyze = vi.fn();
    const { rerender } = render(<AgentPromptPanel {...defaultProps} onAnalyze={onAnalyze} />);

    rerender(<AgentPromptPanel {...defaultProps} presetPrompt="Record synthetic incident" scenarioTitle="Record security incident" onAnalyze={onAnalyze} />);

    expect(screen.getByLabelText('Prompt')).toHaveValue('Record synthetic incident');
    expect(onAnalyze).not.toHaveBeenCalled();
  });

  it('warns before submission that literal private values are blocked before the external provider', () => {
    render(<AgentPromptPanel {...defaultProps} />);
    expect(screen.getByText(/Do not paste private values or secrets/i)).toBeInTheDocument();
    expect(screen.getByText(/rejected server-side before any external AI provider is called/i)).toBeInTheDocument();
  });

  it('renders sanitized rejection guidance without requiring the rejected value', () => {
    render(<AgentPromptPanel {...defaultProps} privacyError="Sensitive literal detected. Remove private values and use an approved logical reference such as verified email instead." />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent(/Sensitive literal detected/i);
    expect(alert).not.toHaveTextContent('@example.com');
  });
});
