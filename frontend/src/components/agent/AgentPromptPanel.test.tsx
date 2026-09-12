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
});
