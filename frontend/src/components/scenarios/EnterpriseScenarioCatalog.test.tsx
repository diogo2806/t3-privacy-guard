import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { EnterpriseScenarioCatalog } from './EnterpriseScenarioCatalog';
import { ENTERPRISE_SCENARIOS } from './scenarioDefinitions';

describe('EnterpriseScenarioCatalog', () => {
  it('renders all four business scenarios without presenting them as authorization', () => {
    render(<EnterpriseScenarioCatalog selectedId="credential-compromised" busy={false} onSelect={vi.fn()} />);

    for (const scenario of ENTERPRISE_SCENARIOS) {
      expect(screen.getAllByText(scenario.title).length).toBeGreaterThan(0);
      expect(screen.getByText(scenario.technicalAction)).toBeInTheDocument();
    }
    expect(screen.getByText(/synthetic input only/i)).toBeInTheDocument();
    expect(screen.getByText(/never grants permission or executes an action/i)).toBeInTheDocument();
  });

  it('shows the selected scenario business context and success definition', async () => {
    const user = userEvent.setup();
    render(<EnterpriseScenarioCatalog selectedId="credential-compromised" busy={false} onSelect={vi.fn()} />);

    await user.click(screen.getByText('Business context and success definition'));
    const scenario = ENTERPRISE_SCENARIOS[0];
    expect(screen.getByText(scenario.businessRisk)).toBeInTheDocument();
    expect(screen.getByText(scenario.protectedAsset)).toBeInTheDocument();
    expect(screen.getByText(scenario.businessOutcome)).toBeInTheDocument();
    expect(screen.getByText(scenario.successDefinition)).toBeInTheDocument();
  });

  it('selects a scenario without executing analysis automatically', async () => {
    const user = userEvent.setup();
    const onSelect = vi.fn();
    render(<EnterpriseScenarioCatalog selectedId="credential-compromised" busy={false} onSelect={onSelect} />);

    await user.click(screen.getByRole('button', { name: /Account takeover/i }));
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0][0].id).toBe('account-takeover');
  });

  it('keeps every preset synthetic and never embeds raw T3N placeholders or email addresses', () => {
    for (const scenario of ENTERPRISE_SCENARIOS) {
      expect(scenario.prompt).not.toMatch(/\{\{profile\./i);
      expect(scenario.prompt).not.toMatch(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
      expect(scenario.prompt).not.toMatch(/t3n[_-]?api[_-]?key\s*[:=]/i);
    }
    expect(ENTERPRISE_SCENARIOS.find((scenario) => scenario.id === 'notify-security-contact')?.prompt).toContain('verified_email');
  });
});
