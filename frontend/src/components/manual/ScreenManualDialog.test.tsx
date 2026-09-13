import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { ScreenManualDialog } from './ScreenManualDialog';

describe('ScreenManualDialog', () => {
  it('traps focus and explains effective authorization, human provenance, business outcome, privacy and T3N provenance', async () => {
    const user = userEvent.setup();
    render(<div><button type="button">Outside action</button><ScreenManualDialog /></div>);

    const trigger = screen.getByRole('button', { name: 'Open Screen Manual' });
    expect(trigger).toHaveAttribute('title', 'Manual da Tela / Screen Manual');
    expect(trigger).toHaveTextContent('Manual da Tela');
    await user.click(trigger);

    const dialog = screen.getByRole('dialog', { name: 'Incident Response Dashboard' });
    const closeButton = screen.getByRole('button', { name: 'Close Screen Manual' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByRole('heading', { name: 'Business Outcome' })).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Time to policy decision.*evaluatedAt.*action.createdAt/i);
    expect(dialog).toHaveTextContent(/Time to verified outcome.*completedAt.*COMPLETED/i);
    expect(dialog).toHaveTextContent(/não calcula dinheiro economizado.*ROI/i);
    expect(dialog).toHaveTextContent(/Not yet observed.*Not verified yet/i);
    expect(screen.getByText('Identidade, Member grant e autorização efetiva')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/checkDelegation.*cliente autenticado do próprio principal/i);
    expect(dialog).toHaveTextContent(/evaluate-action.*execute-remediation.*verify-remediation/i);
    expect(dialog).toHaveTextContent(/Confirmed.*Denied.*Unknown/i);
    expect(screen.getByText('Operador autenticado e provenance da autorização humana')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Authorized by.*conta autenticada da aplicação/i);
    expect(dialog).toHaveTextContent(/SecurityContext.*nunca.*browser/i);
    expect(dialog).toHaveTextContent(/não é a DID do Proposal Agent.*não é a DID do Protected Executor/i);
    expect(dialog).toHaveTextContent(/operatorPrincipalHash.*SHA-256.*authorizedAt.*issuedAt/i);
    expect(dialog).toHaveTextContent(/LEGACY UNBOUND.*reautorização explícita/i);
    expect(dialog).toHaveTextContent(/não entra em Agent Card.*bundle público de evidence.*T3N Activity Log/i);
    expect(screen.getByText('Readiness')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Proposal evaluation.*Protected remediation/i);
    expect(screen.getByText('Agent Card e A2A público')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/A2A.*avaliação pública/i);
    expect(dialog).toHaveTextContent(/PII-free/i);
    expect(screen.getByText('Integridade do audit local e T3N Activity Log')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/HMAC-SHA256/i);
    expect(dialog).toHaveTextContent(/tamper-evident/i);
    expect(dialog).toHaveTextContent(/VERIFIED.*BROKEN.*KEY_MISMATCH.*LEGACY_UNVERIFIED/i);
    expect(dialog).toHaveTextContent(/snapshot antigo internamente consistente/i);
    expect(dialog).toHaveTextContent(/evaluate-action.*Proposal Agent.*execute-remediation.*verify-remediation.*Protected Executor/i);
    expect(screen.getByText('Proof & evidence')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Source tree/i);
    expect(dialog).toHaveTextContent(/COMPLETED/i);
    expect(closeButton).toHaveFocus();

    await user.tab();
    expect(closeButton).toHaveFocus();
    screen.getByRole('button', { name: 'Outside action' }).focus();
    expect(closeButton).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    expect(trigger).toHaveFocus();
  });

  it('closes from the backdrop, restores focus and can be reopened without duplicate handlers', async () => {
    const user = userEvent.setup();
    render(<ScreenManualDialog />);
    const trigger = screen.getByRole('button', { name: 'Open Screen Manual' });
    await user.click(trigger);
    const backdrop = screen.getByRole('presentation');
    await user.pointer([{ target: backdrop, keys: '[MouseLeft>]' }, { keys: '[/MouseLeft]' }]);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    expect(trigger).toHaveFocus();
    await user.click(trigger);
    expect(screen.getByRole('button', { name: 'Close Screen Manual' })).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
