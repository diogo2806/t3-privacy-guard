import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { ScreenManualDialog } from './ScreenManualDialog';

describe('ScreenManualDialog', () => {
  it('traps focus and explains executive demo, effective authorization, human proof, business outcome, A2A, privacy and provenance', async () => {
    const user = userEvent.setup();
    render(<div><button type="button">Outside action</button><ScreenManualDialog /></div>);

    const trigger = screen.getByRole('button', { name: 'Open Screen Manual' });
    expect(trigger).toHaveAttribute('title', 'Manual da Tela / Screen Manual');
    expect(trigger).toHaveTextContent('Manual da Tela');
    await user.click(trigger);

    const dialog = screen.getByRole('dialog', { name: 'Incident Response Dashboard' });
    const closeButton = screen.getByRole('button', { name: 'Close Screen Manual' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByRole('heading', { name: 'Executive Demo' })).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/projeção do mesmo estado runtime.*não cria incidente.*autorização.*execução.*evidence paralela/i);
    expect(dialog).toHaveTextContent(/BLOCKED BEFORE PROTECTED EGRESS.*MINIMIZATION REQUIRED.*HUMAN AUTHORIZATION REQUIRED/i);
    expect(dialog).toHaveTextContent(/AUTHORIZED \/ NOT EXECUTED.*ACCEPTED \/ NOT VERIFIED/i);
    expect(dialog).toHaveTextContent(/Proof at a glance.*não substitui.*Evidence Center/i);
    expect(dialog).toHaveTextContent(/T3N LIVE \/ READY.*protected remediation ready.*evidence válida/i);
    expect(dialog).toHaveTextContent(/não possui botões de Analyze, Authorize, Execute ou Verify/i);
    expect(screen.getByRole('heading', { name: 'Business Outcome' })).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Time to policy decision.*evaluatedAt.*action.createdAt/i);
    expect(dialog).toHaveTextContent(/Time to verified outcome.*completedAt.*COMPLETED/i);
    expect(dialog).toHaveTextContent(/não calcula dinheiro economizado.*ROI/i);
    expect(dialog).toHaveTextContent(/Not yet observed.*Not verified yet/i);
    expect(screen.getByText('Identidade, Member grant e autorização efetiva')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/checkDelegation.*cliente autenticado do próprio principal/i);
    expect(dialog).toHaveTextContent(/evaluate-action.*execute-remediation.*verify-remediation/i);
    expect(dialog).toHaveTextContent(/Confirmed.*Denied.*Unknown/i);
    expect(screen.getByText('Readiness')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Proposal evaluation.*Protected remediation/i);
    expect(screen.getByText('Agent Card e A2A público')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/A2A.*avaliação pública/i);
    expect(dialog).toHaveTextContent(/PII-free/i);
    expect(screen.getByText('Policy, minimização, autorização humana e execução')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/prova.*v2.*one-time.*Ed25519/i);
    expect(dialog).toHaveTextContent(/Gateway proof check.*fail-fast.*não substitui T3N/i);
    expect(dialog).toHaveTextContent(/Antes de ler.*security_api_url.*security_api_key.*WASM verifica assinatura.*nonce/i);
    expect(dialog).toHaveTextContent(/não afirma que T3N verificou identidade civil do humano/i);
    expect(screen.getByText('Integridade do audit local e T3N Activity Log')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/HMAC-SHA256/i);
    expect(dialog).toHaveTextContent(/tamper-evident/i);
    expect(dialog).toHaveTextContent(/VERIFIED.*BROKEN.*KEY_MISMATCH.*LEGACY_UNVERIFIED/i);
    expect(dialog).toHaveTextContent(/snapshot antigo internamente consistente/i);
    expect(dialog).toHaveTextContent(/evaluate-action.*Proposal Agent.*execute-remediation.*verify-remediation.*Protected Executor/i);
    expect(screen.getByText('Proof & evidence')).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/Source tree/i);
    expect(dialog).toHaveTextContent(/prova assinada.*nonce.*chave privada.*não secreta/i);
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
