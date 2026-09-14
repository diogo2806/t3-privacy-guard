import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { BookOpen, X } from 'lucide-react';

const FOCUSABLE_SELECTOR = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled])', 'select:not([disabled])',
  'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
].join(',');

function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((element) => {
    if (element.hidden || element.getAttribute('aria-hidden') === 'true' || element.closest('[hidden], [aria-hidden="true"]')) return false;
    const style = window.getComputedStyle(element);
    return style.display !== 'none' && style.visibility !== 'hidden';
  });
}

export function ScreenManualDialog() {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const close = () => { setOpen(false); requestAnimationFrame(() => triggerRef.current?.focus()); };

  useEffect(() => {
    if (!open) return undefined;
    const appRoot = document.getElementById('root');
    const previousAriaHidden = appRoot?.getAttribute('aria-hidden');
    appRoot?.setAttribute('inert', '');
    appRoot?.setAttribute('aria-hidden', 'true');
    closeButtonRef.current?.focus();

    const keepFocusInside = () => {
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = focusableElements(dialog);
      (focusable[0] ?? dialog).focus();
    };
    const onFocusIn = (event: FocusEvent) => {
      const dialog = dialogRef.current;
      if (dialog && event.target instanceof Node && !dialog.contains(event.target)) keepFocusInside();
    };
    const onKeyDown = (event: KeyboardEvent) => {
      const dialog = dialogRef.current;
      if (!dialog) return;
      if (event.key === 'Escape') { event.preventDefault(); close(); return; }
      if (event.key !== 'Tab') return;
      const focusable = focusableElements(dialog);
      if (focusable.length === 0) { event.preventDefault(); dialog.focus(); return; }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (focusable.length === 1 || !dialog.contains(active) || (event.shiftKey && active === first) || (!event.shiftKey && active === last)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      }
    };

    document.addEventListener('focusin', onFocusIn);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('focusin', onFocusIn);
      document.removeEventListener('keydown', onKeyDown);
      appRoot?.removeAttribute('inert');
      if (previousAriaHidden === null) appRoot?.removeAttribute('aria-hidden');
      else appRoot?.setAttribute('aria-hidden', previousAriaHidden);
    };
  }, [open]);

  const dialog = open ? createPortal(
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && close()}>
      <section ref={dialogRef} tabIndex={-1} className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="screen-manual-title" aria-describedby="screen-manual-purpose">
        <div className="modal-header">
          <div><p className="eyebrow">Manual da Tela</p><h2 id="screen-manual-title">Incident Response Dashboard</h2></div>
          <button ref={closeButtonRef} type="button" className="icon-button" aria-label="Close Screen Manual" title="Close Screen Manual" onClick={close}><X aria-hidden="true" /></button>
        </div>
        <div className="manual-content">
          <section>
            <h3>Finalidade</h3>
            <p id="screen-manual-purpose">A tela demonstra resposta a incidentes com separação entre proposta de IA, decisão de policy T3N, autorização humana, execução protegida e verificação independente. <strong>Protection flow</strong> opera o fluxo, <strong>Executive demo</strong> resume o estado observado, <strong>Measured control impact</strong> agrega resultados persistidos dentro da retenção e <strong>Evidence</strong> apresenta a prova técnica. Nenhum estado de sucesso ou valor financeiro é inferido sem dados compatíveis.</p>
          </section>

          <section>
            <h3>Acesso e permissões humanas</h3>
            <p>A sessão mostra o principal autenticado, suas autoridades e se <strong>Enterprise SoD</strong> está ativo. <strong>ANALYST</strong> cria incidentes, solicita análise, registra propostas e avalia policy. <strong>APPROVER</strong> registra a autorização humana. <strong>EXECUTOR</strong> executa e verifica a remediação protegida. <strong>AUDITOR</strong> é somente leitura e pode consultar estado, histórico, trace, métricas agregadas e evidence.</p>
            <p>As permissões são validadas pelo backend; esconder um botão no navegador não concede nem revoga autoridade. Em modo enterprise, o mesmo principal que autorizou não pode executar nem verificar a mesma remediação, mesmo que possua múltiplas autoridades. Em modo local/demo, uma única conta configurada pode receber todas as autoridades sem ser apresentada como IAM enterprise.</p>
          </section>

          <section>
            <h3>Áreas, campos e botões</h3>
            <p><strong>Protection flow</strong> contém cenário, prompt, proposta, decisão, payload minimizado, autorização, execução, verificação, impacto agregado, retenção e activity rail. <strong>Requested fields</strong>, <strong>Allowed for egress</strong>, <strong>Removed before egress</strong>, <strong>Trusted synthetic values</strong> e <strong>Protected egress payload</strong> explicam a minimização. Para <code>notify-security</code>, a aplicação carrega apenas a referência lógica <code>verified_email</code>.</p>
            <p><strong>Authorize</strong> aparece somente quando a decisão e o contrato de payload permitem remediação e a sessão possui autoridade APPROVER. <strong>Execute protected…</strong> e <strong>Verify external state</strong> exigem EXECUTOR e, em Enterprise SoD, um principal diferente do aprovador. <strong>Execution principal</strong> mostra quem iniciou a execução persistida; <strong>Separation of duties</strong> mostra CONFIRMED, NOT YET PROVEN, NOT COMPLIANT ou LOCAL / DEMO MODE.</p>
            <p>Em <strong>Measured control impact</strong>, os botões <strong>Retained</strong>, <strong>24 hours</strong> e <strong>7 days</strong> alteram somente a janela de observação da leitura agregada. A seleção não executa policy, não autoriza e não dispara remediação.</p>
          </section>

          <section>
            <h3>Policy, privacidade e execução protegida</h3>
            <p>DENY bloqueia remediação. REDACT só continua se o subconjunto permitido ainda satisfizer o contrato mínimo. Para <code>revoke-credential</code>, os campos mínimos são <code>incident_id</code>, <code>credential_id</code> e <code>reason</code>. Para <code>notify-security</code>, são <code>incident_id</code>, <code>severity</code> e <code>summary</code>, com exatamente <code>private_refs=["verified_email"]</code>. Valores removidos pela policy não seguem para o egress.</p>
            <p>Após autorização humana, o backend emite prova one-time assinada e vinculada à ação, policy, destino e principal autorizador. O Protected Executor usa identidade T3N própria. Aceitação externa não equivale a conclusão: revogação exige read-back <strong>REVOKED</strong>; notificação exige <strong>DELIVERED</strong> com <code>recipient_resolved=true</code>.</p>
          </section>

          <section>
            <h3>Identidades T3N e readiness</h3>
            <p>Tenant, Proposal Agent e Protected Executor são identidades distintas. Proposal usa <code>evaluate-action</code>; Executor usa <code>execute-remediation</code> e <code>verify-remediation</code>. Readiness só é apresentado como pronto quando autenticação, contrato, delegation/effective access e integração requerida estão coerentes. Estados UNKNOWN, DENIED, MISMATCH ou indisponíveis falham fechado.</p>
            <p>O Agent Card/A2A público expõe somente capacidades públicas de avaliação compatíveis com Proposal Agent. Ele não expõe autorização humana, credenciais do Executor, valores privados resolvidos nem endpoints privilegiados de remediação.</p>
          </section>

          <section>
            <h3>Executive Demo e Business Outcome</h3>
            <p><strong>Executive demo</strong> é apenas uma projeção do mesmo runtime. Antes da análise mostra <strong>NOT YET OBSERVED</strong>; DENY mostra <strong>BLOCKED BEFORE PROTECTED EGRESS</strong>; ALLOW sem aprovação mostra <strong>HUMAN AUTHORIZATION REQUIRED</strong>; aprovação sem side effect mostra <strong>AUTHORIZED / NOT EXECUTED</strong>; PENDING_VERIFICATION mostra <strong>ACCEPTED / NOT VERIFIED</strong>. UNVERIFIED e FAILED nunca são apresentados como sucesso.</p>
            <p><strong>Business Outcome</strong> deriva risco, ação, policy, autorização, execução e verificação do incidente selecionado. <strong>Time to policy decision</strong> usa <code>decision.evaluatedAt - action.createdAt</code>. <strong>Time to verified outcome</strong> só existe em COMPLETED e usa <code>remediation.completedAt - action.createdAt</code>.</p>
          </section>

          <section>
            <h3>Measured control impact</h3>
            <p>O resumo agregado usa somente dados persistidos ainda cobertos pela retenção. <strong>Evaluated actions</strong> conta decisões de policy observadas. <strong>Blocked before egress</strong> conta decisões DENY. <strong>Minimized decisions</strong> conta REDACT. <strong>Verified outcomes</strong> conta execuções em COMPLETED, estado que já exige read-back independente.</p>
            <p><strong>Observed block rate</strong> = DENY / decisões avaliadas × 100. <strong>Verified completion</strong> = COMPLETED / (COMPLETED + UNVERIFIED + FAILED) × 100. EXECUTING e PENDING_VERIFICATION não entram no denominador finalizado. Quando o denominador é zero, a tela mostra <strong>NOT OBSERVED</strong>, nunca 0% inventado.</p>
            <p><strong>Median policy decision</strong> usa as latências <code>evaluatedAt - createdAt</code>. <strong>Median verified outcome</strong> usa somente COMPLETED e <code>completedAt - createdAt</code>. Tempos negativos/inconsistentes não entram na mediana. <strong>Redacted normal field names</strong> e <strong>Redacted private references</strong> contam nomes/categorias removidos pela policy; não contam bytes, pessoas ou valores privados.</p>
            <p>A janela solicitada nunca ultrapassa a retenção configurada; se 7 dias forem solicitados e apenas 3 estiverem retidos, a cobertura informa a limitação. Dados já purgados não são reconstruídos. O endpoint agregado não retorna prompt, username, normal payload ou valor privado.</p>
            <p><strong>Financial ROI is NOT MEASURED.</strong> O produto não converte essas métricas em dinheiro economizado, breach evitado, percentual de redução de risco, SLA ou compliance porque esses inputs não são medidos pelo runtime.</p>
          </section>

          <section>
            <h3>Audit e Evidence</h3>
            <p>O audit local é encadeado com HMAC-SHA256 e é <strong>tamper-evident</strong>, não imutável. A autorização registra o principal aprovador e a execução persiste o principal executor obtido da sessão autenticada. O evento de início da execução identifica a função EXECUTOR e o principal canônico; nenhum principal é aceito a partir do corpo enviado pelo navegador.</p>
            <p>Evidence diferencia PASS, FAIL e NOT RUN. NOT RUN não conta como prova. O Evidence Center preserva detalhes técnicos como source commit, contrato, DIDs e provenance, sem publicar senha, chave privada, token, nonce ou recipient plaintext. Métricas agregadas são produto/observabilidade operacional e não substituem evidência T3N.</p>
          </section>

          <section>
            <h3>Fluxo principal</h3>
            <p>1. Confira readiness e a autoridade da sessão. 2. Como ANALYST, escolha o cenário, analise e revise proposal/policy/minimização. 3. Como APPROVER, autorize somente a ação e o destino revisados. 4. Em Enterprise SoD, troque para um principal EXECUTOR diferente do aprovador. 5. Execute a remediação protegida. 6. Verifique o estado externo sem repetir automaticamente um side effect ambíguo. 7. Consulte Measured control impact para observar somente resultados persistidos na janela selecionada. 8. Como AUDITOR ou outro papel autenticado em leitura, confira histórico, trace e Evidence. 9. Considere COMPLETED somente após verificação independente.</p>
          </section>

          <section>
            <h3>Mensagens e estados</h3>
            <p><strong>403 Action not allowed</strong> significa que a sessão não possui a autoridade exigida para aquela mutação. <strong>Separation of duties…different principal</strong> significa que o aprovador tentou executar ou verificar em modo enterprise; nenhuma chamada de protected egress é iniciada. <strong>REAUTHORIZATION REQUIRED</strong> indica autorização legada sem provenance suficiente. <strong>Destination changed</strong> exige nova ação, avaliação e autorização. <strong>NOT OBSERVED</strong> em taxa/tempo agregado significa ausência de denominador ou amostra válida, não resultado zero. PENDING_VERIFICATION, UNVERIFIED e FAILED não são equivalentes a COMPLETED. Falhas de provider, T3N, delegation, policy, audit integrity ou trust boundary nunca são convertidas em sucesso.</p>
          </section>
        </div>
      </section>
    </div>,
    document.body,
  ) : null;

  return (
    <>
      <button ref={triggerRef} type="button" className="button button-secondary manual-trigger" aria-label="Open Screen Manual" title="Manual da Tela / Screen Manual" onClick={() => setOpen(true)}>
        <BookOpen aria-hidden="true" /><span>Manual da Tela</span>
      </button>
      {dialog}
    </>
  );
}
