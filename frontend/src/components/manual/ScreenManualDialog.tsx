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
            <p id="screen-manual-purpose">A tela demonstra resposta a incidentes separando proposta de IA, decisão de policy T3N, autorização humana autenticada, Protected Executor, protected egress e verificação independente. A IA escolhe ação e nomes de campos, mas não recebe credenciais do Executor nem fornece os valores operacionais confiáveis usados no egress.</p>
          </section>

          <section>
            <h3>Áreas, campos e ações</h3>
            <p><strong>Protection flow</strong> reúne cenário, prompt, Action Proposal, Policy Decision, autorização, execução e verificação. <strong>Requested fields</strong> mostra os nomes solicitados; <strong>Allowed for egress</strong> mostra o subconjunto permitido; <strong>Removed before egress</strong> mostra o que foi minimizado; <strong>Trusted synthetic values</strong> mostra valores operacionais gerados pelo backend; e <strong>Protected egress payload</strong> mostra apenas valores normais elegíveis ao envio.</p>
            <p><strong>Authorize</strong> grava a conta autenticada em <strong>Authorized by</strong> e o instante persistido em <strong>Authorized at</strong>. <strong>Execute protected</strong> só aparece quando action, purpose, campos, private refs, destino, policy e autorização satisfazem o contrato fechado. <strong>Verify external state</strong> apenas relê o resultado externo; não repete o side effect.</p>
          </section>

          <section>
            <h3>Private data delivery</h3>
            <p>Para <code>notify-security</code>, a aplicação aceita somente o <strong>Logical private reference</strong> <code>verified_email</code>. Navegador, modelo, Spring e gateway não recebem o recipient em plaintext. O contrato Rust/WASM cria internamente o marker T3N correspondente e a resolução ocorre somente dentro de <strong>T3N protected egress</strong> para o destino aprovado. O plaintext pode existir transitoriamente no boundary de egress e no destinatário autorizado, mas não é retornado para a aplicação, audit trail ou evidence.</p>
            <p>O contrato exige <code>purpose=incident-notification</code>, os campos normais <code>incident_id</code>, <code>severity</code> e <code>summary</code>, e exatamente uma private ref <code>verified_email</code> ainda permitida pela policy. Placeholder literal, e-mail em plaintext, private ref adicional, destination diferente ou campo obrigatório removido falham fechado.</p>
            <p>HTTP 2xx significa apenas aceitação. A notificação só chega a <strong>COMPLETED</strong> quando o read-back retorna <strong>VERIFIED</strong>, estado <strong>DELIVERED</strong> e <code>recipient_resolved=true</code>. Sem os três sinais, o estado permanece PENDING_VERIFICATION ou UNVERIFIED e não ocorre reenvio automático.</p>
          </section>

          <section>
            <h3>Business Outcome</h3>
            <p>O painel deriva risco, ativo protegido, decisão, autorização, destino e resultado do mesmo estado retornado pelas APIs. Ausência de observação continua <strong>Not yet observed</strong>; ausência de conclusão verificável continua <strong>Not verified yet</strong>. DENY comprova bloqueio da proposta observada, ALLOW permite prosseguir sob as demais condições e COMPLETED exige read-back independente.</p>
            <p><strong>Time to policy decision</strong> = <code>decision.evaluatedAt - action.createdAt</code>. <strong>Time to verified outcome</strong> = <code>remediation.completedAt - action.createdAt</code> somente quando o estado é <strong>COMPLETED</strong>. A interface não calcula dinheiro economizado, breach evitado, redução percentual de risco, SLA ou ROI porque essas grandezas não são medidas pelo runtime.</p>
          </section>

          <section>
            <h3>Prompt, cenários e privacidade</h3>
            <p>Os cenários usam dados sintéticos e não concedem permissão. O prompt não deve conter PII, segredo ou credencial. O guard do gateway cobre classes estruturadas suportadas, mas um prompt aceito não significa <strong>PII-free</strong>, safe ou certificado. <strong>Analyze with agent</strong> e <strong>Ask agent for minimum proposal</strong> chamam o provider configurado; não criam ALLOW nem fallback de execução no frontend.</p>
          </section>

          <section>
            <h3>Identidade, Member grant e autorização efetiva</h3>
            <p>Tenant, Proposal Agent e Protected Executor usam identidades distintas. Proposal Agent possui somente a função necessária a <code>evaluate-action</code>; Protected Executor usa <code>execute-remediation</code> e <code>verify-remediation</code>. A DID canônica vem da sessão T3N autenticada.</p>
            <p><strong>Effective T3N access</strong> é obtido por <code>checkDelegation()</code> através do cliente autenticado do próprio principal. <strong>Confirmed</strong> exige <code>authorised=true</code>; <strong>Denied</strong> representa negativa observada; <strong>Unknown</strong> cobre erro, timeout ou resposta inconclusiva. Denied e Unknown falham fechado.</p>
            <p>A autorização humana pertence à conta autenticada da aplicação. A capability vincula hash do principal, timestamp persistido, action, decision, policy, payload, private refs, destination e Protected Executor. Outro operador não pode substituir silenciosamente uma autorização existente.</p>
          </section>

          <section>
            <h3>Readiness</h3>
            <p><strong>Proposal evaluation</strong> exige Tenant, Proposal Agent, contrato, Member grant ACTIVE e Effective T3N access Confirmed. <strong>Protected remediation</strong> exige também Protected Executor autenticado, grant ACTIVE e acesso efetivo confirmado. Por isso policy pode estar pronta enquanto execução continua bloqueada.</p>
          </section>

          <section>
            <h3>Agent Card e A2A público</h3>
            <p>Agent Card registra discoverability da Proposal Agent. O endpoint <strong>A2A</strong> expõe somente avaliação pública compatível com proposal + <code>evaluate-action</code>; A2A não expõe autorização humana, capability, payload operacional, <code>execute-remediation</code>, <code>verify-remediation</code> ou credencial do Executor. A2A configurado ou publicado não prova reachability nem delegated authority.</p>
          </section>

          <section>
            <h3>Policy, minimização e execução</h3>
            <p><strong>DENY</strong> bloqueia. <strong>REDACT</strong> só pode continuar quando o mínimo específico da ação sobrevive e o subconjunto reavaliado se torna ALLOW. Para revogação, o mínimo é <code>incident_id</code>, <code>credential_id</code> e <code>reason</code>. Para notificação, é <code>incident_id</code>, <code>severity</code>, <code>summary</code> e <code>verified_email</code> como referência lógica.</p>
            <p>O <strong>Approved destination</strong> é o hostname exato aprovado pelo humano. A URL completa e API key ficam em KV privado. Mudança de hostname após autorização produz <strong>EXECUTION_DESTINATION_CHANGED</strong> antes do HTTP e exige nova ação, avaliação e autorização.</p>
          </section>

          <section>
            <h3>Retenção e activity rail</h3>
            <p>Incidentes possuem <strong>expiresAt</strong> controlado pelo servidor. Execution Trace e Audit Trail mantêm metadados de execução, sem recipient plaintext. Trace ID identifica uma tentativa HTTP e Request ID identifica a operação lógica idempotente.</p>
          </section>

          <section>
            <h3>Integridade do audit local e T3N Activity Log</h3>
            <p>O audit local usa cadeia <strong>HMAC-SHA256</strong> e é <strong>tamper-evident</strong>, não tamper-proof. <strong>VERIFIED</strong> confirma cadeia e head; <strong>BROKEN</strong> indica divergência; <strong>KEY_MISMATCH</strong> indica versão de chave indisponível/incompatível; <strong>LEGACY_UNVERIFIED</strong> identifica eventos antigos sem autenticação retroativa. Um snapshot antigo internamente consistente não é declarado detectável sem âncora externa monotônica.</p>
            <p>O T3N Activity Log é provenance independente: <code>evaluate-action</code> deve apontar para o Proposal Agent, enquanto <code>execute-remediation</code> e <code>verify-remediation</code> devem apontar para o Protected Executor. Ator trocado nunca é promovido para Matched.</p>
          </section>

          <section>
            <h3>Proof &amp; evidence</h3>
            <p>Evidence summary mostra PASS, FAIL, NOT RUN, rede, <strong>Source tree</strong>, trust anchor, policy e horário. PASS exige resultado realmente observado; NOT RUN não conta como prova. O cenário <code>LIVE-PROFILE-PLACEHOLDER-RESOLUTION</code> permanece NOT RUN por padrão e só pode virar PASS em testnet quando <code>EVIDENCE_RUN_PROFILE_PLACEHOLDER=true</code> com perfil sintético verificado e endpoints controlados. O resultado persistido deve conter apenas ALLOW → PENDING_VERIFICATION → VERIFIED DELIVERED e <code>recipient_resolved=true</code>, nunca recipient plaintext ou marker bruto.</p>
          </section>

          <section>
            <h3>Fluxo principal</h3>
            <p>1. Verifique readiness. 2. Escolha o cenário sintético. 3. Analise com o agente. 4. Revise Action Proposal, campos, private refs e Approved destination. 5. Avalie a policy. 6. Se necessário, peça proposta mínima ao agente. 7. Autorize com a conta autenticada. 8. Execute pelo Protected Executor. 9. Verifique o estado externo. 10. Considere sucesso somente após COMPLETED sustentado pelo read-back esperado. 11. Revise Business Outcome, Execution Trace, Audit Trail e Evidence.</p>
          </section>

          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Falha de provider, T3N, grant, policy, executor ou verificação nunca é apresentada como sucesso. Destination changed exige nova avaliação/autorização. Missing operation id, timeout, read-back divergente ou <code>recipient_resolved</code> ausente/falso permanecem UNVERIFIED. Autorização legada sem provenance do operador exige reautorização. Sessão expirada exige novo login.</p>
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
