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
            <p id="screen-manual-purpose">Esta tela demonstra resposta a incidentes com separação explícita entre proposta de IA, identidade T3N, onboarding público, A2A de avaliação, Member Delegation, autorização T3N efetiva, autorização humana e execução por um Protected Executor separado. IA ou cliente A2A podem solicitar proposta/avaliação, mas não podem conceder permissão a si mesmos, obter credenciais do Executor, alterar policy, acessar valores privados diretamente nem declarar remediação como concluída.</p>
          </section>
          <section>
            <h3>Áreas, campos e ações</h3>
            <p><strong>Protection demo</strong> contém cenários, prompt, proposta, decisão, autorização humana, execução, retenção, Execution Trace e audit provenance. <strong>Proof &amp; evidence</strong> mostra resultados observados e metadados verificáveis. <strong>Show technical details</strong> apresenta Tenant DID, Proposal Agent DID, Protected Executor DID, contrato, Agent Card, A2A, Member grants e Effective T3N access. <strong>Refresh status</strong>, <strong>Refresh evidence</strong> e <strong>Refresh provenance</strong> são leituras e não repetem remediações.</p>
          </section>
          <section>
            <h3>Prompt, cenários e privacidade</h3>
            <p>Os cards carregam prompts sintéticos e não concedem permissões. O prompt aceita até 4.000 caracteres e não deve conter dados privados, credenciais ou segredos. Antes de um provedor remoto, o gateway aplica um guard parcial de alta confiança para classes estruturadas suportadas, incluindo e-mail, CPF, CNPJ válido, telefone fortemente sinalizado, IP público rotulado como dado de cliente/usuário, tokens, senhas rotuladas, chave privada e candidato a cartão validado por Luhn. Um prompt aceito não significa <strong>PII-free</strong>, <strong>safe</strong> ou certificação equivalente.</p>
          </section>
          <section>
            <h3>Identidade, Member grant e autorização efetiva</h3>
            <p><strong>Authenticated</strong> significa que a sessão T3N provou a identidade e forneceu a DID canônica. Proposal Agent usa somente <code>evaluate-action</code>. Protected Executor usa outra credencial/DID para <code>execute-remediation</code> e <code>verify-remediation</code>. Tenant, Proposal e Executor devem permanecer distintos.</p>
            <p><strong>Member grant</strong> é o registro observado no documento de delegação do Tenant. Ele informa principal, contrato, janela, funções, scopes e hosts, mas sozinho não prova que uma operação concreta será autorizada. Quando o grant não está <strong>ACTIVE</strong>, o runtime não executa um check positivo artificial: <strong>SCHEDULED</strong>, <strong>REVOKED</strong> e <strong>NOT GRANTED</strong> falham fechado; estado ilegível permanece <strong>UNKNOWN</strong>.</p>
            <p><strong>Effective T3N access</strong> é obtido por <code>checkDelegation()</code> através do cliente autenticado do próprio principal, nunca pelo Tenant. O <code>pii_did</code> vem da sessão autenticada do Tenant e o contrato é o ID canônico resolvido. Proposal verifica exatamente <code>evaluate-action</code>; Executor verifica exatamente <code>execute-remediation</code> e <code>verify-remediation</code>; ambos usam apenas os scopes mínimos <code>incident_id</code>, <code>credential_id</code> e <code>reason</code>. Wildcards não são aceitos. As restrições observadas no grant são diagnóstico e não definem o pedido efetivo.</p>
            <p><strong>Confirmed</strong> exige <code>authorised=true</code>. <strong>Denied</strong> representa <code>authorised=false</code>. <strong>Unknown</strong> representa erro, timeout ou resposta inconclusiva. Denied e Unknown sempre falham fechado.</p>
          </section>
          <section>
            <h3>Readiness</h3>
            <p><strong>Proposal evaluation</strong> fica pronta quando Tenant, Proposal Agent e contrato estão resolvidos, o Proposal Member grant está ACTIVE e seu Effective T3N access está Confirmed. <strong>Protected remediation</strong> exige adicionalmente Protected Executor autenticado, Member grant ACTIVE e Effective T3N access Confirmed. Por isso a avaliação pode estar pronta enquanto a execução continua bloqueada. Agent Card e A2A não alteram esses requisitos.</p>
          </section>
          <section>
            <h3>Agent Card e A2A público</h3>
            <p><strong>Registered</strong> significa que um Agent Card válido foi resolvido para a mesma Proposal Agent DID. <strong>Card check</strong> registra a última tentativa, inclusive em NOT REGISTERED, CARD/DID MISMATCH e UNAVAILABLE, portanto não significa sucesso. Quando <code>A2A_PUBLIC_URL</code> é uma URL HTTPS pública válida, o card pode anunciar o serviço <strong>A2A</strong>. <strong>A2A configured</strong> é configuração local; <strong>A2A published</strong> significa serviço observado no card resolvido. Nenhum desses estados prova reachability do endpoint.</p>
            <p>O endpoint A2A aceita somente avaliação pública compatível com o fluxo de proposta + <code>evaluate-action</code>. Ele não expõe autorização humana, capability, <code>execute-remediation</code>, <code>verify-remediation</code> ou credencial do Protected Executor. Um resultado ALLOW via A2A continua sendo decisão de policy, não execução.</p>
          </section>
          <section>
            <h3>Policy, autorização humana e execução</h3>
            <p><strong>DENY</strong> bloqueia. <strong>REDACT</strong> exige minimização. <strong>ALLOW</strong> permite continuar, mas não equivale a autorização humana. <strong>Authorize credential revocation</strong> registra a decisão humana vinculada à policy version/hash e à Protected Executor DID. <strong>Execute protected credential revocation</strong> usa a sessão do Executor e rejeita troca de identidade. Aceitação externa não é conclusão. <strong>Verify external state</strong> realiza read-back independente e <strong>COMPLETED</strong> só aparece após o estado esperado ser confirmado. Resultado ambíguo permanece <strong>UNVERIFIED</strong> e não é reenviado automaticamente.</p>
          </section>
          <section>
            <h3>Retenção, trace e auditoria</h3>
            <p>Incidentes recebem <strong>expiresAt</strong> controlado pelo servidor e deixam de ser retornados após expiração. <strong>Trace ID</strong> identifica uma tentativa HTTP e <strong>Request ID</strong> identifica a operação lógica idempotente. O trace guarda somente metadados limitados. O audit local e o T3N Activity Log são fontes independentes de provenance. Eventos de avaliação devem identificar o Proposal Agent; execução e verificação devem identificar o Protected Executor.</p>
          </section>
          <section>
            <h3>Proof &amp; evidence</h3>
            <p><strong>PASS</strong> significa resultado observado compatível com o esperado. <strong>FAIL</strong> é divergência observada. <strong>NOT RUN</strong> não conta como prova. O bundle registra <strong>Source commit</strong> como SHA Git completo e <strong>Source tree</strong> como CLEAN ou DIRTY, além de rede, SDK, DIDs, Agent Card/services, contrato, WASM SHA-256, policy version/hash e trust provenance. CLEAN é sinal de reprodutibilidade, não auditoria independente.</p>
            <p>A evidence de autorização registra somente Member state, Effective state e funções/scopes efetivamente consultados para Proposal e Executor. Não persiste grant completo, <code>satisfied</code>, <code>missing</code>, tokens ou credenciais. O live orchestrator falha antes dos cenários se qualquer principal necessário não estiver ACTIVE/Confirmed. Nos negativos, Proposal e Executor são revogados separadamente, o SDK precisa retornar <code>authorised=false</code> para o principal afetado e o grant mínimo é restaurado em <code>finally</code>.</p>
          </section>
          <section>
            <h3>Fluxo principal</h3>
            <p>1. Entre na aplicação. 2. Confira Tenant, Proposal Agent e Protected Executor. 3. Diferencie Agent Card/A2A, Member grant e Effective T3N access. 4. Confirme Proposal evaluation antes de avaliar. 5. Para remediação, confirme também Protected remediation. 6. Escolha o cenário e revise o prompt. 7. Use Ask agent. 8. Inspecione proposta e decisão. 9. Registre autorização humana quando aplicável. 10. Execute pelo Protected Executor. 11. Verifique o estado externo. 12. Consulte Execution Trace, audit provenance e Proof &amp; evidence. A2A pode reproduzir somente a etapa pública de proposta/avaliação.</p>
          </section>
          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Falha de provedor, T3N, Agent Card, A2A, policy KV, Proposal Agent, Protected Executor, <code>checkDelegation()</code> ou trust boundary nunca é apresentada como sucesso. <code>authorised=false</code> resulta em Denied; erro ou resposta inválida resulta em Unknown. Troca da Executor DID invalida a capability. Mudança de policy após autorização bloqueia execução. Prompt rejeitado informa somente a categoria detectada, sem ecoar valor ou offset. Sessão expirada exige novo login.</p>
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
