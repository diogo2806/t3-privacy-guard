import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { BookOpen, X } from 'lucide-react';

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
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

  const close = () => {
    setOpen(false);
    requestAnimationFrame(() => triggerRef.current?.focus());
  };

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
      if (event.key === 'Escape') {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== 'Tab') return;

      const focusable = focusableElements(dialog);
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (
        focusable.length === 1
        || !dialog.contains(active)
        || (event.shiftKey && active === first)
        || (!event.shiftKey && active === last)
      ) {
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
      <section
        ref={dialogRef}
        tabIndex={-1}
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="screen-manual-title"
        aria-describedby="screen-manual-purpose"
      >
        <div className="modal-header">
          <div>
            <p className="eyebrow">Manual da Tela</p>
            <h2 id="screen-manual-title">Incident Response Dashboard</h2>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            className="icon-button"
            aria-label="Close Screen Manual"
            title="Close Screen Manual"
            onClick={close}
          >
            <X aria-hidden="true" />
          </button>
        </div>

        <div className="manual-content">
          <section>
            <h3>Finalidade</h3>
            <p id="screen-manual-purpose">Esta tela demonstra resposta a incidentes com separação entre proposta de IA, identidade T3N, onboarding público, Member Delegation, autorização T3N efetiva, autorização humana e execução protegida. A IA pode propor ações, mas não pode conceder permissão a si mesma, assumir a identidade do Protected Executor, alterar a policy ativa, obter valores privados diretamente nem declarar remediação crítica como concluída.</p>
          </section>

          <section>
            <h3>Áreas, botões e filtros</h3>
            <p><strong>Protection demo</strong> reúne cenários, prompt, proposta, decisão, autorização humana, execução, retenção, Execution Trace e audit provenance. <strong>Proof &amp; evidence</strong> mostra somente resultados observados e metadados verificáveis. <strong>Show technical details</strong> apresenta DIDs, contrato, onboarding, Member grants, autorização efetiva, funções, scopes e hosts. <strong>Refresh status</strong>, <strong>Refresh evidence</strong> e <strong>Refresh provenance</strong> apenas atualizam leituras; não repetem remediações.</p>
          </section>

          <section>
            <h3>Prompt, cenários e dados privados</h3>
            <p>Os cenários carregam prompts sintéticos e não concedem permissões. O prompt aceita até 4.000 caracteres e não deve conter dados privados, credenciais ou segredos. Antes de chamar um provedor remoto, o gateway aplica um guard pre-provider deliberadamente parcial para classes estruturadas de alta confiança, incluindo e-mail, CPF, CNPJ com checksum válido, telefone fortemente sinalizado, IP público rotulado como dado de cliente/usuário, tokens, senhas rotuladas, chaves privadas e candidatos a cartão validados por Luhn. Um prompt aceito não significa <strong>PII-free</strong>, <strong>safe</strong> nem certificação equivalente.</p>
          </section>

          <section>
            <h3>Identidade, Member grant e autorização efetiva</h3>
            <p><strong>Authenticated</strong> significa que a sessão T3N provou a identidade da chave e forneceu a DID canônica. O <strong>Proposal Agent</strong> é usado somente para <code>evaluate-action</code>. O <strong>Protected Executor</strong> usa outra credencial e outra DID para <code>execute-remediation</code> e <code>verify-remediation</code>. As três DIDs técnicas, Tenant, Proposal e Executor, devem permanecer distintas.</p>
            <p><strong>Member grant</strong> é o estado observado no documento de Member Delegation do Tenant. Ele informa existência, janela temporal, funções, scopes e hosts, mas não prova sozinho que a operação será autorizada. <strong>Effective T3N access</strong> é verificado separadamente com <code>checkDelegation()</code> pelo cliente autenticado do próprio principal, usando o contrato resolvido, a Tenant DID canônica e os requisitos mínimos fixos da função. Proposal consulta somente <code>evaluate-action</code>; Executor consulta somente <code>execute-remediation</code> e <code>verify-remediation</code>. Wildcards não são aceitos.</p>
            <p><strong>Confirmed</strong> exige <code>authorised=true</code>. <strong>Denied</strong> representa <code>authorised=false</code>. <strong>Unknown</strong> representa erro, timeout ou resposta inconclusiva. Denied e Unknown falham fechado. Grant <strong>SCHEDULED</strong>, <strong>REVOKED</strong>, <strong>NOT GRANTED</strong> ou inválido nunca é promovido a autorização efetiva ativa.</p>
          </section>

          <section>
            <h3>Readiness e permissões</h3>
            <p><strong>Proposal evaluation</strong> fica pronta somente quando Tenant, Proposal Agent e contrato estão resolvidos e o Proposal possui Member grant ativo com Effective T3N access confirmado. <strong>Protected remediation</strong> exige adicionalmente Protected Executor autenticado e Effective T3N access confirmado. Assim, a avaliação pode estar disponível enquanto a execução protegida permanece bloqueada. Agent Card, Member grant e Effective T3N access são estados independentes.</p>
          </section>

          <section>
            <h3>Agent Card</h3>
            <p><strong>Registered</strong> significa que um Agent Card público válido foi resolvido para a mesma Proposal Agent DID. <strong>Card check</strong> registra a última tentativa de consulta, inclusive em estados <strong>NOT REGISTERED</strong>, <strong>CARD/DID MISMATCH</strong> e <strong>UNAVAILABLE</strong>; portanto, o timestamp não significa sucesso. O card anuncia apenas o serviço realmente suportado e não concede funções, scopes, hosts ou autorização de negócio.</p>
          </section>

          <section>
            <h3>Policy e decisão</h3>
            <p><strong>DENY</strong> bloqueia. <strong>REDACT</strong> exige escopo menor. <strong>ALLOW</strong> permite continuar, mas não equivale a autorização humana nem execução. <strong>Policy version</strong> e <strong>Policy hash</strong> identificam a policy operacional efetivamente usada. Falha de leitura ou validação fecha o fluxo em segurança.</p>
          </section>

          <section>
            <h3>Autorização humana e execução protegida</h3>
            <p>O fluxo completo atual suporta <code>revoke-credential</code>. <strong>Authorize credential revocation</strong> registra a decisão humana e vincula a capability à decisão persistida, à policy version/hash e à Protected Executor DID. <strong>Execute protected credential revocation</strong> usa a sessão do Executor e rejeita troca de identidade. Aceitação externa não significa conclusão. <strong>Verify external state</strong> faz read-back independente, e <strong>COMPLETED</strong> só aparece após confirmação do estado esperado. Resultado ambíguo permanece <strong>UNVERIFIED</strong> e não é reenviado automaticamente.</p>
          </section>

          <section>
            <h3>Retenção, trace e auditoria</h3>
            <p>Incidentes recebem <strong>expiresAt</strong> controlado pelo servidor e deixam de ser retornados após expiração. <strong>Trace ID</strong> identifica uma tentativa HTTP; <strong>Request ID</strong> identifica a operação lógica idempotente. O trace guarda apenas metadados limitados. O audit local registra eventos de negócio sanitizados e o T3N Activity Log fornece uma segunda fonte read-only de provenance. Eventos de avaliação devem identificar o Proposal Agent; execução e verificação devem identificar o Protected Executor.</p>
          </section>

          <section>
            <h3>Proof &amp; evidence</h3>
            <p><strong>PASS</strong> significa resultado observado compatível com o esperado. <strong>FAIL</strong> é divergência observada. <strong>NOT RUN</strong> não conta como prova. O bundle live registra <strong>Source commit</strong> como SHA Git completo e <strong>Source tree</strong> como CLEAN ou DIRTY, além de rede, SDK, DIDs, contrato, WASM SHA-256, policy version/hash e trust-manifest provenance. CLEAN informa apenas que a árvore estava sem alterações quando a geração começou; não significa auditoria independente.</p>
            <p>A evidência de autorização registra de forma sanitizada Member state, Effective state e as funções/scopes exatos consultados para Proposal e Executor. O bundle não persiste o documento completo de grant, tokens, API keys ou credenciais. A geração falha se qualquer principal necessário não estiver efetivamente autorizado.</p>
          </section>

          <section>
            <h3>Fluxo principal</h3>
            <p>1. Entre na aplicação. 2. Confira Tenant, Proposal Agent e Protected Executor. 3. Diferencie Agent Card, Member grant e Effective T3N access. 4. Confirme Proposal evaluation antes de avaliar. 5. Para remediação, confirme também Protected remediation. 6. Escolha o cenário e revise o prompt. 7. Use Ask agent. 8. Inspecione proposta e decisão. 9. Registre autorização humana quando aplicável. 10. Execute uma vez pelo Protected Executor. 11. Verifique o estado externo. 12. Consulte Execution Trace, audit provenance e Proof &amp; evidence.</p>
          </section>

          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Falha de provedor, T3N, Agent Card, policy KV, Proposal Agent, Protected Executor, <code>checkDelegation()</code> ou trust boundary nunca é apresentada como sucesso. <code>authorised=false</code> resulta em <strong>Denied</strong>; erro ou resposta inválida resulta em <strong>Unknown</strong>. Troca da Executor DID invalida a capability. Mudança de policy após autorização bloqueia execução protegida. Prompt rejeitado pelo guard informa apenas a categoria detectada, sem ecoar o valor ou offset. Sessão expirada exige novo login.</p>
          </section>
        </div>
      </section>
    </div>,
    document.body,
  ) : null;

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className="button button-secondary manual-trigger"
        aria-label="Open Screen Manual"
        title="Manual da Tela / Screen Manual"
        onClick={() => setOpen(true)}
      >
        <BookOpen aria-hidden="true" />
        <span>Manual da Tela</span>
      </button>
      {dialog}
    </>
  );
}
