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
            <p id="screen-manual-purpose">Esta tela demonstra resposta a incidentes com separação explícita entre proposta de IA, identidade T3N, onboarding público do agente, autorização por delegação, autorização humana e execução por um principal T3N privilegiado separado. A IA pode propor, mas não pode conceder permissão a si mesma, obter a credencial do Protected Executor, alterar a policy ativa, obter valores privados diretamente nem declarar uma remediação crítica como concluída.</p>
          </section>
          <section>
            <h3>Áreas da tela</h3>
            <p><strong>Protection demo</strong> contém cenários, prompt, proposta, decisão, autorização humana, execução, retenção, Execution Trace e audit provenance. <strong>Proof &amp; evidence</strong> mostra somente resultados observados e metadados verificáveis. <strong>Show technical details</strong> expõe Tenant DID, Proposal Agent DID, Protected Executor DID, contrato, onboarding, Member grants, veredito efetivo da plataforma, hosts, scopes e funções sem misturar esses dados com a jornada principal.</p>
          </section>
          <section>
            <h3>Campos, cenários e ações</h3>
            <p>Os cards de cenário carregam prompts sintéticos e não concedem permissões. O campo de prompt aceita até 4.000 caracteres e não deve receber dados privados, credenciais ou segredos. <strong>Ask agent</strong> envia o prompt ao provedor configurado. <strong>Refresh status</strong>, <strong>Refresh evidence</strong> e <strong>Refresh provenance</strong> são leituras e não repetem uma remediação. Os controles de autorização e execução aparecem apenas quando existe executor suportado e decisão compatível.</p>
          </section>
          <section>
            <h3>Identidade, onboarding e autorização</h3>
            <p><strong>Authenticated</strong> significa que uma sessão T3N provou a identidade da chave e forneceu a DID canônica. O <strong>Proposal Agent</strong> é o principal usado para <code>evaluate-action</code>; ele não recebe grant para <code>execute-remediation</code> ou <code>verify-remediation</code>. O <strong>Protected Executor</strong> usa outra credencial e outra DID canônica, recebe somente as funções de execução/verificação e os hosts necessários, e não é usado pelo provedor de IA.</p>
            <p><strong>Registered</strong> significa que um Agent Card público válido foi resolvido para exatamente a mesma Proposal Agent DID. <strong>Card check</strong> é o momento da última tentativa de consulta e validação do Agent Card; esse timestamp também existe quando o resultado é <strong>NOT REGISTERED</strong>, <strong>CARD/DID MISMATCH</strong> ou <strong>UNAVAILABLE</strong> e, portanto, não representa verificação bem-sucedida. O Agent Card serve para descoberta pública e não concede autoridade sobre o contrato. <strong>Member grant</strong> continua independente do onboarding: é o registro observado no documento de delegação do data owner e representa a intenção/autorização gravada pelo Tenant para um principal específico, com funções, scopes, hosts e janela temporal.</p>
            <p><strong>Platform delegation</strong> é o veredito obtido por <code>checkDelegation()</code> usando a sessão autenticada do próprio Proposal Agent ou Protected Executor. O <code>pii_did</code> vem exclusivamente da sessão autenticada do Tenant, o contrato é o ID canônico resolvido pelo sistema e as funções/scopes vêm do Member grant observado. <strong>Authorized</strong> só aparece quando a T3N retorna <code>authorised=true</code>.</p>
            <p><strong>Effective access</strong> é o resultado operacional final. Ele fica <strong>ACTIVE</strong> somente quando o Member grant está ativo e a plataforma confirma a delegação. <strong>INCOMPLETE</strong> significa que o grant não basta para autorizar a operação; <strong>UNKNOWN</strong> significa que o veredito efetivo não pôde ser confirmado. Erro de rede, parsing, resposta inesperada, grant agendado, revogado ou ausente nunca são convertidos em sucesso. O sistema não é considerado operacional sem effective access ativo para os dois principais.</p>
            <p>O card público anuncia somente o serviço <strong>DID</strong> realmente suportado. Ele não contém API key, private key, token, endpoint interno, A2A, MCP ou x402. Os estados <strong>NOT REGISTERED</strong>, <strong>CARD/DID MISMATCH</strong> e <strong>UNAVAILABLE</strong> nunca são apresentados como sucesso. Um card divergente ou inválido não é aceito apenas por responder HTTP 200.</p>
          </section>
          <section>
            <h3>Policy e decisão</h3>
            <p><strong>DENY</strong> bloqueia. <strong>REDACT</strong> exige escopo menor. <strong>ALLOW</strong> permite continuar, mas não equivale a autorização humana nem execução. <strong>Policy version</strong> identifica o documento operacional versionado no T3N KV e <strong>Policy hash</strong> é o SHA-256 determinístico do documento canônico utilizado. Falha de leitura ou validação da policy fecha o fluxo em segurança.</p>
          </section>
          <section>
            <h3>Invariantes que a policy não pode relaxar</h3>
            <p>Regras críticas permanecem compiladas no WASM: limites de schema/tamanho, fail-closed, identidade T3N autenticada, classes de segredo proibidas, vocabulário de referências privadas e validação de hosts. O documento operacional não pode tornar API keys, tokens, senhas ou private keys válidos para egress nem contornar delegation.</p>
          </section>
          <section>
            <h3>Dados privados e retenção</h3>
            <p>A proposta contém somente ação, recurso, finalidade, host opcional, nomes de campos e referências privadas lógicas suportadas. Valores privados não passam pelo navegador nem pelo modelo. Título, resumo e origem do incidente são minimizados no servidor; literais sensíveis de alta confiança são rejeitados antes da persistência. Cada incidente recebe <strong>expiresAt</strong> controlado pelo servidor. Após expirar, deixa de ser retornado e o purge remove os registros relacionados na ordem segura.</p>
          </section>
          <section>
            <h3>Autorização humana e execução protegida</h3>
            <p>O fluxo completo atual é <code>revoke-credential</code>. <strong>Authorize credential revocation</strong> registra a decisão humana vinculada à decisão persistida e à policy version/hash; a capability de uso único inclui também a Protected Executor DID autenticada no momento da autorização. <strong>Execute protected credential revocation</strong> envia essa capability ao gateway, que rejeita troca de executor e usa a sessão T3N do Protected Executor. O Proposal Agent não possui grant T3N para essa função. A policy é revalidada antes do egress. Aceitação externa gera estado pendente; <strong>Verify external state</strong> faz read-back independente. <strong>COMPLETED</strong> só aparece após confirmação do estado esperado. Resultado ambíguo permanece <strong>UNVERIFIED</strong> e não é reenviado automaticamente.</p>
          </section>
          <section>
            <h3>Execution Trace</h3>
            <p><strong>Trace ID</strong> identifica uma tentativa HTTP e <strong>Request ID</strong> identifica a operação lógica idempotente. Retentativas recebem novo Trace ID sem mudar o Request ID. A linha do tempo guarda somente identificadores limitados, etapa, estado, motivo, timestamp e duração quando disponível; nunca guarda body bruto, headers, capabilities, chaves ou valores privados.</p>
          </section>
          <section>
            <h3>Audit provenance e T3N Activity Log</h3>
            <p>O audit local registra eventos de negócio sanitizados. O T3N Activity Log é uma segunda fonte read-only de provenance de rede. <strong>MATCHED</strong> exige correspondência exata de sequence/hash e identidade técnica esperada. <strong>UNMATCHED</strong> significa que havia provenance esperada sem confirmação exata. <strong>LOCAL ONLY</strong> é normal para eventos apenas da aplicação. <strong>T3N ONLY</strong> indica evento T3N relevante sem vínculo local. Uma janela truncada nunca é apresentada como prova de ausência. Eventos de avaliação devem identificar o Proposal Agent; eventos de execução/verificação devem identificar o Protected Executor.</p>
          </section>
          <section>
            <h3>Proof &amp; evidence</h3>
            <p><strong>PASS</strong> significa resultado observado compatível com o esperado. <strong>FAIL</strong> é divergência observada. <strong>NOT RUN</strong> não conta como prova. O bundle identifica rede, SDK, tenant DID, Proposal Agent DID, Protected Executor DID, Agent Card URI/hash/status, contrato, WASM SHA-256, policy version/hash e trust-manifest provenance. O cenário <strong>LIVE-PROPOSAL-CANNOT-EXECUTE</strong>, quando executado, deve provar que a própria Member Delegation T3N rejeita tentativa do Proposal Agent de chamar a função privilegiada. Agent Card prova onboarding público, não autorização nem attestation de hardware.</p>
          </section>
          <section>
            <h3>Permissões e regras</h3>
            <p>Login na aplicação não concede autoridade T3N. As DIDs do Tenant, Proposal Agent e Protected Executor vêm de sessões autenticadas, nunca de valores hardcoded. O Agent Card não concede funções. Member grant observado não equivale sozinho a effective access. O Proposal Agent só é tratado como autorizado quando sua própria sessão passa em <code>checkDelegation()</code>; o mesmo vale para o Protected Executor. A Proposal delegation não pode conter funções de remediação; a Executor delegation não deve ser usada pelo fluxo de proposta. Rotas internas usam service token. A interface não promove DENY/REDACT para execução, não inventa receipt T3N e não transforma indisponibilidade em sucesso.</p>
          </section>
          <section>
            <h3>Fluxo principal</h3>
            <p>1. Entre na aplicação. 2. Confira status de Tenant, Proposal Agent e Protected Executor. 3. Diferencie Agent Card, Member grant, Platform delegation e Effective access. 4. Confirme que os dois effective access estão ACTIVE antes de interpretar o control plane como pronto. 5. Escolha um cenário e revise o prompt. 6. Use Ask agent. 7. Inspecione a proposta real. 8. Leia a decisão T3N e sua policy version/hash. 9. Se houver ALLOW para revogação suportada, registre autorização humana. 10. Confirme que a autorização está vinculada ao Protected Executor. 11. Execute uma vez. 12. Verifique o estado externo. 13. Consulte Execution Trace, audit provenance e Proof &amp; evidence.</p>
          </section>
          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Conteúdo sensível é rejeitado sem ecoar o literal. Falha de provedor, T3N, Agent Card, policy KV, Proposal Agent, Protected Executor, <code>checkDelegation()</code> ou trust boundary não é apresentada como sucesso. Card ausente gera <strong>NOT REGISTERED</strong>; divergência de DID/schema gera <strong>CARD/DID MISMATCH</strong>; indisponibilidade de resolução gera <strong>UNAVAILABLE</strong>. Member grant <strong>SCHEDULED</strong>, <strong>REVOKED</strong> ou <strong>NOT GRANTED</strong> permanece não operacional. <code>authorised=false</code> resulta em effective access <strong>INCOMPLETE</strong>; erro ou resposta inválida resulta em <strong>UNKNOWN</strong>. Troca da Executor DID entre autorização e execução invalida a capability. Falha no Activity Log mantém o audit local disponível e marca a provenance de rede como não verificada. Mudança de policy após autorização bloqueia execução protegida. Sessão expirada exige novo login.</p>
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
