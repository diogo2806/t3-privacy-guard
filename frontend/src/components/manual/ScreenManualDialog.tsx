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
            <p id="screen-manual-purpose">Esta tela demonstra resposta a incidentes com separação explícita entre proposta de IA, identidade T3N, onboarding público, interoperabilidade A2A de avaliação, autorização por delegação, autorização humana, execução protegida, integridade do audit local e provenance T3N. A IA ou um cliente A2A pode solicitar avaliação, mas não pode conceder permissão a si mesmo, obter a credencial do Protected Executor, alterar a policy ativa, obter valores privados diretamente nem declarar uma remediação crítica como concluída.</p>
          </section>
          <section>
            <h3>Áreas da tela</h3>
            <p><strong>Protection demo</strong> contém cenários, prompt, proposta, decisão, autorização humana, execução, retenção, Execution Trace, integridade local e provenance T3N. <strong>Proof &amp; evidence</strong> mostra somente resultados observados e metadados verificáveis. <strong>Show technical details</strong> expõe Tenant DID, Proposal Agent DID, Protected Executor DID, contrato, onboarding, A2A configurado/publicado, Member grants, veredito efetivo da plataforma, hosts, scopes e funções sem misturar esses dados com a jornada principal.</p>
          </section>
          <section>
            <h3>Campos, cenários e ações</h3>
            <p>Os cards de cenário carregam prompts sintéticos e não concedem permissões. O prompt aceita até 4.000 caracteres e não deve receber dados privados, credenciais ou segredos. <strong>Ask agent</strong> envia o texto ao provedor configurado somente após os guards suportados. <strong>Refresh status</strong>, <strong>Refresh evidence</strong> e <strong>Refresh audit evidence</strong> são leituras e não repetem remediação. Os controles de autorização e execução aparecem somente quando a ação possui executor suportado e a decisão permite continuar.</p>
          </section>
          <section>
            <h3>Identidade, onboarding e autorização</h3>
            <p><strong>Authenticated</strong> significa que uma sessão T3N provou a identidade da chave e forneceu a DID canônica. O <strong>Proposal Agent</strong> é usado para <code>evaluate-action</code>; não recebe grant para <code>execute-remediation</code> nem <code>verify-remediation</code>. O <strong>Protected Executor</strong> usa outra credencial/DID e recebe somente execução, verificação e hosts mínimos.</p>
            <p><strong>Registered</strong> significa que um Agent Card público válido foi resolvido para a mesma Proposal Agent DID. O Agent Card é discovery, não autorização. <strong>Member grant</strong> representa o grant observado com funções, scopes, hosts e janela temporal. <strong>Platform delegation</strong> é o resultado de <code>checkDelegation()</code> pela sessão autenticada do próprio principal. <strong>Effective access ACTIVE</strong> só existe quando grant e veredito efetivo são compatíveis; <strong>INCOMPLETE</strong> e <strong>UNKNOWN</strong> falham fechado.</p>
            <p>O card público sempre anuncia <strong>DID</strong>. Quando <code>A2A_PUBLIC_URL</code> contém HTTPS público válido, pode anunciar também <strong>A2A</strong> apontando para o discovery correspondente. O card não contém API key, private key, token, endpoint interno, MCP ou x402. <strong>NOT REGISTERED</strong>, <strong>CARD/DID MISMATCH</strong> e <strong>UNAVAILABLE</strong> não são sucesso.</p>
          </section>
          <section>
            <h3>A2A público</h3>
            <p><strong>A2A configured</strong> informa somente que existe <code>A2A_PUBLIC_URL</code> válida. <strong>A2A published</strong> informa que o Agent Card resolvido anunciou o serviço esperado. Esses estados não provam reachability externa. O endpoint aceita somente A2A v1.0 por JSON-RPC <code>SendMessage</code>, mensagem textual limitada e o header oficial <code>A2A-Version</code>. Campos de autoridade controlados pelo cliente, payload oversized e prompts sensíveis suportados são rejeitados.</p>
            <p>A2A reutiliza o mesmo fluxo de proposta e <code>evaluate-action</code>. A resposta pode conter proposta estruturada e provenance mínima da decisão, mas não expõe capability, credencial, autorização humana, <code>execute-remediation</code>, <code>verify-remediation</code> ou Protected Executor. <strong>ALLOW</strong> via A2A continua sendo apenas decisão de policy.</p>
          </section>
          <section>
            <h3>Policy e decisão</h3>
            <p><strong>DENY</strong> bloqueia. <strong>REDACT</strong> exige escopo menor. <strong>ALLOW</strong> permite continuar, mas não equivale a autorização humana nem execução. <strong>Policy version</strong> identifica o documento operacional versionado no T3N KV e <strong>Policy hash</strong> é o SHA-256 determinístico do documento canônico utilizado. Falha de leitura ou validação fecha o fluxo em segurança.</p>
          </section>
          <section>
            <h3>Invariantes que a policy não pode relaxar</h3>
            <p>Regras críticas permanecem compiladas no WASM: limites de schema/tamanho, fail-closed, identidade T3N autenticada, classes de segredo proibidas, vocabulário de referências privadas e validação de hosts. O documento operacional não pode tornar API keys, tokens, senhas ou private keys válidos para egress nem contornar delegation.</p>
          </section>
          <section>
            <h3>Dados privados e retenção</h3>
            <p>A proposta contém somente ação, recurso, finalidade, host opcional, nomes de campos e referências privadas lógicas suportadas. <code>verified_email</code> é resolvido somente no boundary protegido. O guard de prompt é parcial e não deve ser interpretado como scanner exaustivo de PII. Título, resumo e origem do incidente são minimizados no servidor. Cada incidente recebe <strong>expiresAt</strong> controlado pelo servidor; após expirar, deixa de ser retornado e o purge remove os registros relacionados, inclusive eventos e chain-head do audit local. A retenção não mantém uma âncora HMAC indefinidamente.</p>
          </section>
          <section>
            <h3>Autorização humana e execução protegida</h3>
            <p>O fluxo completo atual é <code>revoke-credential</code>. <strong>Authorize credential revocation</strong> exige decisão ALLOW versionada e audit local verificável antes de persistir autorização. A capability de uso único inclui a Protected Executor DID autenticada. <strong>Execute protected credential revocation</strong> valida novamente a integridade local antes do egress. <strong>Verify external state</strong> também falha fechado se a cadeia local estiver quebrada. <strong>COMPLETED</strong> só aparece após read-back independente confirmar o estado esperado; resultado ambíguo permanece <strong>UNVERIFIED</strong> sem reexecução automática.</p>
          </section>
          <section>
            <h3>Execution Trace</h3>
            <p><strong>Trace ID</strong> identifica uma tentativa HTTP e <strong>Request ID</strong> identifica a operação lógica idempotente. Retentativas recebem novo Trace ID sem mudar o Request ID. A linha do tempo guarda somente identificadores limitados, etapa, estado, motivo, timestamp e duração quando disponível; nunca guarda body bruto, headers, capabilities, chaves ou valores privados.</p>
          </section>
          <section>
            <h3>Integridade do audit local e T3N Activity Log</h3>
            <p>O audit local registra eventos sanitizados em uma cadeia <strong>HMAC-SHA256 por incidente</strong>. Cada evento autenticado inclui sequência monotônica, vínculo com o MAC anterior e os metadados T3N persistidos; um chain-head também autenticado permite detectar exclusão da cauda. A chave HMAC é uma credencial de runtime independente e nunca aparece na API ou DOM. O mecanismo é <strong>tamper-evident</strong>: detecta adulterações verificáveis no armazenamento retido, mas não torna o H2 imutável e não substitui fonte externa independente.</p>
            <p><strong>VERIFIED</strong> significa que conteúdo, ordem, links, MACs e chain-head foram verificados. <strong>BROKEN</strong> significa divergência/lacuna e bloqueia mudanças protegidas. <strong>KEY_MISMATCH</strong> informa que uma versão de chave necessária não está disponível ou não confirma a cadeia. <strong>LEGACY_UNVERIFIED</strong> identifica eventos anteriores à proteção HMAC; eles não são retroativamente promovidos a autenticados. Criar uma nova raiz sobre legado exige bootstrap explícito e fica desativado no fluxo normal.</p>
            <p>O <strong>T3N Activity Log</strong> é uma segunda fonte read-only. <strong>MATCHED</strong> exige sequence/hash e identidade técnica exatos. <strong>UNMATCHED</strong> significa provenance esperada sem confirmação exata. <strong>LOCAL ONLY</strong> é normal para eventos apenas da aplicação. <strong>T3N ONLY</strong> indica evento T3N relevante sem vínculo local. Integridade local VERIFIED não fabrica MATCHED, e indisponibilidade T3N não transforma a cadeia local em BROKEN.</p>
          </section>
          <section>
            <h3>Proof &amp; evidence</h3>
            <p><strong>PASS</strong> significa resultado observado compatível com o esperado. <strong>FAIL</strong> é divergência. <strong>NOT RUN</strong> não conta como prova. O bundle identifica <strong>Source commit</strong>, <strong>Source tree</strong> CLEAN/DIRTY, rede, SDK, DIDs, Agent Card, serviços observados no card, contrato, WASM SHA-256, policy version/hash e trust-manifest provenance. O source commit liga a execução à revisão pública, mas não substitui hashes de WASM/policy nem auditoria independente. <strong>A2A OBSERVED</strong> significa apenas que o card resolvido anunciou A2A; não prova reachability.</p>
          </section>
          <section>
            <h3>Permissões e regras</h3>
            <p>Login na aplicação não concede autoridade T3N. DIDs vêm de sessões autenticadas. Agent Card e A2A não concedem funções. Member grant sozinho não equivale a effective access. A2A aceita avaliação somente e não cria caminho alternativo para autorização humana ou execução. A chave de integridade do audit deve ser diferente do service token, da capability de remediação e da senha do operador. A interface não promove DENY/REDACT para execução, não inventa receipt T3N, não chama HMAC local de imutável e não transforma indisponibilidade em sucesso.</p>
          </section>
          <section>
            <h3>Fluxo principal</h3>
            <p>1. Entre na aplicação. 2. Confira Tenant, Proposal Agent e Protected Executor. 3. Diferencie Agent Card, A2A configurado/publicado, Member grant, Platform delegation e Effective access. 4. Escolha um cenário e revise o prompt. 5. Use Ask agent. 6. Inspecione proposta e decisão T3N com policy version/hash. 7. Confira integridade local separadamente da provenance T3N. 8. Se houver ALLOW para revogação suportada e audit verificável, registre autorização humana. 9. Execute uma vez. 10. Verifique o estado externo. 11. Consulte Execution Trace, integridade local, T3N provenance e Proof &amp; evidence. A2A pode reproduzir somente proposta + avaliação, nunca autorização ou execução.</p>
          </section>
          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Falha de provedor, T3N, Agent Card, A2A, policy KV, delegation ou trust boundary não é apresentada como sucesso. Requisição A2A inválida, versão incorreta, rate limit, prompt sensível e body oversized retornam erro sanitizado. Grant <strong>SCHEDULED</strong>, <strong>REVOKED</strong> ou <strong>NOT GRANTED</strong> não é operacional. <code>authorised=false</code> resulta em effective access <strong>INCOMPLETE</strong>; erro/inconclusão resulta em <strong>UNKNOWN</strong>. <strong>BROKEN</strong> ou <strong>KEY_MISMATCH</strong> no audit local bloqueia mudanças protegidas e nunca é reparado automaticamente; <strong>LEGACY_UNVERIFIED</strong> permanece explicitamente não verificado até bootstrap/migração autorizada. Falha no Activity Log mantém o audit local visível e apenas marca a provenance T3N como não verificada. Sessão expirada exige novo login.</p>
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
