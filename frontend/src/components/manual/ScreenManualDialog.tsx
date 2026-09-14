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
            <p id="screen-manual-purpose">Esta tela demonstra resposta a incidentes com separação entre proposta de IA, policy T3N, autorização humana, Protected Executor, execução protegida, verificação independente e evidence. <strong>Protection flow</strong> opera o fluxo, <strong>Executive demo</strong> comunica o mesmo estado runtime em formato compacto e <strong>Evidence</strong> mostra a prova técnica. O modelo escolhe ação e nomes de campos, mas não fornece os valores normais executados.</p>
          </section>
          <section>
            <h3>Áreas, campos e ações</h3>
            <p><strong>Protection flow</strong> contém Business Outcome, cenário, prompt, proposta, decisão, próxima ação permitida, autorização humana, execução, retenção e activity rail. <strong>Trust Flow</strong> resume AI, Policy, Human, Execute e Verify. <strong>Enterprise integration</strong> mostra se execução, verificação, policy e delegation formam configuração coerente sem realizar egress. <strong>Requested fields</strong>, <strong>Allowed for egress</strong>, <strong>Removed before egress</strong>, <strong>Trusted synthetic values</strong> e <strong>Protected egress payload</strong> explicam a minimização. <strong>Authorized by</strong> e <strong>Authorized at</strong> mostram a aprovação persistida. <strong>One-time authorization proof</strong>, <strong>Gateway proof check</strong> e <strong>T3N execution proof check</strong> tornam visível a separação entre autorização humana e identidade do Executor sem exibir o token.</p>
          </section>
          <section>
            <h3>Executive Demo</h3>
            <p>A aba <strong>Executive demo</strong> é uma projeção do mesmo estado runtime; não cria incidente, decisão, autorização, execução ou evidence paralela. Antes de análise aparece <strong>NOT YET OBSERVED</strong>. DENY resulta em <strong>BLOCKED BEFORE PROTECTED EGRESS</strong>, REDACT em <strong>MINIMIZATION REQUIRED</strong> e ALLOW sem aprovação em <strong>HUMAN AUTHORIZATION REQUIRED</strong>. Aprovação sem side effect permanece <strong>AUTHORIZED / NOT EXECUTED</strong>; PENDING_VERIFICATION permanece <strong>ACCEPTED / NOT VERIFIED</strong>. UNVERIFIED e FAILED nunca são apresentados como sucesso.</p>
            <p><strong>Proof at a glance</strong> não substitui o Evidence Center. <strong>T3N LIVE / READY</strong> exige protected remediation ready, Enterprise integration READY, evidence válida e zero FAIL. A Executive Demo não possui botões de Analyze, Authorize, Execute ou Verify; <strong>Open technical evidence</strong> apenas muda de aba.</p>
          </section>
          <section>
            <h3>Business Outcome</h3>
            <p>Business Outcome deriva risco, ativo, ação, policy, autorização, execução e verificação do estado observado. Ausência de observação permanece <strong>Not yet observed</strong> e ausência de conclusão verificável permanece <strong>Not verified yet</strong>. <strong>Time to policy decision</strong> = <code>decision.evaluatedAt - action.createdAt</code>. <strong>Time to verified outcome</strong> = <code>remediation.completedAt - action.createdAt</code> apenas em COMPLETED. O sistema não calcula dinheiro economizado, breach evitado, SLA ou ROI.</p>
          </section>
          <section>
            <h3>Prompt, cenários e privacidade</h3>
            <p>Os cenários usam prompts sintéticos. Analyze with agent e Ask agent for minimum proposal chamam o provider configurado sem conceder permissões. O guard de prompt cobre classes estruturadas suportadas, mas um prompt aceito não significa <strong>PII-free</strong>, safe ou certificação equivalente. Valores privados e segredos não devem ser inseridos no prompt.</p>
          </section>
          <section>
            <h3>Identidade, Member grant e autorização efetiva</h3>
            <p>Tenant, Proposal Agent e Protected Executor são principais distintos. Proposal usa <code>evaluate-action</code>; Executor usa <code>execute-remediation</code> e <code>verify-remediation</code>. <strong>Effective T3N access</strong> vem de <code>checkDelegation()</code> pelo cliente autenticado do próprio principal. <strong>Confirmed</strong> exige authorised=true; <strong>Denied</strong> representa authorised=false; <strong>Unknown</strong> representa erro ou resposta inconclusiva e sempre falha fechado.</p>
          </section>
          <section>
            <h3>Readiness</h3>
            <p><strong>Proposal evaluation</strong> exige Tenant, Proposal e contrato resolvidos, Member grant ACTIVE e effective access confirmado. <strong>Protected remediation</strong> exige adicionalmente Executor autenticado, grant ACTIVE e effective access confirmado. Enterprise integration READY é separada e não prova saúde, reachability ou sucesso do serviço externo.</p>
          </section>
          <section>
            <h3>Agent Card e A2A público</h3>
            <p>O A2A expõe somente avaliação pública compatível com Proposal + evaluate-action. Não expõe autorização humana, prova one-time, valores normais, execute-remediation, verify-remediation ou credencial do Executor. A2A configurado/publicado não prova reachability.</p>
          </section>
          <section>
            <h3>Policy, minimização, autorização humana e execução</h3>
            <p>DENY bloqueia. REDACT só pode continuar quando o mínimo obrigatório sobrevive e o subconjunto reavaliado vira ALLOW. Removed before egress nunca é copiado para o request externo.</p>
            <p>Após a autorização humana, o backend emite na execução uma prova <strong>v2</strong> one-time assinada com <strong>Ed25519</strong>. Ela vincula normalPayloadHash, action/resource/purpose, campos, referências privadas, policy version/hash, Protected Executor DID, destino aprovado, hash do principal autenticado, timestamp da autorização, issued/expiry e nonce. A chave privada permanece no backend; gateway e contrato recebem somente material público de verificação. Não existe downgrade silencioso para o formato legado.</p>
            <p><strong>Human authorization</strong> registra o principal autenticado da aplicação, não identidade civil nem DID T3N do humano. A prova não envia o username; vincula o SHA-256 do principal canônico e o timestamp persistido. Autorizações legadas sem provenance exigem <strong>REAUTHORIZATION REQUIRED</strong>.</p>
            <p><strong>Gateway proof check</strong> é fail-fast e não substitui T3N. O gateway encaminha a mesma prova para <code>execute-remediation</code>. Antes de ler <code>security_api_url</code>, <code>security_api_key</code> ou iniciar HTTP, o WASM verifica assinatura, key id, expiração, claims e consome o nonce em KV privado. Executor credential sem prova, prova expirada/tampered, request diferente ou nonce reutilizado falham fechado. A interface não afirma que T3N verificou identidade civil do humano; T3N verifica a prova assinada emitida pelo backend após autenticação e autorização.</p>
            <p><strong>Execute protected credential revocation</strong> exige Executor autorizado + prova válida, destino aprovado, policy atual compatível, payload minimizado e reavaliação ALLOW. Aceitação externa não é conclusão; <strong>COMPLETED</strong> só aparece após read-back independente.</p>
          </section>
          <section>
            <h3>Integridade do audit local e T3N Activity Log</h3>
            <p>O audit local usa <strong>HMAC-SHA256</strong> e é <strong>tamper-evident</strong>, não imutável. <strong>VERIFIED</strong>, <strong>BROKEN</strong>, <strong>KEY_MISMATCH</strong> e <strong>LEGACY_UNVERIFIED</strong> são estados distintos. Um snapshot antigo internamente consistente não é alegado como detectável sem âncora externa monotônica.</p>
            <p>No T3N Activity Log, evaluate-action deve identificar o Proposal Agent; execute-remediation e verify-remediation devem identificar o Protected Executor. Integridade local não fabrica provenance T3N.</p>
          </section>
          <section>
            <h3>Proof &amp; evidence</h3>
            <p>Evidence summary mostra PASS/FAIL/NOT RUN, rede, <strong>Source tree</strong>, trust anchor, policy e horário. PASS exige observação compatível; NOT RUN não conta como prova. A evidence não publica username, e-mail, hash do operador, prova assinada, nonce nem chave privada. O fingerprint da chave pública pode ser metadata não secreta. <strong>COMPLETED</strong> continua dependente de verificação independente.</p>
          </section>
          <section>
            <h3>Fluxo principal</h3>
            <p>1. Leia readiness e Enterprise integration. 2. Use Executive demo apenas para apresentação. 3. No Protection flow, escolha cenário e Analyze with agent. 4. Revise proposal, policy e minimização. 5. Em ALLOW/REDACT executável, registre Human authorization. 6. Confirme Protected Executor. 7. Execute e observe One-time authorization proof, Gateway proof check e T3N execution proof check sem revelar o token. 8. Verifique o estado externo. 9. Somente após read-back aceite COMPLETED. 10. Em Evidence, confira summary, outcomes e provenance.</p>
          </section>
          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Falha de provider, T3N, Agent Card, A2A, policy KV, delegation ou trust boundary nunca é apresentada como sucesso. Prova humana ausente, expirada, assinatura inválida, key id inválido, body/Executor incompatível ou nonce já consumido falha fechado antes do protected egress. REAUTHORIZATION REQUIRED exige nova aprovação explícita. Destination changed exige nova ação, avaliação e autorização. Aceitação sem read-back permanece PENDING_VERIFICATION ou UNVERIFIED. Audit integrity broken bloqueia mudanças protegidas. Evidence ausente permanece Live evidence not loaded/generated.</p>
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
