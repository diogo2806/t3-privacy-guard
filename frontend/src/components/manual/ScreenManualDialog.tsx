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
            <p id="screen-manual-purpose">Esta tela demonstra resposta a incidentes com separação explícita entre proposta de IA, valores operacionais confiáveis, identidade T3N, onboarding público, A2A de avaliação, Member Delegation, autorização T3N efetiva, autorização humana e execução por um Protected Executor separado. A hierarquia judge-first apresenta readiness, Trust Flow e Business Outcome antes dos detalhes técnicos. A IA escolhe ação e nomes de campos, mas não fornece os valores normais executados; esses valores sintéticos são gerados e persistidos pelo backend confiável e só chegam ao egress após minimização T3N.</p>
          </section>
          <section>
            <h3>Áreas, campos e ações</h3>
            <p><strong>Protection flow</strong> contém Business Outcome, cenário, prompt, proposta, decisão, próxima ação permitida, autorização humana, execução, retenção e activity rail. O <strong>Trust Flow</strong> resume AI, Policy, Human, Execute e Verify. <strong>Business Outcome</strong> traduz o mesmo estado em risco, ativo protegido, controle e resultado observado sem criar uma segunda state machine. Na remediação, <strong>Requested fields</strong> mostra o que o modelo solicitou; <strong>Allowed for egress</strong> mostra o subconjunto autorizado; <strong>Removed before egress</strong> mostra o que foi descartado; <strong>Trusted synthetic values</strong> são valores criados pelo backend; e <strong>Protected egress payload</strong> mostra somente os valores elegíveis para serialização. <strong>Evidence</strong> mantém summary, outcomes e provenance técnica.</p>
          </section>
          <section>
            <h3>Progressive disclosure e próxima ação</h3>
            <p>O resultado e a próxima ação aparecem antes da explicação longa. Cada etapa do Trust Flow possui um detalhe <strong>Why</strong> para contexto técnico. O retry de policy aparece dentro da etapa <strong>Policy</strong> apenas quando a ação está PENDING. Após um DENY no cenário de credencial comprometida, <strong>Ask agent for minimum proposal</strong> envia um segundo prompt sintético de escopo mínimo ao mesmo provider configurado, dentro do mesmo incidente. A resposta do modelo é persistida como nova proposta e volta ao T3N; o frontend não cria <code>revoke-credential</code>, não força ALLOW e não possui fallback seguro hardcoded.</p>
          </section>
          <section>
            <h3>Business Outcome</h3>
            <p>O painel <strong>Business Outcome</strong> responde, antes dos detalhes técnicos, qual risco empresarial foi apresentado, qual ativo está protegido, o que o agente pediu, qual decisão T3N foi observada, se houve autorização humana, qual destino foi efetivamente aprovado e se o estado externo foi verificado. O painel deriva esses fatos do incidente, Action Proposal, Policy Decision e Remediation Execution já retornados pelas APIs. Estado futuro nunca é preenchido: ausência de observação permanece <strong>Not yet observed</strong> e ausência de conclusão verificável permanece <strong>Not verified yet</strong>.</p>
            <p><strong>Risk</strong> e <strong>Protected asset</strong> são metadata de apresentação do cenário, não decisões de segurança. <strong>Policy decision</strong>, contagens de field names permitidos/redacted, destino, autorização, execução, verification attempts e final state vêm do estado observado. O Business Outcome continua tratando as contagens como <strong>field names</strong>; a prova de minimização por valor aparece no painel de remediação e na evidence específica. <strong>Approved destination</strong> só é apresentado como autorizado quando o status persistido da ação comprova autorização.</p>
            <p><strong>Time to policy decision</strong> é calculado como <code>decision.evaluatedAt - action.createdAt</code>. <strong>Time to verified outcome</strong> é calculado como <code>remediation.completedAt - action.createdAt</code> somente quando a remediação está <strong>COMPLETED</strong> e existe timestamp de conclusão. Abaixo de um segundo a interface mostra milissegundos inteiros; de um a sessenta segundos mostra segundos com uma casa decimal; acima disso mostra minutos e segundos. O sistema não calcula dinheiro economizado, breach evitado, redução percentual de risco, SLA ou ROI porque essas grandezas não são medidas pelo runtime.</p>
            <p>Um risco apresentado não equivale a um risco comprovadamente bloqueado. <strong>DENY</strong> comprova que a proposta observada foi bloqueada pelo controle antes do protected egress. <strong>REDACT</strong> exige escopo menor e pode continuar apenas quando o executor protegido consegue formar um mínimo válido que a policy reavalia como ALLOW. <strong>ALLOW</strong> permite continuar, mas ainda exige autorização humana quando aplicável. <strong>PENDING_VERIFICATION</strong> significa side effect aceito, não concluído. <strong>Verified final state</strong> só é sucesso após o read-back independente que sustenta <strong>COMPLETED</strong>. O Business Outcome não duplica Authorize, Execute ou Verify.</p>
          </section>
          <section>
            <h3>Prompt, cenários e privacidade</h3>
            <p>Os seletores de cenário carregam prompts sintéticos e não concedem permissões. O prompt aceita até 4.000 caracteres e não deve conter dados privados, credenciais ou segredos. <strong>Analyze with agent</strong> solicita análise/proposta estruturada ao modelo; o modelo pode escolher nomes de campos, mas não consegue fornecer ou sobrescrever <code>normal_payload</code>/<code>normalPayload</code>. <strong>Ask agent for minimum proposal</strong> também chama o provider real e apenas fornece um novo prompt de objetivo mínimo; provider/model, proposta e decisão permanecem observáveis separadamente no mesmo incidente. Antes de um provedor remoto, o gateway aplica um guard parcial de alta confiança para classes estruturadas suportadas, incluindo e-mail, CPF, CNPJ válido, telefone fortemente sinalizado, IP público rotulado como dado de cliente/usuário, tokens, senhas rotuladas, chave privada e candidato a cartão validado por Luhn. Um prompt aceito não significa <strong>PII-free</strong>, <strong>safe</strong> ou certificação equivalente.</p>
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
            <p><strong>Proposal evaluation</strong> fica pronta quando Tenant, Proposal Agent e contrato estão resolvidos, o Proposal Member grant está ACTIVE e seu Effective T3N access está Confirmed. <strong>Protected remediation</strong> exige adicionalmente Protected Executor autenticado, Member grant ACTIVE e Effective T3N access Confirmed. Por isso a avaliação pode estar pronta enquanto a execução continua bloqueada. O badge no Trust Flow mostra o resumo executivo; <strong>System readiness details</strong> mostra o diagnóstico técnico completo. Agent Card e A2A não alteram esses requisitos.</p>
          </section>
          <section>
            <h3>Agent Card e A2A público</h3>
            <p><strong>Registered</strong> significa que um Agent Card válido foi resolvido para a mesma Proposal Agent DID. <strong>Card check</strong> registra a última tentativa, inclusive em NOT REGISTERED, CARD/DID MISMATCH e UNAVAILABLE, portanto não significa sucesso. Quando <code>A2A_PUBLIC_URL</code> é uma URL HTTPS pública válida, o card pode anunciar o serviço <strong>A2A</strong>. <strong>A2A configured</strong> é configuração local; <strong>A2A published</strong> significa serviço observado no card resolvido. Nenhum desses estados prova reachability do endpoint.</p>
            <p>O endpoint A2A aceita somente avaliação pública compatível com o fluxo de proposta + <code>evaluate-action</code>. Ele não expõe autorização humana, capability, valores normais persistidos, <code>execute-remediation</code>, <code>verify-remediation</code> ou credencial do Protected Executor. Um resultado ALLOW via A2A continua sendo decisão de policy, não execução.</p>
          </section>
          <section>
            <h3>Policy, minimização, autorização humana e execução</h3>
            <p><strong>DENY</strong> bloqueia. <strong>REDACT</strong> significa que a policy removeu parte do pedido. Para revogação de credencial, REDACT só pode continuar quando <code>incident_id</code>, <code>credential_id</code> e <code>reason</code> permanecem em <strong>Allowed for egress</strong>; o contrato reavalia esse subconjunto e exige ALLOW antes do HTTP. <strong>Removed before egress</strong> nunca é copiado para o request externo.</p>
            <p>Os valores em <strong>Trusted synthetic values</strong> vêm do backend confiável e são persistidos junto da ação. A capability humana assina <code>normalPayloadHash</code> sobre um formato canônico do mapa, além de action/resource/purpose, campos, referências privadas, policy version/hash, Protected Executor DID e <strong>Approved destination</strong>. Alterar qualquer chave ou valor depois da autorização invalida a capability. Campo secreto, chave não solicitada, payload confiável ausente ou mínimo obrigatório removido falham fechado antes do protected HTTP.</p>
            <p><strong>Policy-allowed destination</strong> significa que um hostname pertence ao conjunto permitido pela policy. <strong>Approved destination</strong> é o hostname exato vinculado à autorização humana. A URL completa permanece no KV privado. <strong>Execute protected credential revocation</strong> exige correspondência do hostname, revalida a policy atual, monta o <strong>Protected egress payload</strong> somente com a interseção entre valores persistidos e <code>allowed_fields</code>, reavalia o conjunto mínimo e só então chama o endpoint externo. Aceitação externa não é conclusão; <strong>COMPLETED</strong> só aparece após read-back independente do estado esperado.</p>
          </section>
          <section>
            <h3>Retenção e activity rail</h3>
            <p>Incidentes recebem <strong>expiresAt</strong> controlado pelo servidor e deixam de ser retornados após expiração. O purge remove os registros dependentes, inclusive eventos de audit e o chain-head autenticado. <strong>Execution Trace</strong> e <strong>Audit Trail</strong> ficam na lateral em desktop e abaixo do fluxo em mobile. <strong>Trace ID</strong> identifica uma tentativa HTTP e <strong>Request ID</strong> identifica a operação lógica idempotente. O trace guarda somente metadados limitados.</p>
          </section>
          <section>
            <h3>Integridade do audit local e T3N Activity Log</h3>
            <p>O audit local registra eventos de negócio sanitizados em uma cadeia <strong>HMAC-SHA256</strong> por incidente. Cada evento autenticado contém sequência monotônica, MAC do evento anterior, MAC próprio, versão/key id e, quando aplicável, a sequence/hash/function de provenance T3N. Um chain-head também autenticado permite detectar alteração de conteúdo, reordenação, lacunas e remoção da cauda no estado retido.</p>
            <p>Esse controle é <strong>tamper-evident</strong>, não imutável nem tamper-proof. Ele detecta alterações no banco quando o atacante não possui a chave de integridade. Compromisso do backend/runtime junto da chave, comprometimento simultâneo de banco e chave, ou restauração completa de um snapshot antigo internamente consistente não são transformados em uma claim de detecção sem uma âncora externa monotônica.</p>
            <p><strong>VERIFIED</strong> significa que cadeia, sequência, links, MACs e head foram verificados. <strong>BROKEN</strong> indica divergência/lacuna e bloqueia mudanças protegidas. <strong>KEY_MISMATCH</strong> significa que uma versão de chave necessária não está disponível ou não confirma a cadeia. <strong>LEGACY_UNVERIFIED</strong> identifica eventos anteriores à proteção HMAC; eles continuam visíveis, mas nunca são retroativamente apresentados como autenticados. O bootstrap automático de legado fica desativado.</p>
            <p>O <strong>T3N Activity Log</strong> é uma segunda fonte independente de provenance. Um <strong>Matched</strong> exige sequence, hash, contrato, função e ator canônico exatos: <code>evaluate-action</code> deve identificar o Proposal Agent; <code>execute-remediation</code> e <code>verify-remediation</code> devem identificar o Protected Executor. Ator trocado nunca é promovido para Matched. Se uma identidade canônica estiver indisponível, os eventos continuam observáveis, mas as operações afetadas permanecem sem provenance confirmada. Integridade local VERIFIED não fabrica MATCHED, e indisponibilidade do Activity Log não transforma a cadeia local em BROKEN.</p>
          </section>
          <section>
            <h3>Proof &amp; evidence</h3>
            <p><strong>Evidence summary</strong> mostra primeiro os totais PASS/FAIL/NOT RUN, rede, Source tree, Trust anchor, policy version e horário da geração. <strong>Observed outcomes</strong> vem em seguida e mantém cada status textual explícito, com nome legível e ID técnico para rastreabilidade. <strong>Technical provenance</strong> agrupa Source &amp; build, Trust &amp; network, Identities &amp; discoverability e Contract &amp; policy em detalhes expansíveis, onde ficam DIDs, hashes, Agent Card, A2A, contrato e WASM.</p>
            <p><strong>PASS</strong> significa resultado observado compatível com o esperado. <strong>FAIL</strong> é divergência observada. <strong>NOT RUN</strong> nunca conta como prova nem como PASS. <code>LIVE-AI-MINIMUM-REMEDIATION</code> só passa quando o provider/model configurado realmente produz a proposta mínima esperada e essa saída exata recebe T3N ALLOW; com AI desabilitada permanece NOT RUN. O cenário opcional <code>LIVE-NORMAL-PAYLOAD-MINIMIZATION</code> é testnet-only e passa somente quando um read-back controlado informa <code>must_egress_seen=true</code> e <code>must_not_egress_seen=false</code>. Os sentinelas brutos não retornam no bundle. <strong>CLEAN</strong> é sinal de reprodutibilidade do working tree, não auditoria independente.</p>
            <p>A evidence de autorização registra somente Member state, Effective state e funções/scopes efetivamente consultados para Proposal e Executor. Não persiste grant completo, <code>satisfied</code>, <code>missing</code>, tokens, credenciais ou payload operacional bruto. O live orchestrator falha antes dos cenários se qualquer principal necessário não estiver ACTIVE/Confirmed.</p>
          </section>
          <section>
            <h3>Fluxo principal</h3>
            <p>1. Entre na aplicação. 2. Leia readiness, <strong>Current result</strong> e <strong>Business Outcome</strong>. 3. Escolha o cenário e revise o prompt. 4. Use <strong>Analyze with agent</strong>. 5. Volte ao Business Outcome para conferir risco/controle observado. 6. Após DENY em credencial comprometida, use <strong>Ask agent for minimum proposal</strong>; confira provider/model e a segunda Action Proposal persistida. 7. Se a nova decisão continuar DENY/REDACT não executável ou vier outra ação, pare sem fallback. 8. Em <code>revoke-credential</code> permitido, compare <strong>Requested fields</strong>, <strong>Allowed for egress</strong> e <strong>Removed before egress</strong>. 9. Confira <strong>Trusted synthetic values</strong> e <strong>Protected egress payload</strong>. 10. Registre autorização humana quando exigida. 11. Execute pelo Protected Executor. 12. Verifique o estado externo e confirme que Business Outcome só mostra resultado verificado após read-back. 13. Em Evidence, leia summary e outcomes antes da provenance técnica.</p>
          </section>
          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Falha do provider na primeira ou na segunda proposta não cria Action Proposal sintética de fallback. Falha de T3N, Agent Card, A2A, policy KV, Proposal Agent, Protected Executor, <code>checkDelegation()</code> ou trust boundary nunca é apresentada como sucesso. <code>authorised=false</code> resulta em Denied; erro ou resposta inválida resulta em Unknown. Uma segunda proposta DENY, REDACT não executável ou de ação sem executor protegido permanece visível e bloqueada. <strong>REDACT</strong> só é executável quando o mínimo obrigatório sobrevive e o subconjunto reavaliado vira ALLOW. Payload confiável ausente, chave não solicitada, campo secreto ou valor alterado após autorização falha fechado. <strong>Destination changed</strong> exige nova ação, avaliação e autorização. Aceitação sem read-back permanece pendente ou UNVERIFIED. <strong>Audit integrity broken</strong> bloqueia mudanças protegidas. Prompt rejeitado informa somente a categoria detectada, sem ecoar valor ou offset. Sessão expirada exige novo login.</p>
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