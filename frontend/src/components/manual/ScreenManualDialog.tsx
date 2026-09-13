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
            <p id="screen-manual-purpose">Esta tela demonstra resposta a incidentes com separação explícita entre proposta de IA, identidade T3N, onboarding público, A2A de avaliação, Member Delegation, autorização T3N efetiva, autorização humana, proof criptográfico de uso único e execução por um Protected Executor separado. A credencial do Executor, isoladamente, não autoriza remediação: o mesmo proof humano Ed25519 precisa ser aceito primeiro no gateway e novamente dentro de <code>execute-remediation</code> no contrato T3N antes de segredos protegidos ou egress ficarem disponíveis. IA ou cliente A2A podem solicitar proposta/avaliação, mas não podem conceder permissão a si mesmos, obter credenciais do Executor, fabricar proof humano, alterar policy, acessar valores privados diretamente nem declarar remediação como concluída.</p>
          </section>
          <section>
            <h3>Áreas, campos e ações</h3>
            <p><strong>Protection flow</strong> contém cenário, prompt, proposta, decisão, próxima ação permitida, autorização humana, proof de uso único, execução, retenção e activity rail. <strong>Evidence</strong> começa com resumo executivo e outcomes observados, deixando hashes, DIDs e provenance técnica em grupos expansíveis. O <strong>Trust Flow</strong> no topo resume AI, Policy, Human, Execute e Verify. <strong>System readiness details</strong> expande o diagnóstico completo sem criar uma segunda fonte de estado. <strong>Refresh status</strong>, <strong>Refresh evidence</strong> e <strong>Refresh audit evidence</strong> são leituras e não repetem remediações.</p>
          </section>
          <section>
            <h3>Progressive disclosure e próxima ação</h3>
            <p>O resultado e a próxima ação aparecem antes da explicação longa. Cada etapa do Trust Flow possui um detalhe <strong>Why</strong> para contexto técnico. O retry de policy aparece dentro da etapa <strong>Policy</strong> apenas quando a ação está PENDING. Após um DENY no cenário de credencial comprometida, <strong>Try the safe path</strong> oferece preparar uma revogação de escopo mínimo; preparar não autoriza nem executa. Autorização, emissão do proof, execução e verificação continuam condicionadas ao estado real do backend.</p>
          </section>
          <section>
            <h3>Prompt, cenários e privacidade</h3>
            <p>Os seletores de cenário carregam prompts sintéticos e não concedem permissões. O prompt aceita até 4.000 caracteres e não deve conter dados privados, credenciais ou segredos. <strong>Analyze with agent</strong> solicita análise/proposta estruturada ao modelo; não promete que a policy permitirá continuação. Antes de um provedor remoto, o gateway aplica um guard parcial de alta confiança para classes estruturadas suportadas, incluindo e-mail, CPF, CNPJ válido, telefone fortemente sinalizado, IP público rotulado como dado de cliente/usuário, tokens, senhas rotuladas, chave privada e candidato a cartão validado por Luhn. Um prompt aceito não significa <strong>PII-free</strong>, <strong>safe</strong> ou certificação equivalente.</p>
          </section>
          <section>
            <h3>Identidade, Member grant e autorização efetiva</h3>
            <p><strong>Authenticated</strong> significa que a sessão T3N provou a identidade e forneceu a DID canônica. Proposal Agent usa somente <code>evaluate-action</code>. Protected Executor usa outra credencial/DID para <code>execute-remediation</code> e <code>verify-remediation</code>. Tenant, Proposal e Executor devem permanecer distintos. A DID do Executor é vinculada ao proof e também conferida no contrato contra o caller T3N observado; possuir a credencial do Executor não substitui o proof humano.</p>
            <p><strong>Member grant</strong> é o registro observado no documento de delegação do Tenant. Ele informa principal, contrato, janela, funções, scopes e hosts, mas sozinho não prova que uma operação concreta será autorizada. Quando o grant não está <strong>ACTIVE</strong>, o runtime não executa um check positivo artificial: <strong>SCHEDULED</strong>, <strong>REVOKED</strong> e <strong>NOT GRANTED</strong> falham fechado; estado ilegível permanece <strong>UNKNOWN</strong>.</p>
            <p><strong>Effective T3N access</strong> é obtido por <code>checkDelegation()</code> através do cliente autenticado do próprio principal, nunca pelo Tenant. O <code>pii_did</code> vem da sessão autenticada do Tenant e o contrato é o ID canônico resolvido. Proposal verifica exatamente <code>evaluate-action</code>; Executor verifica exatamente <code>execute-remediation</code> e <code>verify-remediation</code>; ambos usam apenas os scopes mínimos <code>incident_id</code>, <code>credential_id</code> e <code>reason</code>. Wildcards não são aceitos. As restrições observadas no grant são diagnóstico e não definem o pedido efetivo.</p>
            <p><strong>Confirmed</strong> exige <code>authorised=true</code>. <strong>Denied</strong> representa <code>authorised=false</code>. <strong>Unknown</strong> representa erro, timeout ou resposta inconclusiva. Denied e Unknown sempre falham fechado.</p>
          </section>
          <section>
            <h3>Readiness</h3>
            <p><strong>Proposal evaluation</strong> fica pronta quando Tenant, Proposal Agent e contrato estão resolvidos, o Proposal Member grant está ACTIVE e seu Effective T3N access está Confirmed. <strong>Protected remediation</strong> exige adicionalmente Protected Executor autenticado, Member grant ACTIVE e Effective T3N access Confirmed. Esses sinais são pré-requisitos, não substitutos do proof humano de uso único. Por isso a avaliação pode estar pronta enquanto a execução continua bloqueada. O badge no Trust Flow mostra o resumo executivo; <strong>System readiness details</strong> mostra o diagnóstico técnico completo. Agent Card e A2A não alteram esses requisitos.</p>
          </section>
          <section>
            <h3>Agent Card e A2A público</h3>
            <p><strong>Registered</strong> significa que um Agent Card válido foi resolvido para a mesma Proposal Agent DID. <strong>Card check</strong> registra a última tentativa, inclusive em NOT REGISTERED, CARD/DID MISMATCH e UNAVAILABLE, portanto não significa sucesso. Quando <code>A2A_PUBLIC_URL</code> é uma URL HTTPS pública válida, o card pode anunciar o serviço <strong>A2A</strong>. <strong>A2A configured</strong> é configuração local; <strong>A2A published</strong> significa serviço observado no card resolvido. Nenhum desses estados prova reachability do endpoint.</p>
            <p>O endpoint A2A aceita somente avaliação pública compatível com o fluxo de proposta + <code>evaluate-action</code>. Ele não expõe autorização humana, proof de autorização, <code>execute-remediation</code>, <code>verify-remediation</code> ou credencial do Protected Executor. Um resultado ALLOW via A2A continua sendo decisão de policy, não execução.</p>
          </section>
          <section>
            <h3>Policy, autorização humana e execução</h3>
            <p><strong>DENY</strong> bloqueia. <strong>REDACT</strong> exige minimização. <strong>ALLOW</strong> permite continuar, mas não equivale a autorização humana. <strong>Policy-allowed destination</strong> significa apenas que um hostname pertence ao conjunto permitido pela policy. <strong>Approved destination</strong> é o hostname exato exibido na proposta e vinculado à autorização humana. A policy pode permitir vários destinos, mas a aprovação humana vale somente para o destino exato mostrado. Antes de registrar <strong>Authorize credential revocation</strong>, executar ou verificar uma remediação protegida, o backend exige que a cadeia local autenticada continue verificável.</p>
            <p>Na execução, somente o backend possui a chave privada Ed25519 e emite um proof <strong>v2</strong> curto e de uso único. O proof vincula key id, incident/action/request/decision, action/resource/purpose, hashes dos campos e referências privadas, policy version/hash, Protected Executor DID, Approved destination, timestamps e nonce. A chave privada nunca é enviada ao gateway nem ao T3N; gateway e contrato recebem somente a chave pública associada ao key id ativo. O gateway verifica assinatura, TTL, binding e replay local como fail-fast e encaminha o mesmo proof, sem convertê-lo em um booleano confiável.</p>
            <p>Dentro de <code>execute-remediation</code>, o contrato T3N verifica novamente versão, assinatura Ed25519, key id ativo, relógio do cluster, TTL, binding integral, DID do caller e nonce antes de ler URL/API key protegidas ou permitir egress. O nonce é consumido no KV privado do próprio contrato; replay falha fechado. Prova ausente, expirada, alterada, vinculada a outro corpo, outro Executor ou key id inativo também falha fechado. Rotação troca key id e chave pública ativa; não existe fallback silencioso de v2 para formatos antigos. A interface nunca exibe o token nem a chave privada.</p>
            <p><strong>Execute protected credential revocation</strong> usa a sessão do Executor, lê a URL completa somente do KV privado e exige que o hostname resolvido continue igual ao Approved destination antes de qualquer egress; depois revalida a policy atual. Se o destino mudar, a execução falha fechado e uma nova avaliação e autorização são obrigatórias. Aceitação externa não é conclusão. <strong>Verify external state</strong> realiza read-back independente; o host de verificação é provenance técnica separada e não substitui o Approved destination do side effect. <strong>COMPLETED</strong> só aparece após o estado esperado ser confirmado. Resultado ambíguo permanece <strong>UNVERIFIED</strong> e não é reenviado automaticamente.</p>
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
            <h3>Evidence</h3>
            <p><strong>Evidence summary</strong> mostra primeiro os totais PASS/FAIL/NOT RUN, rede, Source tree, Trust anchor, policy version e horário da geração. <strong>Observed outcomes</strong> vem em seguida e mantém cada status textual explícito, com nome legível e ID técnico para rastreabilidade. <strong>Technical provenance</strong> agrupa Source &amp; build, Trust &amp; network, Identities &amp; discoverability e Contract &amp; policy em detalhes expansíveis, onde ficam DIDs, hashes, Agent Card, A2A, contrato e WASM.</p>
            <p><strong>PASS</strong> significa resultado observado compatível com o esperado. <strong>FAIL</strong> é divergência observada. <strong>NOT RUN</strong> nunca conta como prova nem como PASS. <strong>CLEAN</strong> é sinal de reprodutibilidade do working tree, não auditoria independente. <strong>Trust anchor VERIFIED</strong> é provenance de confiança e não hardware attestation por request. Agent Card/A2A provam discoverability observada, não delegated authority nem reachability pública por si só.</p>
            <p><strong>LIVE-EXECUTOR-REQUIRES-HUMAN-PROOF</strong> usa a credencial e DID reais do Protected Executor no T3N testnet e tenta <code>execute-remediation</code> sem proof humano; PASS exige rejeição dentro do boundary protegido antes do egress. O runner adversarial não recebe a chave privada e, por isso, não fabrica uma prova positiva. O caminho positivo é coletado pelo fluxo autenticado backend/UI, que emite o proof legítimo somente no momento da execução. A evidence não persiste proof, grant completo, <code>satisfied</code>, <code>missing</code>, tokens ou credenciais.</p>
          </section>
          <section>
            <h3>Fluxo principal</h3>
            <p>1. Entre na aplicação. 2. Leia o readiness e o <strong>Current result</strong> no Trust Flow. 3. Abra <strong>System readiness details</strong> quando precisar diagnosticar Tenant, Proposal Agent, Protected Executor, grants ou acesso efetivo. 4. Em <strong>Protection flow</strong>, escolha o cenário e revise o prompt. 5. Use <strong>Analyze with agent</strong>. 6. Inspecione proposta, decisão e <strong>Approved destination</strong>. 7. Se houver DENY no cenário de credencial comprometida, use <strong>Prepare safe path</strong> para criar somente a proposta mínima. 8. Se a policy estiver PENDING, use o retry dentro da etapa Policy. 9. Em ALLOW, registre autorização humana quando exigida. 10. Confirme novamente Approved destination e Protected Executor DID; ao executar, confira separadamente <strong>One-time authorization proof</strong>, <strong>Gateway proof check</strong> e <strong>T3N contract proof check</strong>. 11. Verifique o estado externo. 12. Em <strong>Evidence</strong>, leia summary e outcomes antes de abrir provenance técnica. A2A pode reproduzir somente a etapa pública de proposta/avaliação.</p>
          </section>
          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Falha de provedor, T3N, Agent Card, A2A, policy KV, Proposal Agent, Protected Executor, <code>checkDelegation()</code> ou trust boundary nunca é apresentada como sucesso. <code>authorised=false</code> resulta em Denied; erro ou resposta inválida resulta em Unknown. <strong>Audit integrity broken</strong> bloqueia mudanças protegidas; chave histórica ausente é exibida como KEY_MISMATCH e não como VERIFIED. Troca da Executor DID, alteração do corpo autorizado, expiração, assinatura inválida, replay do nonce ou rotação para outro key id invalidam o proof. Mudança de policy após autorização bloqueia execução. <strong>Destination changed</strong> significa que o hostname configurado no KV privado deixou de corresponder ao Approved destination vinculado à autorização humana; o contrato bloqueia antes do egress e a interface orienta criar/reavaliar e autorizar novamente a ação. Host ausente ou enviado como URL, porta, path ou credencial também falha fechado. Prompt rejeitado informa somente a categoria detectada, sem ecoar valor ou offset. Sessão expirada exige novo login.</p>
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
