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
      if (previousAriaHidden === null || previousAriaHidden === undefined) appRoot?.removeAttribute('aria-hidden');
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
            <p id="screen-manual-purpose">Esta tela demonstra resposta a incidentes com separação entre proposta de IA, policy T3N, autorização humana, Protected Executor, execução protegida, verificação independente e evidence. <strong>Protection flow</strong> opera o fluxo e inclui o <strong>Incident workspace</strong> para retomar qualquer incidente ativo, inclusive sinais recebidos de integrações empresariais autenticadas, sem transformar o cenário demonstrativo em identidade do caso. A entrada M2M cria somente o incidente minimizado e nunca avalia policy, autoriza, executa ou verifica remediação automaticamente. <strong>Executive demo</strong> comunica o mesmo estado runtime em formato compacto, <strong>Measured control impact</strong> agrega resultados persistidos dentro da retenção e <strong>Evidence</strong> mostra a prova técnica. O modelo escolhe ação e nomes de campos, mas não fornece os valores normais executados. Dados privados suportados permanecem referências lógicas até a resolução dentro do protected execution.</p>
          </section>
          <section>
            <h3>Áreas, campos e ações</h3>
            <p><strong>Protection flow</strong> contém Business Outcome, Measured control impact, Incident workspace, cenário, prompt, proposta, decisão, próxima ação permitida, autorização humana, execução, retenção e activity rail. O workspace mostra severidade, tipo de origem, fonte, horário de recebimento, estado operacional e <strong>Next action</strong> para cada incidente ativo; o filtro <strong>All / External / Demo</strong> altera somente a visualização e clicar em uma linha apenas abre o caso. <strong>Trust Flow</strong> resume AI, Policy, Human, Execute e Verify. <strong>Enterprise integration</strong> mostra se execução, verificação, policy e delegation formam configuração coerente sem realizar egress. <strong>Requested fields</strong>, <strong>Allowed for egress</strong>, <strong>Removed before egress</strong>, <strong>Trusted synthetic values</strong> e <strong>Protected egress payload</strong> explicam a minimização. Para notificação, <strong>Logical private reference</strong> mostra somente <code>verified_email</code>, <strong>Resolution boundary</strong> mostra T3N PROTECTED EXECUTION e <strong>Plaintext visible to app</strong> permanece NO. <strong>Authorized by</strong>, <strong>Authorized at</strong> e <strong>Execution principal</strong> mostram a provenance humana persistida. <strong>One-time authorization proof</strong>, <strong>Gateway proof check</strong> e <strong>T3N execution proof check</strong> tornam visível a separação entre autorização humana e identidade do Executor sem exibir o token.</p>
          </section>
          <section>
            <h3>Acesso e permissões humanas</h3>
            <p>A sessão mostra o principal autenticado, suas autoridades e se <strong>Enterprise SoD</strong> está ativo. <strong>ANALYST</strong> cria incidentes, solicita análise, registra propostas e avalia policy. <strong>APPROVER</strong> registra a autorização humana. <strong>EXECUTOR</strong> executa e verifica a remediação protegida. <strong>AUDITOR</strong> é somente leitura e pode consultar estado, histórico, trace, métricas agregadas, workspace e evidence.</p>
            <p>As permissões são validadas pelo backend; esconder um botão no navegador não concede nem revoga autoridade. Abrir um incidente pelo workspace é leitura/navegação e não autoriza, executa nem verifica nada. Em modo enterprise, o mesmo principal que autorizou não pode executar nem verificar a mesma remediação, mesmo que possua múltiplas autoridades. Em modo local/demo, uma única conta configurada pode receber todas as autoridades sem ser apresentada como IAM enterprise.</p>
          </section>
          <section>
            <h3>Executive Demo</h3>
            <p>A aba <strong>Executive demo</strong> é uma projeção do mesmo estado runtime; não cria incidente, decisão, autorização, execução ou evidence paralela. A leitura é deliberadamente organizada como <strong>problema empresarial → resultado observado → impacto operacional medido → mecanismo de autoridade → prova técnica</strong>. A headline explica primeiro que agentes de IA podem participar de workflows sensíveis sem receber autoridade de segurança sobre dados privados, decisões de policy ou ações críticas. A tese <strong>AI can propose. Policy decides. Humans authorize. T3N executes.</strong> permanece na seção <strong>Trust path</strong> para explicar o mecanismo depois que o valor já foi entendido. Antes de análise aparece <strong>NOT YET OBSERVED</strong>. DENY resulta em <strong>BLOCKED BEFORE PROTECTED EGRESS</strong>, REDACT em <strong>MINIMIZATION REQUIRED</strong> e ALLOW sem aprovação em <strong>HUMAN AUTHORIZATION REQUIRED</strong>. Aprovação sem side effect permanece <strong>AUTHORIZED / NOT EXECUTED</strong>; PENDING_VERIFICATION permanece <strong>ACCEPTED / NOT VERIFIED</strong>. UNVERIFIED e FAILED nunca são apresentados como sucesso.</p>
            <p><strong>Measured control impact</strong> aparece como uma projeção compacta de quatro valores já calculados pelo backend: blocked, minimized, verified e median decision. Ele não cria uma segunda fonte de cálculo. <strong>Proof at a glance</strong> não substitui o Evidence Center. <strong>T3N LIVE / READY</strong> exige protected remediation ready, Enterprise integration READY, evidence válida e zero FAIL. <strong>Enterprise integration</strong> e <strong>Agent registration</strong> aparecem no resumo como fatos independentes observados em <code>SystemStatus</code>; ausência de estado aparece como <strong>NOT OBSERVED</strong>. <strong>REGISTERED</strong> descreve apenas o estado público observado do Agent Card e não concede autorização; <strong>READY</strong> de integração não prova reachability nem sucesso de serviço externo. A Executive Demo não possui botões de Analyze, Authorize, Execute ou Verify; <strong>Open technical evidence</strong> apenas muda de aba. Quando um incidente persistido é retomado pelo workspace e não existe vínculo de cenário armazenado, a Executive Demo diz <strong>Persisted incident</strong> e não inventa Business risk ou Protected asset a partir do cenário demo atualmente selecionado. A tela não converte métricas operacionais em dinheiro economizado, breach evitado, compliance garantido ou percentual de redução de risco.</p>
          </section>
          <section>
            <h3>Business Outcome</h3>
            <p>Business Outcome deriva risco, ativo, ação, policy, autorização, execução e verificação do estado observado. Ausência de observação permanece <strong>Not yet observed</strong> e ausência de conclusão verificável permanece <strong>Not verified yet</strong>. <strong>Time to policy decision</strong> = <code>decision.evaluatedAt - action.createdAt</code>. <strong>Time to verified outcome</strong> = <code>remediation.completedAt - action.createdAt</code> apenas em COMPLETED. O sistema não calcula dinheiro economizado, breach evitado, SLA ou ROI. Para notificação, COMPLETED exige read-back <strong>DELIVERED</strong> com <code>recipient_resolved=true</code>; 2xx isolado permanece PENDING_VERIFICATION. Em caso retomado sem cenário persistido, o painel omite os metadados estáticos do cenário em vez de associar ao incidente um risco/resultado-alvo que não foi comprovado.</p>
          </section>
          <section>
            <h3>Measured control impact</h3>
            <p>O resumo agregado usa somente dados persistidos ainda cobertos pela retenção. <strong>Evaluated actions</strong> conta decisões de policy observadas. <strong>Blocked before egress</strong> conta decisões DENY. <strong>Minimized decisions</strong> conta REDACT. <strong>Verified outcomes</strong> conta execuções em COMPLETED, estado que já exige read-back independente. Os filtros <strong>Retained</strong>, <strong>24 hours</strong> e <strong>7 days</strong> alteram somente a janela de leitura.</p>
            <p><strong>Observed block rate</strong> = DENY / decisões avaliadas × 100. <strong>Verified completion</strong> = COMPLETED / (COMPLETED + UNVERIFIED + FAILED) × 100. EXECUTING e PENDING_VERIFICATION não entram no denominador finalizado. Quando o denominador é zero, a tela mostra <strong>NOT OBSERVED</strong>, nunca 0% inventado.</p>
            <p><strong>Median policy decision</strong> usa as latências <code>evaluatedAt - action.createdAt</code>. <strong>Median verified outcome</strong> usa somente COMPLETED e <code>completedAt - action.createdAt</code>. Tempos negativos/inconsistentes não entram na mediana. <strong>Redacted normal field names</strong> e <strong>Redacted private references</strong> contam nomes/categorias removidos pela policy; não contam bytes, pessoas ou valores privados.</p>
            <p>A janela solicitada nunca ultrapassa a retenção configurada; dados já purgados não são reconstruídos. A API agregada não retorna prompt, username, normal payload nem private value. <strong>Financial ROI is NOT MEASURED.</strong> O produto não infere dinheiro economizado, breach evitado, redução percentual de risco, SLA ou compliance.</p>
          </section>
          <section>
            <h3>Incident workspace</h3>
            <p>O workspace lista todos os incidentes ativos cobertos pela retenção usando um resumo operacional calculado no backend. <strong>Need attention</strong> conta somente itens cujo estado exige revisão ou próxima ação. Os estados incluem <strong>Needs analysis</strong>, <strong>Policy evaluation required</strong>, <strong>Blocked by policy</strong>, <strong>Needs human approval</strong>, <strong>Execution pending</strong>, <strong>Execution in progress</strong>, <strong>Verification pending</strong>, <strong>Verified complete</strong>, <strong>Unverified / review required</strong>, <strong>Failed / review required</strong> e estados de revisão quando a combinação persistida não permite uma conclusão segura.</p>
            <p><strong>Source filter</strong> possui <strong>All</strong>, <strong>External</strong> e <strong>Demo</strong>. External é determinado pelo <code>originType=EXTERNAL</code> persistido pelo backend, nunca pelo título, posição da fila ou texto da fonte. A fonte de um incidente externo é derivada no servidor da integração autenticada, por exemplo <strong>Approved integration: Security automation</strong>; o request M2M não escolhe esse valor. Demo cobre os casos não externos originados pela aplicação, incluindo os cenários sintéticos do catálogo. Casos criados manualmente pela API humana também permanecem origem da aplicação e, por isso, não são apresentados como integração externa.</p>
            <p>Cada linha mostra a origem, <strong>Source</strong>, <strong>Received</strong>, estado e <strong>Next action</strong>. Next action é orientação de triagem derivada do estado persistido; não é um botão privilegiado nem uma autorização. Ao selecionar um caso, o dashboard limpa o detalhe anterior e carrega Incident, última Action Proposal, Policy Decision, Remediation, Trace e Audit daquele incidente. O detalhe apresenta <strong>Source</strong> e <strong>Received at</strong> sem expor credencial da integração.</p>
            <p>A entrada M2M autenticada é separada da sessão humana e de CSRF. Ela aceita somente metadados operacionais minimizados, aplica a mesma retenção e audit do domínio e usa idempotência por integração + external event id. Reentrega do mesmo evento pela mesma integração retoma o mesmo incidente; o mesmo identificador enviado por integrações diferentes continua independente. Tokens de intake são configuração exclusiva do backend e nunca são enviados ao navegador, DOM, audit ou evidence.</p>
            <p>Receber um incidente externo não chama Agent, policy, autorização humana, Protected Executor, execução ou verificação. O workspace não contém Authorize, Execute ou Verify. Essas ações permanecem no detalhe existente e continuam sujeitas às autoridades e regras de SoD. Se um incidente expirar entre a listagem e a abertura, a tela o remove da fila e informa que ele não está mais ativo. Falha ao carregar a fila ou o detalhe mostra ação de <strong>Retry</strong>; zero incidentes mostra um estado vazio e não é tratado como erro.</p>
            <p>O catálogo de cenários continua sendo uma ferramenta demonstrativa separada. Selecionar um cenário não seleciona nem renomeia um incidente persistido. Retomar um caso pelo workspace não tenta deduzir o cenário pelo título, severity, source ou action.</p>
          </section>
          <section>
            <h3>Prompt, cenários e privacidade</h3>
            <p>Os cenários usam prompts sintéticos. Analyze with agent e Ask agent for minimum proposal chamam o provider configurado sem conceder permissões. O guard de prompt cobre classes estruturadas suportadas, mas um prompt aceito não significa <strong>PII-free</strong>, safe ou certificação equivalente. Valores privados e segredos não devem ser inseridos no prompt.</p>
            <p>No fluxo <strong>notify-security</strong>, navegador, modelo, backend Java e gateway trafegam somente a referência lógica <code>verified_email</code>. O marker de profile é criado exclusivamente dentro do contrato Rust/WASM. O plaintext resolvido pode existir transitoriamente no protected egress e no serviço externo autorizado, mas não é retornado pelas APIs, pelo Business Outcome, Audit Trail ou Evidence.</p>
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
            <p>O A2A expõe somente avaliação pública compatível com Proposal + evaluate-action. Não expõe intake de incidentes, autorização humana, prova one-time, valores normais, referências privadas resolvidas, execute-remediation, verify-remediation ou credencial do Executor. A2A configurado/publicado não prova reachability.</p>
          </section>
          <section>
            <h3>Policy, minimização, autorização humana e execução</h3>
            <p>DENY bloqueia. REDACT só pode continuar quando o mínimo obrigatório sobrevive e o subconjunto reavaliado vira ALLOW. Para <code>revoke-credential</code>, o mínimo normal é <code>incident_id</code>, <code>credential_id</code> e <code>reason</code>, sem private refs. Para <code>notify-security</code>, o mínimo normal é <code>incident_id</code>, <code>severity</code> e <code>summary</code>, com exatamente <code>private_refs=["verified_email"]</code>. Removed before egress nunca é copiado para o request externo.</p>
            <p>Após a autorização humana, o backend emite na execução uma prova <strong>v2</strong> one-time assinada com <strong>Ed25519</strong>. Ela vincula normalPayloadHash, action/resource/purpose, campos, referências privadas, policy version/hash, Protected Executor DID, destino aprovado, hash do principal autenticado, timestamp da autorização, issued/expiry e nonce. A chave privada permanece no backend; gateway e contrato recebem somente material público de verificação. Não existe downgrade silencioso para o formato legado.</p>
            <p><strong>Human authorization</strong> registra o principal autenticado da aplicação, não identidade civil nem DID T3N do humano. A prova não envia o username; vincula o SHA-256 do principal canônico e o timestamp persistido. Autorizações legadas sem provenance exigem <strong>REAUTHORIZATION REQUIRED</strong>. Em Enterprise SoD, o principal executor deve ser diferente do aprovador; essa regra é aplicada no backend antes do protected egress.</p>
            <p><strong>Gateway proof check</strong> é fail-fast e não substitui T3N. O gateway encaminha a mesma prova para <code>execute-remediation</code>. Antes de ler <code>security_api_url</code>, <code>security_api_key</code> ou iniciar HTTP, o WASM verifica assinatura, key id, expiração, claims e consome o nonce em KV privado. Executor credential sem prova, prova expirada/tampered, request diferente ou nonce reutilizado falham fechado. A interface não afirma que T3N verificou identidade civil do humano; T3N verifica a prova assinada emitida pelo backend após autenticação e autorização.</p>
            <p><strong>Execute protected credential revocation</strong> e <strong>Execute protected security notification</strong> exigem Executor autorizado + prova válida, destino aprovado, policy atual compatível, payload minimizado e reavaliação ALLOW. Na notificação, somente o contrato adiciona o marker de <code>verified_email</code> ao egress. Aceitação externa não é conclusão; revogação exige REVOKED e notificação exige DELIVERED + <code>recipient_resolved=true</code> em read-back independente.</p>
          </section>
          <section>
            <h3>Integridade do audit local e T3N Activity Log</h3>
            <p>O audit local usa <strong>HMAC-SHA256</strong> e é <strong>tamper-evident</strong>, não imutável. <strong>VERIFIED</strong>, <strong>BROKEN</strong>, <strong>KEY_MISMATCH</strong> e <strong>LEGACY_UNVERIFIED</strong> são estados distintos. Um snapshot antigo internamente consistente não é alegado como detectável sem âncora externa monotônica. A autorização registra o principal aprovador e a execução persiste o principal executor obtido da sessão; identidade humana não é aceita no request body.</p>
            <p>No T3N Activity Log, evaluate-action deve identificar o Proposal Agent; execute-remediation e verify-remediation devem identificar o Protected Executor. Integridade local não fabrica provenance T3N.</p>
          </section>
          <section>
            <h3>Proof &amp; evidence</h3>
            <p>Evidence summary mostra PASS/FAIL/NOT RUN, rede, <strong>Source tree</strong>, trust anchor, policy e horário. PASS exige observação compatível; NOT RUN não conta como prova. A evidence não publica username, e-mail, recipient plaintext, hash do operador, prova assinada, nonce nem chave privada. O fingerprint da chave pública pode ser metadata não secreta. <strong>LIVE-PROFILE-PLACEHOLDER-RESOLUTION</strong> permanece NOT RUN por padrão e só pode virar PASS após execução real opt-in em T3N testnet com perfil sintético contendo e-mail verificado, side effect controlado e read-back DELIVERED com <code>recipient_resolved=true</code>. <strong>COMPLETED</strong> continua dependente de verificação independente. Measured control impact é observabilidade operacional agregada e não substitui evidence T3N.</p>
          </section>
          <section>
            <h3>Fluxo principal</h3>
            <p>1. Leia readiness, Enterprise integration e a autoridade da sessão. 2. No Incident workspace, escolha um incidente ativo para retomar; incidentes externos já chegam como <strong>External</strong> e iniciam em <strong>Needs analysis</strong>, enquanto o catálogo permanece disponível para iniciar um fluxo demo. 3. Use Executive demo apenas para apresentação. 4. No Protection flow, como ANALYST, use Analyze with agent quando estiver iniciando um cenário novo ou proponha a resposta mínima para o incidente selecionado. 5. Revise proposal, policy e minimização. 6. Em ALLOW/REDACT executável, confira os campos mínimos e, em notify-security, somente a referência <code>verified_email</code>. 7. Como APPROVER, registre Human authorization. 8. Em Enterprise SoD, troque para um principal EXECUTOR diferente do aprovador. 9. Execute e observe One-time authorization proof, Gateway proof check e T3N execution proof check sem revelar o token ou recipient. 10. Verifique o estado externo específico da ação. 11. Somente após REVOKED ou DELIVERED + recipient_resolved aceite COMPLETED. 12. Consulte Measured control impact para resultados agregados dentro da retenção. 13. Em Evidence, confira summary, outcomes e provenance.</p>
          </section>
          <section>
            <h3>Mensagens e estados de erro</h3>
            <p>Falha de provider, T3N, Agent Card, A2A, policy KV, delegation ou trust boundary nunca é apresentada como sucesso. Falha ao carregar o Incident workspace ou o detalhe oferece <strong>Retry</strong>; um incidente que expirou antes de ser aberto é removido da fila e informado como não ativo. O filtro de origem sem resultados mostra um estado vazio específico, sem sugerir falha de serviço. <strong>403 Action not allowed</strong> indica autoridade humana insuficiente. <strong>Separation of duties…different principal</strong> indica que o aprovador tentou executar/verificar a mesma ação em modo enterprise; o protected egress não é iniciado. Prova humana ausente, expirada, assinatura inválida, key id inválido, body/Executor incompatível ou nonce já consumido falha fechado antes do protected egress. Para notify-security, private ref ausente, extra, literal de placeholder, não permitido pela policy, DELIVERED sem <code>recipient_resolved=true</code> ou erro de resolução permanecem bloqueados/UNVERIFIED sem ecoar recipient. REAUTHORIZATION REQUIRED exige nova aprovação explícita. Destination changed exige nova ação, avaliação e autorização. Aceitação sem read-back permanece PENDING_VERIFICATION ou UNVERIFIED. Audit integrity broken bloqueia mudanças protegidas. Evidence ausente permanece Live evidence not loaded/generated. <strong>NOT OBSERVED</strong> em taxa ou latência agregada significa ausência de denominador/amostra válida, não um zero inventado.</p>
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
