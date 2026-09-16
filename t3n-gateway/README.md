# T3N Gateway runtime provisioning

Este diretório contém o runtime do gateway e os comandos administrativos necessários para preparar a integração T3N publicada.

## Build do container

O serviço do T3N Gateway usa `t3n-gateway` como contexto/base do build no EasyPanel. O `Dockerfile` é, portanto, autocontido nesse diretório e não tenta executar `COPY` de caminhos irmãos ou da raiz do monorepo.

O código-fonte canônico do contrato continua em `contracts/privacy-guard`. Para que o Docker consiga compilá-lo sem acessar arquivos fora do contexto, `t3n-gateway/contract-source` mantém somente os inputs necessários ao build (`Cargo.toml`, `src` e `wit`). Esse espelho deve permanecer byte a byte igual ao contrato canônico.

Sempre que `contracts/privacy-guard/Cargo.toml`, `contracts/privacy-guard/src` ou `contracts/privacy-guard/wit` mudar, regenere o espelho antes de commitar:

```bash
cd t3n-gateway
npm run contract:sync-build-context
npm test
```

O teste `contract-source-sync.test.ts` falha se o conjunto de arquivos ou qualquer conteúdo do espelho divergir da fonte canônica.

Build local equivalente ao deploy:

```bash
docker build \
  --build-arg EVIDENCE_SOURCE_COMMIT_SHA=<full-40-char-commit-built> \
  --build-arg EVIDENCE_SOURCE_TREE_CLEAN=true \
  -t t3-privacy-guard-gateway t3n-gateway
```

Os build args de evidência são metadados públicos, não secrets. Quando fornecidos, a imagem grava `/app/runtime/source-revision.json` como metadado imutável do artefato. Se o provedor de deploy não injeta build args, o mesmo par pode ser fornecido explicitamente no ambiente como `EVIDENCE_SOURCE_COMMIT_SHA` e `EVIDENCE_SOURCE_TREE_CLEAN`; o fluxo nunca consulta a `main` remota para adivinhar qual commit foi construído.

No EasyPanel, mantenha `t3n-gateway` como contexto/base de build e use o `Dockerfile` desse diretório. O runtime final não contém o código-fonte TypeScript nem as dependências de desenvolvimento. Ele contém apenas as dependências Node de produção, `dist`, a policy versionada e o WASM compilado do contrato sincronizado.

A imagem define caminhos estáveis para os artefatos administrativos e de evidência:

```text
T3N_CONTRACT_WASM_PATH=/app/runtime/privacy_guard_contract.wasm
T3N_POLICY_FILE=/app/policy/privacy-guard-policy.json
AGENT_CARD_OUTPUT=/data/agent-card.json
T3N_RUNTIME_PROVISIONING_STATE_PATH=/data/t3n-runtime-provisioning.json
EVIDENCE_RUNTIME_DIR=/data/evidence
EVIDENCE_SOURCE_REVISION_FILE=/app/runtime/source-revision.json
```

`/data` continua sendo o volume persistente e o processo continua executando como usuário `node`, não-root. Nenhum segredo é incorporado à imagem.

## Configuração-base do runtime

Todos os comandos administrativos carregam `readGatewayConfig()`. Portanto, eles devem ser executados no mesmo container com a configuração-base válida usada pelo serviço, incluindo pelo menos as variáveis exigidas pelo gateway, como:

```text
T3N_API_KEY
T3N_NETWORK
T3N_CONTRACT_TAIL
T3N_CONTRACT_VERSION
GATEWAY_SERVICE_TOKEN
REMEDIATION_AUTH_PUBLIC_KEY_SPKI
REMEDIATION_AUTH_KEY_ID
REMEDIATION_REPLAY_STORE_PATH
T3N_TRUST_FLOOR_STORE_PATH
```

`T3N_API_KEY` é a credencial administrativa do Tenant e continua usando autenticação de sessão secp256k1; mantenha nela a chave privada `0x` de 32 bytes. Proposal Agent e Protected Executor podem usar credenciais secp256k1 legadas distintas, mas o fluxo recomendado é provisioná-los como agentes organization-owned e usar as credenciais opacas `t3n_key_<key-id>.<secret>` emitidas pela T3N.

`readGatewayConfig()` valida esses formatos antes de qualquer tentativa de conexão. `T3N_API_KEY` aceita somente `0x` seguido por exatamente 64 caracteres hexadecimais; `T3N_AGENT_API_KEY` e `T3N_EXECUTOR_API_KEY`, quando presentes, aceitam somente esse mesmo formato secp256k1 ou `t3n_key_<key-id>.<secret>`. Formato desconhecido ou malformado encerra a inicialização sem incluir o valor da credencial na mensagem de erro.

Os valores opcionais podem continuar usando os defaults já definidos pelo runtime. Credenciais reais devem existir somente no secret store/ambiente do serviço. Os requisitos abaixo são adicionais ou específicos de cada etapa e não substituem essa configuração-base.

## Reconciliação automática no container publicado

Quando `NODE_ENV=production` e `T3N_NETWORK=testnet`, o gateway habilita por padrão uma reconciliação idempotente de runtime. Ela pode ser desabilitada explicitamente com:

```text
T3N_RUNTIME_PROVISIONING=false
```

Em `T3N_NETWORK=production`, mutações automáticas permanecem desabilitadas por padrão. Habilitá-las exige `T3N_RUNTIME_PROVISIONING=true` de forma explícita.

A reconciliação usa os mesmos contratos de segurança dos comandos administrativos e executa somente o necessário para aproximar o runtime do estado configurado:

```text
autenticar Tenant + Proposal Agent + Protected Executor
      |
      v
resolver contrato canônico
      |
      +--> ausente: registrar WASM e persistir numericContractId em /data
      |
      v
publicar/confirmar policy quando numericContractId estiver disponível
      |
      v
configurar private remediation maps somente com SECURITY_* reais e válidos
      |
      v
aplicar delegação mínima do Proposal Agent
      |
      v
aplicar delegação mínima do Executor somente com endpoints reais
      |
      v
verificar e, quando permitido, reparar/publicar Agent Card
```

O arquivo `T3N_RUNTIME_PROVISIONING_STATE_PATH` contém somente `tenantDid`, contract id, contract version, numeric contract id e timestamp. Ele nunca contém chaves T3N, credenciais de integração, tokens, chaves privadas ou valores de profile. Um numeric id persistido só é reutilizado quando Tenant DID, contract id e versão coincidem exatamente com a sessão autenticada atual.

`T3N_CONTRACT_NUMERIC_ID` continua aceito como override explícito para contratos já existentes. Para contratos registrados pela própria reconciliação, o numeric id retornado pela T3N é persistido automaticamente em `/data`, eliminando a necessidade de copiar esse identificador manualmente entre redeploys.

A configuração protegida de remediation só é reconciliada quando `SECURITY_API_KEY`, `SECURITY_API_URL` e `SECURITY_VERIFICATION_URL` representam valores reais. Hosts `.invalid`, `example.invalid`, `postman-echo.com`, HTTP e placeholders de documentação não são promovidos a readiness operacional. Os hosts reais também precisam estar permitidos pela policy selecionada em `T3N_POLICY_FILE`; a reconciliação não altera silenciosamente a policy versionada para acomodar um destino novo.

Se `A2A_PUBLIC_URL` estiver configurada e o card público estiver divergente, a reconciliação pode republicar o Agent Card somente quando `T3N_ORG_DID` e `T3N_AGENT_API_KEY` estiverem presentes. O DID publicado continua vindo exclusivamente da autenticação do Proposal Agent.

Falha em qualquer etapa é sanitizada, registrada sem secrets e mantém o sistema fail-closed. O servidor HTTP continua observável para que `/health` e os endpoints de status indiquem o que ainda não está pronto; uma falha de provisionamento nunca é convertida em readiness positivo.

## Evidência live no container de produção

A imagem final executa a geração live somente a partir de JavaScript compilado em `dist`; `src`, `tsx` e `.git` não são requisitos de runtime.

```bash
npm run evidence:live
```

Em `NODE_ENV=production`, o bundle principal é persistido no volume do gateway:

```text
/data/evidence/deployment-manifest.json
/data/evidence/testnet-run.json
/data/evidence/human-proof-testnet.json
```

`evidence:live` reutiliza o contrato já reconciliado. O `numericContractId` vem de `T3N_CONTRACT_NUMERIC_ID` quando explicitamente configurado ou de `/data/t3n-runtime-provisioning.json` somente quando Tenant DID, contract id e versão coincidem. O comando não inventa um numeric id nem consulta estado externo para inferi-lo.

A proveniência de código vem, nesta ordem, de:

1. `EVIDENCE_SOURCE_COMMIT_SHA` + `EVIDENCE_SOURCE_TREE_CLEAN` fornecidos explicitamente pelo deploy;
2. `/app/runtime/source-revision.json` criado pelos build args equivalentes;
3. somente em desenvolvimento, um checkout Git local.

O SHA deve ser completo, com 40 caracteres. Se a imagem não tiver metadado de build válido e o deploy também não fornecer o par explícito, a geração falha fechada. Uma execução de submissão também recusa `sourceTreeClean=false` salvo override explícito para uma execução marcada como não submetível.

Antes de gravar os artefatos, o fluxo mantém as validações já existentes de três DIDs distintos, trust anchor, rollback floor, contract id/version, WASM SHA-256, policy version/hash, Member grants e effective access. `assertNoSecretLeak` continua obrigatório tanto no manifest quanto no run final. `NOT_RUN` permanece `NOT_RUN`.

Para Agent Card em estado `REGISTERED`, a evidência exige o serviço `DID` e aceita opcionalmente `A2A` quando ele está efetivamente publicado. Somente `DID` e `A2A` são aceitos, sem duplicatas e sem dependência da ordem retornada. Essa regra espelha o `AgentCardRegistry`: endpoint, DID canônico e endpoint A2A continuam validados no card resolvido antes de a evidência registrar o conjunto de serviços.

O backend não compartilha filesystem com o gateway. O gateway expõe o último par persistido somente em `GET /internal/evidence/latest`, atrás do mesmo `X-Gateway-Service-Token` usado pelos demais endpoints internos. A semântica é:

```text
204 -> nenhum bundle gerado
200 -> par manifest + testnet disponível
409 -> bundle parcial, ilegível ou inválido estruturalmente no storage
```

O backend consulta esse endpoint e aplica novamente a validação semântica completa antes de responder `GET /api/evidence/latest`. Assim, reiniciar containers preserva o último bundle em `/data`, ausência nunca vira PASS e arquivos parciais continuam fail-closed.

Os comandos `evidence:testnet`, `evidence:human-proof` e `evidence:profile-placeholder` da imagem também usam `node dist/...` e caminhos persistentes de `/data/evidence`. Para desenvolvimento com TypeScript/checkout local, use os comandos `*:dev`.

## Autenticação dos três principais

O gateway reconhece explicitamente dois formatos, sem converter um no outro:

```text
0x<64 hex>                    -> handshake + authenticate secp256k1
 t3n_key_<key-id>.<secret>    -> keyed/stateless T3N transport
```

Para `t3n_key_*`, o gateway valida a identidade com `discoverWhoami`, obtém o DID canônico retornado pela própria T3N e executa contratos por `invoke`. A verificação efetiva de delegação usa `discoverCheckDelegation`. Esse caminho não chama `eth_get_address`, `metamask_sign`, `createEthAuthInput`, `handshake` nem autenticação de sessão. Credenciais opacas inválidas ou expiradas falham fechadas e são removidas de mensagens de erro/log antes de serem propagadas.

A credencial `t3n_key_*` é retornada uma única vez ao criar o agente e não deve ser impressa, commitada ou armazenada em evidence. Registre o DID retornado no provisionamento para conferência operacional, mas o runtime considera canônico o DID obtido pela autenticação T3N daquele principal.

Além de manter as credenciais distintas por valor, o runtime exige separação dos DIDs canônicos autenticados. Tenant, Proposal Agent e Protected Executor, quando configurados e autenticados, devem resolver para DIDs diferentes entre si. Um guardião compartilhado aplica essa regra em status/readiness, reconnect e operações de sessão; qualquer reutilização de DID mantém a topologia `ready: false` e bloqueia delegações ou execuções dependentes da segregação até que as identidades autenticadas voltem a ser distintas. Quando um principal opcional não está configurado, somente os DIDs efetivamente autenticados são comparados.

## Ordem de provisionamento manual

A sequência abaixo continua disponível como fallback operacional ou quando `T3N_RUNTIME_PROVISIONING=false`. Execute os comandos no shell do container publicado, com diretório de trabalho `/app`.

### 1. Registrar o contrato

Confirme na configuração-base:

```text
T3N_API_KEY
T3N_NETWORK
T3N_CONTRACT_TAIL
T3N_CONTRACT_VERSION
```

Execute:

```bash
npm run contract:register
```

O comando usa o WASM empacotado na imagem e retorna `numericContractId`. No fluxo manual, copie somente esse identificador numérico para a configuração de runtime:

```text
T3N_CONTRACT_NUMERIC_ID=<numericContractId retornado pela T3N>
```

Nunca invente ou antecipe esse valor. Reinicie/reimplante o serviço com o valor real antes das etapas seguintes. Quando a reconciliação automática registra o contrato, esse valor é persistido em `/data` e não precisa ser copiado manualmente.

### 2. Publicar a policy operacional

Requisito adicional:

```text
T3N_CONTRACT_NUMERIC_ID
```

Execute:

```bash
npm run contract:setup-policy
```

A policy padrão vem de `/app/policy/privacy-guard-policy.json`. O script grava a versão/hash na KV privada e só conclui após read-back compatível. `T3N_POLICY_FILE` pode ser sobrescrita explicitamente apenas quando houver um arquivo de policy válido montado no container.

### 3. Configurar remediation protegida

Requisitos adicionais:

```text
T3N_CONTRACT_NUMERIC_ID
SECURITY_API_KEY
SECURITY_API_URL
SECURITY_VERIFICATION_URL
```

`REMEDIATION_AUTH_PUBLIC_KEY_SPKI` e `REMEDIATION_AUTH_KEY_ID` já fazem parte da configuração-base do gateway e também são usados nesta etapa.

Execute:

```bash
npm run contract:setup-remediation
```

O script cria/atualiza somente os mapas privados necessários ao contrato, incluindo a chave da integração protegida, URLs HTTPS, chave pública de autorização e o mapa de nonces. Valores sensíveis não são impressos no resultado.

### 4. Provisionar organização, Proposal Agent e Protected Executor

Use o DID canônico da organização T3N proprietária dos agentes. Grave esse DID público explicitamente no ambiente do gateway:

```text
T3N_ORG_DID=did:t3n:<organization-id>
```

`T3N_ORG_DID` nunca deve ser derivado de `T3N_API_KEY`, `T3N_AGENT_API_KEY`, endereço Ethereum ou outro segredo. Ele deve ser o DID canônico retornado/confirmado pelo fluxo oficial de organização da T3N.

Crie dois agentes distintos sob essa organização usando o fluxo oficial atual, por exemplo `t3n agent create --org <did> --name <name> ...` ou a API equivalente da versão instalada. Para cada criação, capture imediatamente os três valores retornados pela T3N:

```text
agent DID
key id
t3n_key_<key-id>.<secret>
```

A API key opaca é exibida somente no momento da criação. Grave-a diretamente no secret store do serviço e nunca em arquivos de evidence. Use agentes diferentes para as duas responsabilidades:

```text
T3N_AGENT_API_KEY    -> Proposal Agent: evaluate-action
T3N_EXECUTOR_API_KEY -> Protected Executor: execute-remediation + verify-remediation
```

Depois do deploy, confirme pelo status/readiness que `agentDid` e `executorDid` correspondem aos DIDs criados. O valor exibido pelo gateway vem de `discoverWhoami` autenticado com cada credencial, não de derivação local nem de valor hardcoded.

### 5. Publicar e verificar o Agent Card

Requisitos adicionais:

```text
T3N_ORG_DID
T3N_AGENT_API_KEY
```

`T3N_API_KEY` continua sendo a credencial administrativa secp256k1 do Tenant/Admin. `T3N_AGENT_API_KEY` continua sendo exclusivamente a credencial do Proposal Agent e deve ser diferente de `T3N_API_KEY` e `T3N_EXECUTOR_API_KEY`. Ela não é copiada, convertida nem reinterpretada como `T3N_API_KEY`.

Quando `A2A_PUBLIC_URL` estiver configurada, ela deve apontar para o endpoint HTTPS `/a2a` externamente alcançável.

Execute:

```bash
npm run agent:card:publish
npm run agent:card:verify
```

A publicação gera o card em `/data/agent-card.json`, autentica o Tenant/Admin com `T3N_API_KEY`, cria o cliente administrativo de organização a partir dessa sessão e chama `agentCardSet`/`agentCardPublish` com `ownerDid=T3N_ORG_DID`. O `agentDid` é obtido exclusivamente pela autenticação T3N do Proposal Agent (`AgentSession.getAgentDid()`), inclusive quando sua credencial é `t3n_key_*`. O fluxo não executa `t3n agent host-card`, não cria subprocesso de CLI e não assume que o DID da organização é igual ao DID do agente.

Após a publicação, `AgentCardRegistry.verify()` resolve novamente o registro usando a identidade autenticada do Proposal Agent. O comando só conclui quando o estado chega a `REGISTERED`; falha de publicação, resolução ou mismatch permanece fail-closed. A publicação é uma operação mutável e pode consumir créditos T3N.

Fluxo de identidade da publicação:

```text
Tenant/Admin secp256k1 (T3N_API_KEY)
        |
        +--> organização (T3N_ORG_DID)
                 |
                 +--> Proposal Agent (DID autenticado via T3N_AGENT_API_KEY)
                         |
                         +--> Agent Card set/publish
```

### 6. Validar readiness e delegações

Depois do provisionamento, mantenha as três credenciais separadas:

```text
T3N_API_KEY          -> Tenant/Admin, sessão secp256k1
T3N_AGENT_API_KEY    -> Proposal Agent: evaluate-action
T3N_EXECUTOR_API_KEY -> Protected Executor: execute-remediation + verify-remediation
```

O `T3N_EXECUTOR_API_KEY` não é usado para registrar o contrato ou publicar a policy, mas é obrigatório para readiness de remediation protegida. As delegações Member e as verificações efetivas continuam sendo validadas separadamente em runtime; para um principal `t3n_key_*`, a verificação efetiva usa `discoverCheckDelegation` no keyed transport.

A sequência operacional completa é:

```text
register contract
      |
      v
persist T3N_CONTRACT_NUMERIC_ID
      |
      v
setup policy + read-back
      |
      v
setup remediation private maps
      |
      v
provision organization + Proposal Agent + Protected Executor
      |
      v
persist T3N_ORG_DID and agent credentials
      |
      v
publish + verify Agent Card
      |
      v
validate readiness + effective delegations
```

## Remote MCP integration

The gateway exposes an authenticated Model Context Protocol endpoint at `/mcp`. It uses the official MCP TypeScript SDK v2 Streamable HTTP handler, which implements the `2026-07-28` protocol revision and keeps the SDK's stateless compatibility path for 2025-era clients.

The endpoint is protected before MCP dispatch with the existing gateway service credential using standard bearer authentication:

```http
Authorization: Bearer <GATEWAY_SERVICE_TOKEN>
```

Do not use `T3N_API_KEY`, `T3N_AGENT_API_KEY` or `T3N_EXECUTOR_API_KEY` as the MCP bearer token. Those credentials remain server-side only.

Exactly three MCP tools are registered:

```text
privacy.contract_identity
privacy.evaluate_action
privacy.verify_remediation
```

`privacy.contract_identity` returns the canonical deployed contract identity and version. `privacy.evaluate_action` evaluates a proposed action and never authorizes remediation. `privacy.verify_remediation` verifies the observed state of a remediation that was already authorized and executed through the protected flow.

`execute-remediation`, `privacy.execute_remediation` and any equivalent privileged operation are intentionally not registered. MCP cannot bypass `RemediationAuthorizationVerifier` or obtain the Protected Executor capability.

Tool arguments are validated by the MCP SDK from strict Zod schemas before the contract service handler is invoked. Unknown fields, missing required fields, oversized arrays, invalid remediation actions and invalid expected states fail closed without invoking T3N. Contract/T3N failures return the generic tool error `Privacy Guard MCP operation failed closed`; internal exception messages and credentials are not returned to the MCP client.

A compatible v2 client can connect with a static bearer provider:

```ts
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const client = new Client(
  { name: 'privacy-guard-client', version: '1.0.0' },
  { versionNegotiation: { mode: 'auto' } },
);
const transport = new StreamableHTTPClientTransport(
  new URL('https://gateway.example/mcp'),
  { authProvider: { token: async () => process.env.GATEWAY_SERVICE_TOKEN } },
);

await client.connect(transport);
const { tools } = await client.listTools();
const identity = await client.callTool({
  name: 'privacy.contract_identity',
  arguments: {},
});
```

For `privacy.evaluate_action`, send `request_id`, `action`, `resource`, `purpose` and `fields`; `host` and `private_refs` are optional. For `privacy.verify_remediation`, send `request_id`, `operation_id`, `action` (`revoke-credential` or `notify-security`) and `expected_state` (`REVOKED` or `DELIVERED`).

## Falhas esperadas e segurança

Os comandos administrativos e o runtime falham fechados quando os artefatos, credenciais ou variáveis obrigatórios não existem. Em particular:

- `contract:setup-policy` e `contract:setup-remediation` recusam execução sem `T3N_CONTRACT_NUMERIC_ID` válido;
- a reconciliação automática não inventa numeric id: registra contrato ausente ou reutiliza somente override/state coerente com Tenant, contract id e versão;
- a reconciliação automática não persiste credenciais; o arquivo de state contém somente metadados públicos de provisionamento;
- `agent:card:publish` recusa execução sem `T3N_AGENT_API_KEY` ou `T3N_ORG_DID` canônico;
- `agent:card:verify` recusa execução sem `T3N_AGENT_API_KEY`;
- a reparação automática do Agent Card só ocorre quando a organização e o Proposal Agent estão explicitamente configurados;
- `contract:register` falha se o WASM runtime estiver ausente ou ilegível;
- `evidence:live` falha se a proveniência do artefato não trouxer um SHA completo ou se o bundle de origem estiver DIRTY sem override explícito;
- `evidence:live` não usa `tsx`, `src` ou `.git` no container final e só publica o par persistente após manter as verificações de identidade, trust, policy, contrato e delegação;
- `/internal/evidence/latest` exige `GATEWAY_SERVICE_TOKEN`; bundle parcial/ilegível retorna estado inválido e nunca é exposto como sucesso;
- `T3N_API_KEY` fora do formato secp256k1 exato e credenciais Proposal/Executor fora dos formatos suportados são rejeitadas antes de iniciar conexões;
- `t3n_key_*` malformada, inválida ou expirada não é reinterpretada como chave privada e não cai no fluxo secp256k1;
- DIDs canônicos repetidos entre Tenant, Proposal Agent e Protected Executor tornam readiness inválido e bloqueiam operações que dependem da segregação;
- falhas de autenticação/rede do keyed transport não expõem a API key no status ou na mensagem propagada;
- falhas de `agentCardSet`/`agentCardPublish` são sanitizadas contra as credenciais Tenant/Admin e Proposal Agent antes de serem propagadas;
- URLs de remediation devem ser HTTPS;
- placeholders e hosts de demonstração não recebem delegação operacional automática;
- chaves privadas, API keys e segredos de integração devem existir somente nas variáveis/secret store do ambiente de execução;
- nenhum segredo deve ser copiado para a imagem, commitado no repositório ou incluído em logs/evidence.

O serviço normal permanece:

```bash
npm start
```

que executa `node dist/index.js` como usuário não-root. No testnet publicado, a reconciliação idempotente é disparada em paralelo ao startup e qualquer falha mantém readiness fechado enquanto o serviço continua observável.
