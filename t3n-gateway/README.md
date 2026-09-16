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
docker build -t t3-privacy-guard-gateway t3n-gateway
```

No EasyPanel, mantenha `t3n-gateway` como contexto/base de build e use o `Dockerfile` desse diretório. O runtime final não contém o código-fonte TypeScript nem as dependências de desenvolvimento. Ele contém apenas as dependências Node de produção, `dist`, a policy versionada e o WASM compilado do contrato sincronizado.

A imagem define caminhos estáveis para os artefatos administrativos:

```text
T3N_CONTRACT_WASM_PATH=/app/runtime/privacy_guard_contract.wasm
T3N_POLICY_FILE=/app/policy/privacy-guard-policy.json
AGENT_CARD_OUTPUT=/data/agent-card.json
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

Os valores opcionais podem continuar usando os defaults já definidos pelo runtime. Credenciais reais devem existir somente no secret store/ambiente do serviço. Os requisitos abaixo são adicionais ou específicos de cada etapa e não substituem essa configuração-base.

## Autenticação dos três principais

O gateway reconhece explicitamente dois formatos, sem converter um no outro:

```text
0x<64 hex>                    -> handshake + authenticate secp256k1
 t3n_key_<key-id>.<secret>    -> keyed/stateless T3N transport
```

Para `t3n_key_*`, o gateway valida a identidade com `discoverWhoami`, obtém o DID canônico retornado pela própria T3N e executa contratos por `invoke`. A verificação efetiva de delegação usa `discoverCheckDelegation`. Esse caminho não chama `eth_get_address`, `metamask_sign`, `createEthAuthInput`, `handshake` nem autenticação de sessão. Credenciais opacas inválidas ou expiradas falham fechadas e são removidas de mensagens de erro/log antes de serem propagadas.

A credencial `t3n_key_*` é retornada uma única vez ao criar o agente e não deve ser impressa, commitada ou armazenada em evidence. Registre o DID retornado no provisionamento para conferência operacional, mas o runtime considera canônico o DID obtido pela autenticação T3N daquele principal.

## Ordem de provisionamento

Execute os comandos no shell do container publicado, com diretório de trabalho `/app`.

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

O comando usa o WASM empacotado na imagem e retorna `numericContractId`. Copie somente esse identificador numérico para a configuração de runtime:

```text
T3N_CONTRACT_NUMERIC_ID=<numericContractId retornado pela T3N>
```

Nunca invente ou antecipe esse valor. Reinicie/reimplante o serviço com o valor real antes das etapas seguintes.

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

## Falhas esperadas e segurança

Os comandos administrativos e o runtime falham fechados quando os artefatos, credenciais ou variáveis obrigatórios não existem. Em particular:

- `contract:setup-policy` e `contract:setup-remediation` recusam execução sem `T3N_CONTRACT_NUMERIC_ID` válido;
- `agent:card:publish` recusa execução sem `T3N_AGENT_API_KEY` ou `T3N_ORG_DID` canônico;
- `agent:card:verify` recusa execução sem `T3N_AGENT_API_KEY`;
- `contract:register` falha se o WASM runtime estiver ausente ou ilegível;
- `t3n_key_*` malformada, inválida ou expirada não é reinterpretada como chave privada e não cai no fluxo secp256k1;
- falhas de autenticação/rede do keyed transport não expõem a API key no status ou na mensagem propagada;
- falhas de `agentCardSet`/`agentCardPublish` são sanitizadas contra as credenciais Tenant/Admin e Proposal Agent antes de serem propagadas;
- URLs de remediation devem ser HTTPS;
- chaves privadas, API keys e segredos de integração devem existir somente nas variáveis/secret store do ambiente de execução;
- nenhum segredo deve ser copiado para a imagem, commitado no repositório ou incluído em logs/evidence.

O serviço normal permanece:

```bash
npm start
```

que executa `node dist/index.js` como usuário não-root.
