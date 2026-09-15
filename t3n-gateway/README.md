# T3N Gateway runtime provisioning

Este diretório contém o runtime do gateway e os comandos administrativos necessários para preparar a integração T3N publicada.

## Build do container

O Dockerfile do gateway também compila o contrato Rust localizado em `contracts/privacy-guard`. Por isso, o contexto de build deve ser a raiz do repositório, mantendo o Dockerfile em `t3n-gateway/Dockerfile`:

```bash
docker build -f t3n-gateway/Dockerfile -t t3-privacy-guard-gateway .
```

No EasyPanel, use a raiz do repositório como contexto/base de build e `t3n-gateway/Dockerfile` como Dockerfile. O runtime final não contém o código-fonte TypeScript nem as dependências de desenvolvimento. Ele contém apenas as dependências Node de produção, `dist`, a policy versionada e o WASM compilado.

A imagem define caminhos estáveis para os artefatos administrativos:

```text
T3N_CONTRACT_WASM_PATH=/app/runtime/privacy_guard_contract.wasm
T3N_POLICY_FILE=/app/policy/privacy-guard-policy.json
AGENT_CARD_OUTPUT=/data/agent-card.json
```

`/data` continua sendo o volume persistente e o processo continua executando como usuário `node`, não-root. Nenhum segredo é incorporado à imagem.

## Ordem de provisionamento

Execute os comandos no shell do container publicado, com diretório de trabalho `/app`.

### 1. Registrar o contrato

Pré-requisitos mínimos:

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

Pré-requisitos adicionais:

```text
T3N_CONTRACT_NUMERIC_ID
```

Execute:

```bash
npm run contract:setup-policy
```

A policy padrão vem de `/app/policy/privacy-guard-policy.json`. O script grava a versão/hash na KV privada e só conclui após read-back compatível. `T3N_POLICY_FILE` pode ser sobrescrita explicitamente apenas quando houver um arquivo de policy válido montado no container.

### 3. Configurar remediation protegida

Pré-requisitos adicionais:

```text
T3N_CONTRACT_NUMERIC_ID
SECURITY_API_KEY
SECURITY_API_URL
SECURITY_VERIFICATION_URL
REMEDIATION_AUTH_PUBLIC_KEY_SPKI
REMEDIATION_AUTH_KEY_ID
```

Execute:

```bash
npm run contract:setup-remediation
```

O script cria/atualiza somente os mapas privados necessários ao contrato, incluindo a chave da integração protegida, URLs HTTPS, chave pública de autorização e o mapa de nonces. Valores sensíveis não são impressos no resultado.

### 4. Publicar e verificar o Agent Card

`T3N_AGENT_API_KEY` é a credencial exclusiva do Proposal Agent e deve ser diferente de `T3N_API_KEY` e `T3N_EXECUTOR_API_KEY`. O Proposal Agent permanece limitado a `evaluate-action`.

Quando `A2A_PUBLIC_URL` estiver configurada, ela deve apontar para o endpoint HTTPS `/a2a` externamente alcançável.

Execute:

```bash
npm run agent:card:publish
npm run agent:card:verify
```

A publicação gera o card em `/data/agent-card.json`, usa a CLI T3N instalada com as dependências de produção e depois verifica o card publicado. A publicação é uma operação mutável e pode consumir créditos T3N.

### 5. Validar readiness e delegações

Depois do provisionamento, mantenha as três credenciais separadas:

```text
T3N_API_KEY          -> Tenant
T3N_AGENT_API_KEY    -> Proposal Agent: evaluate-action
T3N_EXECUTOR_API_KEY -> Protected Executor: execute-remediation + verify-remediation
```

O `T3N_EXECUTOR_API_KEY` não é usado para registrar o contrato ou publicar a policy, mas é obrigatório para readiness de remediation protegida. As delegações Member e os `checkDelegation()` efetivos continuam sendo validados separadamente em runtime.

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
publish + verify Agent Card
      |
      v
validate readiness + effective delegations
```

## Falhas esperadas e segurança

Os comandos administrativos falham fechados quando os artefatos ou variáveis obrigatórios não existem. Em particular:

- `contract:setup-policy` e `contract:setup-remediation` recusam execução sem `T3N_CONTRACT_NUMERIC_ID` válido;
- `agent:card:publish` e `agent:card:verify` recusam execução sem `T3N_AGENT_API_KEY`;
- `contract:register` falha se o WASM runtime estiver ausente ou ilegível;
- URLs de remediation devem ser HTTPS;
- chaves privadas, API keys e segredos de integração devem existir somente nas variáveis/secret store do ambiente de execução;
- nenhum segredo deve ser copiado para a imagem, commitado no repositório ou incluído em logs/evidence.

O serviço normal permanece:

```bash
npm start
```

que executa `node dist/index.js` como usuário não-root.
