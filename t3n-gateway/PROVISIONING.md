# Provisionamento T3N no container do gateway

A imagem de produção do `t3n-gateway` contém os scripts JavaScript compilados, o documento de policy, o contrato Rust compilado para WASM e as dependências de produção necessárias para executar o provisionamento. O diretório `src/`, `tsx`, TypeScript e o diretório local `target/` não são necessários no container final.

## Build da imagem

O Dockerfile fica em `t3n-gateway/Dockerfile`, mas o contexto de build deve ser a raiz do repositório porque o estágio `contract-build` compila a fonte canônica em `contracts/privacy-guard`.

```bash
docker build -f t3n-gateway/Dockerfile -t t3-privacy-guard-gateway .
```

No EasyPanel, mantenha o Dockerfile em `t3n-gateway/Dockerfile` e configure o contexto de build como a raiz do repositório.

A imagem usa estes caminhos internos determinísticos:

```text
T3N_POLICY_FILE=policy/privacy-guard-policy.json
T3N_CONTRACT_WASM_PATH=contracts/privacy_guard_contract.wasm
```

O build executa `npm run runtime:preflight` e falha se os scripts compilados, a policy, o WASM ou a CLI `t3n` não estiverem disponíveis na imagem final.

## Variáveis

Configure os segredos apenas no ambiente de execução. Não grave chaves reais no repositório. Use `.env.example` como referência para os nomes das variáveis.

Antes do primeiro provisionamento, são necessários pelo menos `T3N_API_KEY`, `T3N_NETWORK`, `T3N_CONTRACT_TAIL` e `T3N_CONTRACT_VERSION`. As etapas posteriores também exigem as credenciais e valores específicos documentados em `.env.example`, como `T3N_AGENT_API_KEY`, `T3N_EXECUTOR_API_KEY` e os valores de remediação.

## Sequência de provisionamento

Execute os comandos dentro do mesmo container/artefato que será usado em produção:

```bash
npm run runtime:preflight
npm run contract:register
```

`contract:register` imprime `numericContractId`. Grave esse valor como `T3N_CONTRACT_NUMERIC_ID` no ambiente do gateway antes de continuar. Depois execute:

```bash
npm run contract:setup-policy
npm run contract:setup-remediation
npm run agent:card:publish
npm run agent:card:verify
```

`agent:card:publish` é uma operação mutável na T3N e pode consumir créditos. `agent:card:verify` é a verificação read-only do registro publicado.

Depois do provisionamento, reinicie o serviço se `T3N_CONTRACT_NUMERIC_ID` tiver sido adicionado ou alterado no ambiente do deployment.
