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

O build executa `npm run runtime:preflight` como o usuário não-root `node` e falha se os scripts compilados, a policy, o WASM ou a escrita em `/data` não estiverem disponíveis na imagem final.

## Variáveis por etapa

Todos os scripts que abrem sessão T3N usam a configuração compartilhada do gateway. Por isso, configure `T3N_API_KEY`, `GATEWAY_SERVICE_TOKEN` e `REMEDIATION_AUTH_PUBLIC_KEY_SPKI` antes de qualquer etapa conectada. `T3N_NETWORK`, `T3N_CONTRACT_TAIL`, `T3N_CONTRACT_VERSION` e `REMEDIATION_AUTH_KEY_ID` possuem defaults, mas devem ser definidos explicitamente no deployment quando os valores do ambiente forem diferentes. Nunca grave chaves reais no repositório.

| Etapa | Variáveis adicionais obrigatórias |
| --- | --- |
| `npm run runtime:preflight` | Nenhum segredo. Valida somente os artefatos runtime e o volume `/data`. |
| `npm run contract:register` | `T3N_CONTRACT_WASM_PATH` pode ser omitida quando for usado o caminho empacotado `contracts/privacy_guard_contract.wasm`. |
| Persistir ID retornado | Defina `T3N_CONTRACT_NUMERIC_ID` com o `numericContractId` real retornado pelo registro. Não use placeholder. |
| `npm run contract:setup-policy` | `T3N_CONTRACT_NUMERIC_ID`. `T3N_POLICY_FILE` pode ser omitida quando for usado `policy/privacy-guard-policy.json`. |
| `npm run contract:setup-remediation` | `T3N_CONTRACT_NUMERIC_ID`, `SECURITY_API_KEY`, `SECURITY_API_URL` HTTPS e `SECURITY_VERIFICATION_URL` HTTPS. A chave pública ativa já deve estar em `REMEDIATION_AUTH_PUBLIC_KEY_SPKI`. |
| `npm run agent:card:publish` | `T3N_AGENT_API_KEY`, distinta de `T3N_API_KEY`. A publicação usa diretamente a API de Agent Card do SDK instalada na imagem, sem CLI externa. |
| `npm run agent:card:verify` | `T3N_AGENT_API_KEY`, distinta de `T3N_API_KEY`. |
| Readiness/delegações | Configure também `T3N_EXECUTOR_API_KEY`, distinta de Tenant e Proposal Agent, quando o Protected Executor for habilitado. |

A rotação opcional da chave de autorização exige o trio `REMEDIATION_AUTH_PREVIOUS_KEY_ID`, `REMEDIATION_AUTH_PREVIOUS_PUBLIC_KEY_SPKI` e `REMEDIATION_AUTH_PREVIOUS_KEY_GRACE_SECONDS` em conjunto. Consulte `.env.example` para os demais valores e restrições.

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

Depois do provisionamento, reinicie o serviço se `T3N_CONTRACT_NUMERIC_ID` tiver sido adicionado ou alterado no ambiente do deployment. Em seguida, valide o endpoint de status/readiness do gateway e as delegações observadas pela aplicação para confirmar que contrato, policy, Proposal Agent, Protected Executor e Agent onboarding passaram a refletir os recursos reais da T3N. Proposal Agent continua limitado a `evaluate-action`; Protected Executor continua limitado a `execute-remediation` e `verify-remediation`.
