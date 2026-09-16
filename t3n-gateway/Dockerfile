FROM rust:1.90.0-alpine3.22 AS contract-build
WORKDIR /contract
RUN apk add --no-cache build-base musl-dev
RUN rustup target add wasm32-wasip2
COPY contract-source/Cargo.toml ./Cargo.toml
COPY contract-source/src ./src
COPY contract-source/wit ./wit
RUN cargo build --release --target wasm32-wasip2

FROM node:22.20.0-alpine3.22 AS gateway-build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22.20.0-alpine3.22
ARG EVIDENCE_SOURCE_COMMIT_SHA=""
ARG EVIDENCE_SOURCE_TREE_CLEAN=""
WORKDIR /app
ENV NODE_ENV=production \
    T3N_CONTRACT_WASM_PATH=/app/runtime/privacy_guard_contract.wasm \
    T3N_POLICY_FILE=/app/policy/privacy-guard-policy.json \
    AGENT_CARD_OUTPUT=/data/agent-card.json \
    T3N_RUNTIME_PROVISIONING_STATE_PATH=/data/t3n-runtime-provisioning.json \
    EVIDENCE_RUNTIME_DIR=/data/evidence \
    EVIDENCE_SOURCE_REVISION_FILE=/app/runtime/source-revision.json
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY --from=gateway-build /app/dist ./dist
COPY policy ./policy
RUN mkdir -p /app/runtime /data/evidence
COPY --from=contract-build /contract/target/wasm32-wasip2/release/privacy_guard_contract.wasm /app/runtime/privacy_guard_contract.wasm
RUN if [ -n "$EVIDENCE_SOURCE_COMMIT_SHA" ] && ! printf '%s' "$EVIDENCE_SOURCE_COMMIT_SHA" | grep -Eq '^[a-f0-9]{40}$'; then echo 'EVIDENCE_SOURCE_COMMIT_SHA must be a full lowercase 40-character Git SHA' >&2; exit 1; fi \
    && if [ -n "$EVIDENCE_SOURCE_TREE_CLEAN" ] && [ "$EVIDENCE_SOURCE_TREE_CLEAN" != "true" ] && [ "$EVIDENCE_SOURCE_TREE_CLEAN" != "false" ]; then echo 'EVIDENCE_SOURCE_TREE_CLEAN must be true or false' >&2; exit 1; fi \
    && CLEAN_VALUE=false \
    && if [ "$EVIDENCE_SOURCE_TREE_CLEAN" = "true" ]; then CLEAN_VALUE=true; fi \
    && printf '{"sourceCommitSha":"%s","sourceTreeClean":%s}\n' "$EVIDENCE_SOURCE_COMMIT_SHA" "$CLEAN_VALUE" > /app/runtime/source-revision.json \
    && chmod 0444 /app/runtime/source-revision.json \
    && test -f /app/dist/scripts/register-contract.js \
    && test -f /app/dist/scripts/setup-policy.js \
    && test -f /app/dist/scripts/setup-remediation-secrets.js \
    && test -f /app/dist/scripts/agent-card-verify.js \
    && test -f /app/dist/scripts/agent-card-publish.js \
    && test -f /app/dist/scripts/live-evidence.js \
    && test -f /app/dist/scripts/adversarial-testnet.js \
    && test -f /app/dist/scripts/human-proof-testnet.js \
    && test -f /app/dist/scripts/profile-placeholder-evidence.js \
    && test -f /app/dist/provisioning/runtime-provisioning.js \
    && test -f /app/policy/privacy-guard-policy.json \
    && test -s /app/runtime/privacy_guard_contract.wasm \
    && chown -R node:node /data
VOLUME ["/data"]
USER node
EXPOSE 3001
CMD ["node", "dist/index.js"]
