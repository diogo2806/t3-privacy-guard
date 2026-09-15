FROM rust:1.90.0-alpine3.22 AS contract-build
WORKDIR /contract
RUN rustup target add wasm32-wasip2
COPY contracts/privacy-guard/Cargo.toml ./Cargo.toml
COPY contracts/privacy-guard/src ./src
COPY contracts/privacy-guard/wit ./wit
RUN cargo build --release --target wasm32-wasip2

FROM node:22.20.0-alpine3.22 AS gateway-build
WORKDIR /app
COPY t3n-gateway/package*.json ./
RUN npm install
COPY t3n-gateway/tsconfig.json ./
COPY t3n-gateway/src ./src
RUN npm run build

FROM node:22.20.0-alpine3.22
WORKDIR /app
ENV NODE_ENV=production \
    T3N_CONTRACT_WASM_PATH=/app/runtime/privacy_guard_contract.wasm \
    T3N_POLICY_FILE=/app/policy/privacy-guard-policy.json \
    AGENT_CARD_OUTPUT=/data/agent-card.json
COPY t3n-gateway/package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY --from=gateway-build /app/dist ./dist
COPY t3n-gateway/policy ./policy
RUN mkdir -p /app/runtime /data
COPY --from=contract-build /contract/target/wasm32-wasip2/release/privacy_guard_contract.wasm /app/runtime/privacy_guard_contract.wasm
RUN chown -R node:node /data
VOLUME ["/data"]
USER node
EXPOSE 3001
CMD ["node", "dist/index.js"]
