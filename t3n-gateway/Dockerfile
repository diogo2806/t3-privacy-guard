FROM rust:1.90.0-alpine3.22 AS contract-build
WORKDIR /contract
RUN rustup target add wasm32-wasip2
COPY contracts/privacy-guard/ ./
RUN cargo build --target wasm32-wasip2 --release

FROM node:22.20.0-alpine3.22 AS build
WORKDIR /app
COPY t3n-gateway/package*.json ./
RUN npm install
COPY t3n-gateway/tsconfig.json ./
COPY t3n-gateway/src ./src
RUN npm run build

FROM node:22.20.0-alpine3.22
WORKDIR /app
ENV NODE_ENV=production
ENV T3N_POLICY_FILE=policy/privacy-guard-policy.json
ENV T3N_CONTRACT_WASM_PATH=contracts/privacy_guard_contract.wasm
COPY t3n-gateway/package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY t3n-gateway/policy ./policy
RUN mkdir -p /app/contracts /data && chown node:node /data
COPY --from=contract-build /contract/target/wasm32-wasip2/release/privacy_guard_contract.wasm /app/contracts/privacy_guard_contract.wasm
USER node
RUN npm run runtime:preflight
VOLUME ["/data"]
EXPOSE 3001
CMD ["node", "dist/index.js"]
