#!/usr/bin/env bash
# End-to-end check of the self-hosted stack without Docker and without Terminal 3:
# guard-runtime (Java) + gateway (TRUST_RUNTIME=selfhosted) + backend, driven through the backend API exactly as
# the dashboard drives it: login, incident, action, policy evaluation, human authorization, protected execution
# and independent read-back. Every secret is generated for this run and discarded afterwards.
#
# Requirements: Java 21, Maven, Node 22+, curl. Ports default to 3101 (guard-runtime), 3001 (gateway) and 8080
# (backend); override with RUNTIME_PORT, GATEWAY_PORT and BACKEND_PORT.
# Usage: scripts/selfhosted-e2e.sh            (builds the jars first)
#        SKIP_BUILD=1 scripts/selfhosted-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_PORT="${RUNTIME_PORT:-3101}"
GATEWAY_PORT="${GATEWAY_PORT:-3001}"
BACKEND_PORT="${BACKEND_PORT:-8080}"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "${KEEP_WORK:-0}" == "1" ]]; then echo "Logs kept in $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

random_secret() { node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"; }
# json <path> reads JSON on stdin and prints the value at a dotted path (array indexes allowed).
json() { node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{let v=JSON.parse(s);for(const k of process.argv[1].split('.'))v=v?.[k];process.stdout.write(v==null?'':typeof v==='object'?JSON.stringify(v):String(v))})" "$1"; }
wait_for() { curl -s -o /dev/null --retry 90 --retry-connrefused --retry-delay 1 "$1" || { echo "Timed out waiting for $1" >&2; exit 1; }; }
step() { printf '\n== %s\n' "$1"; }

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  step "Building guard-runtime and backend"
  mvn -B -q -f "$ROOT/guard-runtime/pom.xml" package -DskipTests
  mvn -B -q -f "$ROOT/backend/pom.xml" package -DskipTests
fi
[[ -d "$ROOT/t3n-gateway/node_modules" ]] || (cd "$ROOT/t3n-gateway" && npm install --no-package-lock --no-audit --no-fund)

GATEWAY_TOKEN="$(random_secret)"
PROPOSAL_TOKEN="$(random_secret)"
EXECUTOR_TOKEN="$(random_secret)"
SECURITY_API_KEY="$(random_secret)"
AUDIT_KEY="$(random_secret)"
OPERATOR_PASSWORD="$(random_secret)"
read -r CAPABILITY_PRIVATE_KEY CAPABILITY_PUBLIC_KEY < <(node -e "
const { generateKeyPairSync } = require('crypto');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
console.log(privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'), publicKey.export({ format: 'der', type: 'spki' }).toString('base64'));")
SECURITY_BASE="http://localhost:$BACKEND_PORT/api/security/remediation"

step "Starting guard-runtime on :$RUNTIME_PORT"
env GUARD_RUNTIME_PORT="$RUNTIME_PORT" \
  GUARD_RUNTIME_POLICY_FILE="$ROOT/deploy/local/policy.json" \
  GUARD_RUNTIME_REPLAY_FILE="$WORK/runtime/replay.json" \
  GUARD_RUNTIME_ACTIVITY_FILE="$WORK/runtime/activity.jsonl" \
  GUARD_RUNTIME_TENANT_ID=local \
  GUARD_RUNTIME_CALLERS_JSON="[{\"id\":\"agent:proposal\",\"token\":\"$PROPOSAL_TOKEN\",\"functions\":[\"evaluate-action\"]},{\"id\":\"agent:executor\",\"token\":\"$EXECUTOR_TOKEN\",\"functions\":[\"execute-remediation\",\"verify-remediation\"]}]" \
  GUARD_RUNTIME_VERIFIED_EMAIL=soc@example.test \
  GUARD_RUNTIME_ALLOW_INSECURE_HTTP=true \
  SECURITY_API_URL="$SECURITY_BASE/execute" \
  SECURITY_VERIFICATION_URL="$SECURITY_BASE/verify" \
  SECURITY_API_KEY="$SECURITY_API_KEY" \
  REMEDIATION_AUTH_KEY_ID=primary \
  REMEDIATION_AUTH_PUBLIC_KEY_SPKI="$CAPABILITY_PUBLIC_KEY" \
  java -jar "$ROOT/guard-runtime/target/guard-runtime-0.1.0.jar" > "$WORK/guard-runtime.log" 2>&1 &
PIDS+=($!)

step "Starting gateway on :$GATEWAY_PORT (TRUST_RUNTIME=selfhosted, no T3N_* settings)"
# exec makes the background PID the node process itself, so cleanup really stops it.
(cd "$ROOT/t3n-gateway" && exec env -u T3N_API_KEY -u T3N_AGENT_API_KEY -u T3N_EXECUTOR_API_KEY \
  TRUST_RUNTIME=selfhosted \
  T3N_GATEWAY_PORT="$GATEWAY_PORT" \
  GATEWAY_SERVICE_TOKEN="$GATEWAY_TOKEN" \
  REMEDIATION_AUTH_PUBLIC_KEY_SPKI="$CAPABILITY_PUBLIC_KEY" \
  REMEDIATION_REPLAY_STORE_PATH="$WORK/gateway/replay.json" \
  GUARD_RUNTIME_URL="http://localhost:$RUNTIME_PORT" \
  GUARD_RUNTIME_PROPOSAL_TOKEN="$PROPOSAL_TOKEN" \
  GUARD_RUNTIME_EXECUTOR_TOKEN="$EXECUTOR_TOKEN" \
  node --import tsx src/index.ts > "$WORK/gateway.log" 2>&1) &
PIDS+=($!)

step "Starting backend on :$BACKEND_PORT"
env SERVER_PORT="$BACKEND_PORT" \
  DATABASE_URL="jdbc:h2:file:$WORK/backend/privacyguard" \
  T3N_GATEWAY_URL="http://localhost:$GATEWAY_PORT" \
  GATEWAY_SERVICE_TOKEN="$GATEWAY_TOKEN" \
  SECURITY_API_KEY="$SECURITY_API_KEY" \
  REMEDIATION_AUTH_PRIVATE_KEY_PKCS8="$CAPABILITY_PRIVATE_KEY" \
  REMEDIATION_AUTH_KEY_ID=primary \
  AUDIT_INTEGRITY_KEY="$AUDIT_KEY" \
  OPERATOR_USERNAME=operator \
  OPERATOR_PASSWORD="$OPERATOR_PASSWORD" \
  EVIDENCE_MANIFEST_PATH="$WORK/none-manifest.json" \
  EVIDENCE_TESTNET_PATH="$WORK/none-testnet.json" \
  java -jar "$ROOT/backend/target/backend-0.1.0.jar" > "$WORK/backend.log" 2>&1 &
PIDS+=($!)

wait_for "http://localhost:$RUNTIME_PORT/actuator/health"
wait_for "http://localhost:$GATEWAY_PORT/health"
wait_for "http://localhost:$BACKEND_PORT/actuator/health"

API="http://localhost:$BACKEND_PORT/api"
JAR="$WORK/cookies.txt"
csrf() { curl -s -c "$JAR" -b "$JAR" "$API/auth/csrf" | json token; }
post() { curl -s -c "$JAR" -b "$JAR" -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $(csrf)" -X POST "$API$1" -d "${2:-{\}}"; }
get() { curl -s -c "$JAR" -b "$JAR" "$API$1"; }

step "Operator login"
post /auth/login "{\"username\":\"operator\",\"password\":\"$OPERATOR_PASSWORD\"}" | json authenticated

step "System status as the dashboard sees it"
STATUS="$(get /system/status)"
echo "network=$(json network <<<"$STATUS") evaluationReady=$(json evaluationReady <<<"$STATUS") protectedRemediationReady=$(json protectedRemediationReady <<<"$STATUS") enterpriseIntegration=$(json enterpriseIntegrationState <<<"$STATUS")"
echo "message: $(json message <<<"$STATUS")"

step "Incident and AI-proposed action asking for one field too many"
INCIDENT_ID="$(post /incidents '{"title":"Leaked deploy credential","severity":"HIGH","summary":"Credential cred-42 found in a public paste","source":"e2e"}' | json id)"
ACTION_ID="$(post "/incidents/$INCIDENT_ID/actions" '{"requestId":"e2e-revoke-001","action":"revoke-credential","resource":"credential:cred-42","purpose":"incident-remediation","host":"localhost","fields":["incident_id","credential_id","reason","employee_department"],"privateRefs":[]}' | json id)"
echo "incident=$INCIDENT_ID action=$ACTION_ID"

step "Policy evaluation (guard-runtime)"
DECISION="$(post "/incidents/$INCIDENT_ID/actions/$ACTION_ID/evaluate")"
echo "decision=$(json decision <<<"$DECISION") reason=$(json reasonCode <<<"$DECISION") redacted=$(json redactedFields <<<"$DECISION")"

step "Human authorization"
post "/incidents/$INCIDENT_ID/actions/$ACTION_ID/authorize-remediation" | json state

step "Protected execution (capability -> gateway -> guard-runtime -> security API)"
EXECUTION="$(post "/incidents/$INCIDENT_ID/actions/$ACTION_ID/execute-remediation")"
echo "state=$(json state <<<"$EXECUTION")"

step "Independent read-back"
VERIFICATION="$(post "/incidents/$INCIDENT_ID/actions/$ACTION_ID/verify-remediation")"
FINAL_STATE="$(json state <<<"$VERIFICATION")"
echo "state=$FINAL_STATE"

step "Execution trace"
get "/incidents/$INCIDENT_ID/actions/$ACTION_ID/trace" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{for(const e of JSON.parse(s))console.log('  '+e.stage+' '+e.state+(e.reasonCode?' ('+e.reasonCode+')':''))})"

step "Private notification: verified_email is resolved only inside guard-runtime's egress"
NOTIFY_ID="$(post "/incidents/$INCIDENT_ID/actions" '{"requestId":"e2e-notify-001","action":"notify-security","resource":"incident:leaked-credential","purpose":"incident-notification","host":"localhost","fields":["incident_id","severity","summary"],"privateRefs":["verified_email"]}' | json id)"
NOTIFY_DECISION="$(post "/incidents/$INCIDENT_ID/actions/$NOTIFY_ID/evaluate")"
echo "decision=$(json decision <<<"$NOTIFY_DECISION") allowedPrivateRefs=$(json allowedPrivateRefs <<<"$NOTIFY_DECISION")"
post "/incidents/$INCIDENT_ID/actions/$NOTIFY_ID/authorize-remediation" > /dev/null
post "/incidents/$INCIDENT_ID/actions/$NOTIFY_ID/execute-remediation" > /dev/null
NOTIFY_STATE="$(json state <<<"$(post "/incidents/$INCIDENT_ID/actions/$NOTIFY_ID/verify-remediation")")"
echo "state=$NOTIFY_STATE"
if grep -q "soc@example.test" "$WORK/backend.log" "$WORK/gateway.log"; then EMAIL_SEEN=yes; else EMAIL_SEEN=no; fi
echo "verified email in backend or gateway logs: $EMAIL_SEEN"

step "Audit evidence: local HMAC chain reconciled with guard-runtime's activity log"
AUDIT="$(get "/incidents/$INCIDENT_ID/audit-evidence")"
echo "integrity=$(json integrity.state <<<"$AUDIT") runtimeAvailable=$(json provenance.t3nAvailable <<<"$AUDIT") matched=$(json provenance.matched <<<"$AUDIT") unmatched=$(json provenance.unmatched <<<"$AUDIT") localOnly=$(json provenance.localOnly <<<"$AUDIT") runtimeOnly=$(json provenance.t3nOnly <<<"$AUDIT")"
echo "message: $(json provenance.message <<<"$AUDIT")"

step "guard-runtime activity log"
if [[ -s "$WORK/runtime/activity.jsonl" ]]; then
  node -e "for(const l of require('fs').readFileSync(process.argv[1],'utf8').trim().split('\n')){const e=JSON.parse(l);console.log('  #'+e.sequence+' '+e.actorDid+' '+e.function+' '+e.outcome)}" "$WORK/runtime/activity.jsonl"
else
  echo "  (empty)"
fi

step "Secrets never logged"
LEAKS=0
for secret in "$GATEWAY_TOKEN" "$PROPOSAL_TOKEN" "$EXECUTOR_TOKEN" "$SECURITY_API_KEY" "$OPERATOR_PASSWORD"; do
  if grep -q -- "$secret" "$WORK"/*.log; then LEAKS=$((LEAKS + 1)); fi
done
echo "secrets found in logs: $LEAKS"

if [[ "$FINAL_STATE" == "COMPLETED" && "$NOTIFY_STATE" == "COMPLETED" && "$LEAKS" == "0" && "$EMAIL_SEEN" == "no" ]]; then
  printf '\nPASS: both remediations independently verified and COMPLETED without Terminal 3.\n'
else
  printf '\nFAIL: revoke %s, notify %s, secrets in logs %s, email seen %s. Re-run with KEEP_WORK=1 to inspect logs.\n' \
    "$FINAL_STATE" "$NOTIFY_STATE" "$LEAKS" "$EMAIL_SEEN"
  exit 1
fi
