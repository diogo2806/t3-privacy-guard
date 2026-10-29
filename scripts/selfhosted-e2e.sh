#!/usr/bin/env bash
# End-to-end check of the two services without Docker: guard-runtime (Java) + app (backend serving the dashboard),
# driven through the backend API exactly as the dashboard drives it: login, incident, action, policy evaluation,
# human authorization, protected execution and independent read-back, plus the MCP endpoint and policy versioning
# (publish, stale approval refused, rollback). Every secret is generated for this run and discarded afterwards.
#
# Requirements: Java 21, Maven, Node 22+, curl. Ports default to 3101 (guard-runtime) and 8080 (app); override with
# RUNTIME_PORT and BACKEND_PORT.
# Usage: scripts/selfhosted-e2e.sh            (builds dashboard and jars first)
#        SKIP_BUILD=1 scripts/selfhosted-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_PORT="${RUNTIME_PORT:-3101}"
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
  step "Building dashboard, guard-runtime and app"
  (cd "$ROOT/frontend" && { [[ -d node_modules ]] || npm install --no-package-lock --no-audit --no-fund; } && npm run build && rm -f tsconfig.tsbuildinfo)
  mvn -B -q -f "$ROOT/guard-runtime/pom.xml" package -DskipTests
  mvn -B -q -f "$ROOT/backend/pom.xml" package -DskipTests
fi

PROPOSAL_TOKEN="$(random_secret)"
EXECUTOR_TOKEN="$(random_secret)"
POLICY_ADMIN_TOKEN="$(random_secret)"
MCP_TOKEN="$(random_secret)"
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
  GUARD_RUNTIME_POLICY_DIR="$WORK/runtime/policy" \
  GUARD_RUNTIME_REPLAY_FILE="$WORK/runtime/replay.json" \
  GUARD_RUNTIME_ACTIVITY_FILE="$WORK/runtime/activity.jsonl" \
  GUARD_RUNTIME_TENANT_ID=local \
  GUARD_RUNTIME_CALLERS_JSON="[{\"id\":\"agent:proposal\",\"token\":\"$PROPOSAL_TOKEN\",\"functions\":[\"evaluate-action\"]},{\"id\":\"agent:executor\",\"token\":\"$EXECUTOR_TOKEN\",\"functions\":[\"execute-remediation\",\"verify-remediation\"]},{\"id\":\"agent:policy-admin\",\"token\":\"$POLICY_ADMIN_TOKEN\",\"functions\":[\"manage-policy\"]}]" \
  GUARD_RUNTIME_VERIFIED_EMAIL=soc@example.test \
  GUARD_RUNTIME_ALLOW_INSECURE_HTTP=true \
  SECURITY_API_URL="$SECURITY_BASE/execute" \
  SECURITY_VERIFICATION_URL="$SECURITY_BASE/verify" \
  SECURITY_API_KEY="$SECURITY_API_KEY" \
  REMEDIATION_AUTH_KEY_ID=primary \
  REMEDIATION_AUTH_PUBLIC_KEY_SPKI="$CAPABILITY_PUBLIC_KEY" \
  java -jar "$ROOT/guard-runtime/target/guard-runtime-0.1.0.jar" > "$WORK/guard-runtime.log" 2>&1 &
PIDS+=($!)

step "Starting app (backend + dashboard) on :$BACKEND_PORT"
DASHBOARD_ENV=()
if [[ -f "$ROOT/frontend/dist/index.html" ]]; then
  # Serve the freshly built dashboard from disk; the Docker image packages it inside the jar instead.
  DIST="$ROOT/frontend/dist"
  if command -v cygpath > /dev/null; then DIST="$(cygpath -m "$DIST")"; fi # Git Bash: /c/... -> C:/... for Java
  DASHBOARD_ENV=(SPRING_WEB_RESOURCES_STATIC_LOCATIONS="file:$DIST/")
fi
env "${DASHBOARD_ENV[@]}" SERVER_PORT="$BACKEND_PORT" \
  DATABASE_URL="jdbc:h2:file:$WORK/backend/privacyguard" \
  GUARD_RUNTIME_URL="http://localhost:$RUNTIME_PORT" \
  GUARD_RUNTIME_PROPOSAL_TOKEN="$PROPOSAL_TOKEN" \
  GUARD_RUNTIME_EXECUTOR_TOKEN="$EXECUTOR_TOKEN" \
  GUARD_RUNTIME_POLICY_ADMIN_TOKEN="$POLICY_ADMIN_TOKEN" \
  MCP_TOKEN="$MCP_TOKEN" \
  SECURITY_API_KEY="$SECURITY_API_KEY" \
  REMEDIATION_AUTH_PRIVATE_KEY_PKCS8="$CAPABILITY_PRIVATE_KEY" \
  REMEDIATION_AUTH_KEY_ID=primary \
  AUDIT_INTEGRITY_KEY="$AUDIT_KEY" \
  OPERATOR_USERNAME=operator \
  OPERATOR_PASSWORD="$OPERATOR_PASSWORD" \
  SESSION_COOKIE_SECURE=false \
  java -jar "$ROOT/backend/target/backend-0.1.0.jar" > "$WORK/backend.log" 2>&1 &
PIDS+=($!)

wait_for "http://localhost:$RUNTIME_PORT/actuator/health"
wait_for "http://localhost:$BACKEND_PORT/actuator/health"

APP="http://localhost:$BACKEND_PORT"
API="$APP/api"
JAR="$WORK/cookies.txt"
csrf() { curl -s -c "$JAR" -b "$JAR" "$API/auth/csrf" | json token; }
post() { curl -s -c "$JAR" -b "$JAR" -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $(csrf)" -X POST "$API$1" -d "${2:-{\}}"; }
get() { curl -s -c "$JAR" -b "$JAR" "$API$1"; }
mcp() { curl -s -H "Authorization: Bearer $MCP_TOKEN" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" -X POST "$APP/mcp" -d "$1"; }

step "Dashboard served by the app"
if [[ ${#DASHBOARD_ENV[@]} -gt 0 ]]; then
  DASHBOARD_STATUS="$(curl -s -o "$WORK/index.html" -w '%{http_code}' "$APP/")"
  echo "GET / -> HTTP $DASHBOARD_STATUS, $(grep -c '<div id="root">' "$WORK/index.html") root element(s), CSP: $(curl -sI "$APP/" | grep -ci '^content-security-policy')"
else
  DASHBOARD_STATUS=skipped
  echo "frontend/dist not built; skipped"
fi

step "Operator login"
post /auth/login "{\"username\":\"operator\",\"password\":\"$OPERATOR_PASSWORD\"}" | json authenticated

step "System status as the dashboard sees it"
STATUS="$(get /system/status)"
echo "evaluationReady=$(json evaluationReady <<<"$STATUS") protectedRemediationReady=$(json protectedRemediationReady <<<"$STATUS") enterpriseIntegration=$(json enterpriseIntegrationState <<<"$STATUS")"
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

step "Protected execution (capability -> guard-runtime -> security API)"
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
if grep -q "soc@example.test" "$WORK/backend.log"; then EMAIL_SEEN=yes; else EMAIL_SEEN=no; fi
echo "verified email in backend logs: $EMAIL_SEEN"

step "Audit evidence: local HMAC chain reconciled with guard-runtime's activity log"
AUDIT="$(get "/incidents/$INCIDENT_ID/audit-evidence")"
echo "integrity=$(json integrity.state <<<"$AUDIT") matched=$(json provenance.matched <<<"$AUDIT") unmatched=$(json provenance.unmatched <<<"$AUDIT") localOnly=$(json provenance.localOnly <<<"$AUDIT") runtimeOnly=$(json provenance.runtimeOnly <<<"$AUDIT")"

step "MCP: an external agent asks the guard before acting"
echo "initialize: $(mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}' | json result.serverInfo.name)"
echo "tools: $(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).result.tools.map(t=>t.name).join(', ')))")"
MCP_DECISION="$(mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"privacy.evaluate_action","arguments":{"request_id":"mcp-001","action":"revoke-credential","resource":"credential:cred-42","purpose":"incident-remediation","host":"localhost","fields":["incident_id","api_key"]}}}' | json result.content.0.text | json decision)"
echo "evaluate with api_key -> $MCP_DECISION"
MCP_UNAUTHORIZED="$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -X POST "$APP/mcp" -d '{"jsonrpc":"2.0","id":1,"method":"ping"}')"
echo "without token -> HTTP $MCP_UNAUTHORIZED"

step "Policy versioning: an approval does not survive a policy change"
POLICY="$(get /policy)"
SEED_VERSION="$(json version <<<"$POLICY")"
echo "active=$SEED_VERSION managed=$(json managed <<<"$POLICY")"
STALE_ID="$(post "/incidents/$INCIDENT_ID/actions" '{"requestId":"e2e-revoke-002","action":"revoke-credential","resource":"credential:cred-43","purpose":"incident-remediation","host":"localhost","fields":["incident_id","credential_id","reason"],"privateRefs":[]}' | json id)"
echo "decision under $SEED_VERSION: $(json decision <<<"$(post "/incidents/$INCIDENT_ID/actions/$STALE_ID/evaluate")")"
post "/incidents/$INCIDENT_ID/actions/$STALE_ID/authorize-remediation" > /dev/null
PUBLISH_BODY="$(node -e "const p=JSON.parse(process.argv[1]);p.document.version=p.version+'-e2e';console.log(JSON.stringify({document:p.document,expectedCurrentHash:p.hash}))" "$POLICY")"
PUBLISHED="$(post /policy/publish "$PUBLISH_BODY")"
NEW_VERSION="$(json version <<<"$PUBLISHED")"
echo "published $NEW_VERSION (previous $(json previousVersion <<<"$PUBLISHED"))"
STALE_EXECUTION="$(post "/incidents/$INCIDENT_ID/actions/$STALE_ID/execute-remediation")"
STALE_STATE="$(json state <<<"$STALE_EXECUTION")"
STALE_FAILURE="$(json failureCode <<<"$STALE_EXECUTION")"
echo "execute the approval from $SEED_VERSION -> state=${STALE_STATE:-refused} ${STALE_FAILURE}$(json detail <<<"$STALE_EXECUTION")"
CONFLICT_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -b "$JAR" -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $(csrf)" -X POST "$API/policy/publish" -d "$PUBLISH_BODY")"
echo "publish again with the old hash -> HTTP $CONFLICT_STATUS"
ROLLED_BACK="$(post /policy/rollback "{\"version\":\"$SEED_VERSION\",\"expectedCurrentHash\":\"$(json hash <<<"$PUBLISHED")\"}")"
ACTIVE_AFTER="$(json version <<<"$(get /policy)")"
echo "rolled back to $(json version <<<"$ROLLED_BACK"); active=$ACTIVE_AFTER"
get "/policy/history" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{for(const e of JSON.parse(s))console.log('  #'+e.sequence+' '+e.operation+' '+e.version+' requested by '+(e.requestedBy||'-')+' via '+e.caller)})"

step "guard-runtime activity log"
if [[ -s "$WORK/runtime/activity.jsonl" ]]; then
  node -e "for(const l of require('fs').readFileSync(process.argv[1],'utf8').trim().split('\n')){const e=JSON.parse(l);console.log('  #'+e.sequence+' '+e.actorDid+' '+e.function+' '+e.outcome)}" "$WORK/runtime/activity.jsonl"
fi

step "Secrets never logged"
LEAKS=0
for secret in "$PROPOSAL_TOKEN" "$EXECUTOR_TOKEN" "$POLICY_ADMIN_TOKEN" "$MCP_TOKEN" "$SECURITY_API_KEY" "$OPERATOR_PASSWORD"; do
  if grep -q -- "$secret" "$WORK"/*.log; then LEAKS=$((LEAKS + 1)); fi
done
echo "secrets found in logs: $LEAKS"

if [[ "$FINAL_STATE" == "COMPLETED" && "$NOTIFY_STATE" == "COMPLETED" && "$LEAKS" == "0" && "$EMAIL_SEEN" == "no" \
  && "$MCP_DECISION" == "DENY" && "$MCP_UNAUTHORIZED" == "401" && "$DASHBOARD_STATUS" =~ ^(200|skipped)$ \
  && -n "$NEW_VERSION" && "$STALE_STATE" == "FAILED" && "$STALE_FAILURE" == "POLICY_CHANGED_AFTER_AUTHORIZATION" && "$CONFLICT_STATUS" == "409" \
  && "$ACTIVE_AFTER" == "$SEED_VERSION" ]]; then
  printf '\nPASS: both remediations independently verified and COMPLETED; MCP and dashboard served by the app; a policy change voided the old approval and rollback restored the version.\n'
else
  printf '\nFAIL: revoke %s, notify %s, secrets in logs %s, email seen %s, MCP %s/%s, dashboard %s, policy published %s / stale approval %s / conflict %s / active after rollback %s. Re-run with KEEP_WORK=1 to inspect logs.\n' \
    "$FINAL_STATE" "$NOTIFY_STATE" "$LEAKS" "$EMAIL_SEEN" "$MCP_DECISION" "$MCP_UNAUTHORIZED" "$DASHBOARD_STATUS" "${NEW_VERSION:-no}" "${STALE_STATE:-refused}" "$CONFLICT_STATUS" "$ACTIVE_AFTER"
  exit 1
fi
