#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/docs/evidence/runtime"
mkdir -p "$OUTPUT_DIR"
SENTINEL_SCAN_STATUS="NOT_CONFIGURED"

run_and_capture() {
  local name="$1"
  shift
  echo "==> $name"
  "$@" 2>&1 | tee "$OUTPUT_DIR/$name.log"
}

run_and_capture rust-contract-properties bash -lc "cd '$ROOT_DIR/contracts/privacy-guard' && cargo test"
run_and_capture java-backend bash -lc "cd '$ROOT_DIR/backend' && mvn test"
run_and_capture t3n-gateway bash -lc "cd '$ROOT_DIR/t3n-gateway' && npm test && npm run typecheck"
run_and_capture react-frontend bash -lc "cd '$ROOT_DIR/frontend' && npm test && npm run typecheck"

if [[ -n "${EVIDENCE_SENTINEL_SECRET:-}" ]]; then
  if [[ ${#EVIDENCE_SENTINEL_SECRET} -lt 6 ]]; then
    echo "EVIDENCE_SENTINEL_SECRET must be at least 6 characters" >&2
    exit 1
  fi
  if grep -R -F -- "$EVIDENCE_SENTINEL_SECRET" "$OUTPUT_DIR" >/dev/null 2>&1; then
    echo "Local evidence contains the synthetic sentinel secret" >&2
    exit 1
  fi
  SENTINEL_SCAN_STATUS="PASS"
fi

cat > "$OUTPUT_DIR/summary.txt" <<SUMMARY
T3 Privacy Guard local evidence run
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Rust contract + property invariants: PASS
Java backend: PASS
T3N gateway local tests/typecheck (including deterministic schema properties): PASS
React frontend tests/typecheck: PASS
Secret sentinel scan: $SENTINEL_SCAN_STATUS

These are LOCAL results only, including property-generated cases. They are not T3N testnet execution evidence.
SUMMARY

cat "$OUTPUT_DIR/summary.txt"
