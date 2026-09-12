#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/docs/evidence/runtime"
mkdir -p "$OUTPUT_DIR"

run_and_capture() {
  local name="$1"
  shift
  echo "==> $name"
  "$@" 2>&1 | tee "$OUTPUT_DIR/$name.log"
}

run_and_capture rust-contract bash -lc "cd '$ROOT_DIR/contracts/privacy-guard' && cargo test"
run_and_capture java-backend bash -lc "cd '$ROOT_DIR/backend' && mvn test"
run_and_capture t3n-gateway bash -lc "cd '$ROOT_DIR/t3n-gateway' && npm test && npm run typecheck"
run_and_capture react-frontend bash -lc "cd '$ROOT_DIR/frontend' && npm test && npm run typecheck"

cat > "$OUTPUT_DIR/summary.txt" <<SUMMARY
T3 Privacy Guard local evidence run
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Rust contract: PASS
Java backend: PASS
T3N gateway local tests/typecheck: PASS
React frontend tests/typecheck: PASS

These are LOCAL results only. They are not T3N testnet execution evidence.
SUMMARY

cat "$OUTPUT_DIR/summary.txt"
