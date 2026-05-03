#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_PATH="${1:-$ROOT_DIR/build/libparity_pkcs11.so}"
PIN="${PKCS11_PIN:-$(sed -n 's/.*"password":[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT_DIR/config/config.json" | head -n 1)}"
HARNESS="$ROOT_DIR/build/pkcs11_validation_harness"

if [[ ! -f "$MODULE_PATH" ]]; then
  echo "PKCS#11 module not found: $MODULE_PATH" >&2
  exit 1
fi

if [[ -z "$PIN" ]]; then
  echo "Unable to determine PKCS#11 PIN. Set PKCS11_PIN or update config/config.json." >&2
  exit 1
fi

c++ -std=c++17 -I "$ROOT_DIR/include" \
  "$ROOT_DIR/scripts/pkcs11_validation_harness.cpp" \
  -o "$HARNESS"
