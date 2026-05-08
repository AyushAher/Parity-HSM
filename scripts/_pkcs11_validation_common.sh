#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_PATH="${1:-$ROOT_DIR/build/libparity_pkcs11.so}"
PIN="${PKCS11_PIN:-$(sed -n 's/.*"password":[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT_DIR/config/config.json" | head -n 1)}"
SO_PIN="${PKCS11_SO_PIN:-${PIN}so}"
HARNESS="$ROOT_DIR/build/pkcs11_validation_harness"
TEST_TMP_DIR="$(mktemp -d)"
export PARITY_HSM_VAULT="$TEST_TMP_DIR/token.vault"
export PARITY_HSM_VAULT_OFFSET=4096
export PARITY_HSM_VAULT_SLOT_SPAN=$((1024 * 1024))

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

truncate -s $((PARITY_HSM_VAULT_OFFSET + (PARITY_HSM_VAULT_SLOT_SPAN * 2))) "$PARITY_HSM_VAULT"

cleanup_test_tmp() {
  rm -rf "$TEST_TMP_DIR"
}

trap cleanup_test_tmp EXIT

if [[ "${PARITY_HSM_SKIP_BOOTSTRAP:-0}" != "1" ]]; then
  PKCS11_SO_PIN="$SO_PIN" "$HARNESS" initialize-token "$MODULE_PATH" "$PIN" >/dev/null
  PKCS11_SO_PIN="$SO_PIN" "$HARNESS" bootstrap-default-key "$MODULE_PATH" "$PIN" >/dev/null
fi
