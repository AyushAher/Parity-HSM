#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
export PARITY_HSM_VAULT="$WORK_DIR/token.vault"

cleanup() {
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

source "$ROOT_DIR/scripts/_pkcs11_validation_common.sh"

"$HARNESS" initialize-token "$MODULE_PATH" "$PIN"
