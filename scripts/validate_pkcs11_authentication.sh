#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/_pkcs11_validation_common.sh"

"$HARNESS" auth "$MODULE_PATH" "$PIN"
