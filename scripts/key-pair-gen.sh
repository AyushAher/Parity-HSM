#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/_pkcs11_validation_common.sh"

for id in 02 03 04; do
  pkcs11-tool \
    --module "$MODULE_PATH" \
    --login --pin "$PIN" \
    --keypairgen \
    --key-type rsa:4096 \
    --id "$id" \
    --label "ParityKey-$id" >/dev/null
done

echo "Key pair generation script completed"
