#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/_pkcs11_validation_common.sh"
OBJECT_ID="${PKCS11_OBJECT_ID:-01}"

WORK_DIR="$(mktemp -d)"
DER_PATH="$WORK_DIR/public.der"
PEM_PATH="$WORK_DIR/public.pem"

cleanup() {
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

echo "Exporting public key from $MODULE_PATH"
pkcs11-tool \
  --module "$MODULE_PATH" \
  --read-object \
  --type pubkey \
  --id "$OBJECT_ID" \
  --login \
  --pin "$PIN" \
  --output-file "$DER_PATH"

echo "Converting DER to PEM"
openssl pkey -pubin -inform DER -in "$DER_PATH" -out "$PEM_PATH"

KEY_INFO="$(openssl pkey -pubin -inform PEM -in "$PEM_PATH" -text -noout)"
echo "$KEY_INFO"

if ! grep -q "Public-Key: (2048 bit)" <<<"$KEY_INFO"; then
  echo "Exported key is not 2048 bits" >&2
  exit 1
fi

echo "Validation passed: exported public key converts to a 2048-bit PEM key."
