#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/_pkcs11_validation_common.sh"
OBJECT_ID="${PKCS11_OBJECT_ID:-01}"

WORK_DIR="$(mktemp -d)"
PUBLIC_DER="$WORK_DIR/public.der"
PUBLIC_PEM="$WORK_DIR/public.pem"
SIGNATURE="$WORK_DIR/signature.bin"

cleanup() {
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

pkcs11-tool \
  --module "$MODULE_PATH" \
  --read-object \
  --type pubkey \
  --id "$OBJECT_ID" \
  --login \
  --pin "$PIN" \
  --output-file "$PUBLIC_DER"

openssl pkey -pubin -inform DER -in "$PUBLIC_DER" -out "$PUBLIC_PEM"

pkcs11-tool \
  --module "$MODULE_PATH" \
  --sign \
  --mechanism SHA256-RSA-PKCS \
  --type privkey \
  --id "$OBJECT_ID" \
  --login \
  --pin "$PIN" \
  --input-file "$ROOT_DIR/config/config.json" \
  --output-file "$SIGNATURE"

openssl dgst -sha256 -verify "$PUBLIC_PEM" -signature "$SIGNATURE" "$ROOT_DIR/config/config.json"

echo "Validation passed: PKCS#11 signature verifies with OpenSSL."
