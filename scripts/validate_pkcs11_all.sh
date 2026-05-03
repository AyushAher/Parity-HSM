#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_PATH="${1:-$ROOT_DIR/build/libparity_pkcs11.so}"

"$ROOT_DIR/scripts/validate_pkcs11_general.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_initialize_token.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_slot_token.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_sessions.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_authentication.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_object_management.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_object_search.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_key_management.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_encrypt_decrypt.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_export.sh" "$MODULE_PATH"
"$ROOT_DIR/scripts/validate_pkcs11_sign_verify.sh" "$MODULE_PATH"

echo "All PKCS#11 validations passed."
