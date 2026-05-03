#include "parity_hsm/common.hpp"
#include "parity_hsm/vault.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

extern std::vector<uint8_t> generate_rsa_private(int bits);

// =========================
// GENERATE + STORE
// =========================
void generate_and_store(const std::string& config_path) {
    std::ifstream f(config_path);
    json cfg;
    f >> cfg;

    int bits = cfg["key_size"];
    std::string password = cfg["password"];

    if (!hsm_vault_exists())
        hsm_vault_initialize(password, "ParityHSM");

    auto key = hsm_vault_generate_rsa_key(password, "", "ParityKey", bits);

    std::cout << "Key generated and stored in hidden HSM vault\n";
    std::cout << "Vault: " << hsm_vault_path() << std::endl;
    std::cout << "Key ID: " << key.id_hex << std::endl;
}

// =========================
// VALIDATE RSA KEY
// =========================
void validate_rsa_key(const std::vector<uint8_t>& der) {
    const unsigned char* p = der.data();

    EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &p, der.size());

    if (!pkey) {
        std::cerr << "❌ Key validation failed\n";
        return;
    }

    std::cout << "✅ RSA Key successfully validated!\n";

    EVP_PKEY_free(pkey);
}

// =========================
// RECOVER KEY
// =========================
void recover_key(
    const std::string& usb,
    size_t offset,
    const std::string& password
) {
    std::cout << "Starting recovery...\n";
    hsm_vault_import_legacy_if_needed(password);
    auto A = hsm_vault_default_private_key(password);
    std::cout << "Reconstructed key from hidden parity vault\n";
    validate_rsa_key(A);
}
