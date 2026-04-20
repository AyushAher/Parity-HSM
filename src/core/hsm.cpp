#include "parity_hsm/common.hpp"
#include <openssl/rand.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <iostream>
#include <openssl/evp.h>

using json = nlohmann::json;

extern std::vector<uint8_t> generate_rsa_private(int bits);

void generate_and_store(const std::string& config_path) {
    std::ifstream f(config_path);
    json cfg;
    f >> cfg;

    std::string usb = cfg["usb_path"];
    size_t offset = cfg["usb_offset"];
    int bits = cfg["key_size"];
    std::string password = cfg["password"];
    auto priv = generate_rsa_private(bits);

    // Generate B
    std::vector<uint8_t> B(priv.size());
    RAND_bytes(B.data(), B.size());

    // Compute C
    auto C = xor_data(priv, B);

    // 🔐 Encrypt all shares
    auto A_enc = aes_encrypt(priv, password);
    auto B_enc = aes_encrypt(B, password);
    auto C_enc = aes_encrypt(C, password);

    // Store
    usb_write(usb, offset, A_enc);
    save_file("B.enc", B_enc);
    save_file("C.enc", C_enc);

    std::cout << "Priv size: " << priv.size() << std::endl;
    std::cout << "A_enc size: " << A_enc.size() << std::endl;
}


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


void recover_key(
    const std::string& usb,
    size_t offset,
    const std::string& password
) {
    std::cout << "Starting recovery...\n";

    // 1. Load encrypted shares
    auto B_enc = load_file("B.enc");
    auto C_enc = load_file("C.enc");

    // 2. Decrypt
    auto B = aes_decrypt(B_enc, password);
    auto C = aes_decrypt(C_enc, password);

    std::cout << "Decrypted B & C\n";

    // 3. Reconstruct A
    auto A = xor_data(B, C);

    std::cout << "Reconstructed A (key material)\n";

    // 4. Re-encrypt A for USB
    auto A_enc = aes_encrypt(A, password);

    // 5. Write back to USB
    usb_write(usb, offset, A_enc);

    std::cout << "Rewritten encrypted A to USB\n";

    // 6. Validate key
    validate_rsa_key(A);
}
