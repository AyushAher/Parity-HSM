#include "parity_hsm/common.hpp"
#include <openssl/rand.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <iostream>
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