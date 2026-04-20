#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <vector>
#include <stdexcept>

std::vector<uint8_t> generate_rsa_private(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) throw std::runtime_error("Failed to create context");

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        throw std::runtime_error("Keygen init failed");

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        throw std::runtime_error("Set bits failed");

    EVP_PKEY* pkey = nullptr;

    if (EVP_PKEY_generate(ctx, &pkey) <= 0)
        throw std::runtime_error("Key generation failed");

    // Convert to DER
    int len = i2d_PrivateKey(pkey, NULL);
    if (len <= 0) throw std::runtime_error("DER size failed");

    std::vector<uint8_t> der(len);
    unsigned char* p = der.data();

    if (i2d_PrivateKey(pkey, &p) <= 0)
        throw std::runtime_error("DER encode failed");

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return der;
}