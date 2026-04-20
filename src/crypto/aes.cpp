#include "parity_hsm/common.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>
#include <cstring>
#include <iostream>

static const int SALT_LEN = 16;
static const int IV_LEN = 12;
static const int TAG_LEN = 16;
static const int KEY_LEN = 32;

// 🔑 Argon2 Key Derivation
std::vector<uint8_t> derive_key(const std::string& password, const uint8_t* salt) {
    std::vector<uint8_t> key(KEY_LEN);

    int result = argon2id_hash_raw(
        3,          // iterations
        1 << 16,    // memory (64MB)
        1,          // parallelism
        password.data(),
        password.size(),
        salt,
        SALT_LEN,
        key.data(),
        KEY_LEN
    );

    if (result != ARGON2_OK) {
        throw std::runtime_error("Argon2 failed");
    }

    return key;
}

// 🔐 Encrypt (AES-256-GCM)
std::vector<uint8_t> aes_encrypt(
    const std::vector<uint8_t>& data,
    const std::string& password
) {
    uint8_t salt[SALT_LEN];
    uint8_t iv[IV_LEN];

    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(iv, IV_LEN);

    auto key = derive_key(password, salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    std::vector<uint8_t> ciphertext(data.size());
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv);

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size());
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    uint8_t tag[TAG_LEN];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ctx);

    // Combine all parts
    std::vector<uint8_t> out;
    out.insert(out.end(), salt, salt + SALT_LEN);
    out.insert(out.end(), iv, iv + IV_LEN);
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    out.insert(out.end(), tag, tag + TAG_LEN);

    return out;
}

// 🔓 Decrypt
std::vector<uint8_t> aes_decrypt(
    const std::vector<uint8_t>& data,
    const std::string& password
) {
    const uint8_t* salt = data.data();
    const uint8_t* iv = data.data() + SALT_LEN;
    const uint8_t* ciphertext = data.data() + SALT_LEN + IV_LEN;

    size_t ciphertext_len = data.size() - SALT_LEN - IV_LEN - TAG_LEN;
    const uint8_t* tag = data.data() + data.size() - TAG_LEN;

    auto key = derive_key(password, salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    std::vector<uint8_t> plaintext(ciphertext_len);
    int len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv);

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);
    int plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag);

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        throw std::runtime_error("Decryption failed (tampered or wrong password)");
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return plaintext;
}