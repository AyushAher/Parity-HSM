#include "pkcs11_wrapper.h"
#include <openssl/evp.h>
#include <vector>
#include <iostream>

// your existing functions
extern std::vector<uint8_t> load_file(const std::string&);
extern std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>&, const std::string&);
extern std::vector<uint8_t> xor_data(const std::vector<uint8_t>&, const std::vector<uint8_t>&);

static std::vector<uint8_t> current_key;

extern "C"
CK_RV C_SignInit(CK_SESSION_HANDLE,
                 CK_MECHANISM_PTR,
                 CK_OBJECT_HANDLE) {

    std::string password = "your-password";

    auto B_enc = load_file("B.enc");
    auto C_enc = load_file("C.enc");

    auto B = aes_decrypt(B_enc, password);
    auto C = aes_decrypt(C_enc, password);

    current_key = xor_data(B, C);

    return CKR_OK;
}

extern "C"
CK_RV C_Sign(CK_SESSION_HANDLE,
             CK_BYTE_PTR pData,
             CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen) {

    const unsigned char* p = current_key.data();

    EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &p, current_key.size());

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, pData, ulDataLen);

    unsigned int sigLen = 0;

    if (!pSignature) {
        *pulSignatureLen = 256;
        return CKR_OK;
    }

    EVP_SignFinal(ctx, pSignature, &sigLen, pkey);
    *pulSignatureLen = sigLen;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return CKR_OK;
}