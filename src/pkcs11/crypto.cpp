#include "pkcs11_wrapper.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <vector>
#include <iostream>
#include <cstring>
#include "pkcs11_state.h"
#include "parity_hsm/vault.h"

namespace {
bool is_private_handle(CK_OBJECT_HANDLE hObject)
{
    return hObject > 0 && (hObject % 2) == 1;
}

bool is_public_handle(CK_OBJECT_HANDLE hObject)
{
    return hObject > 0 && (hObject % 2) == 0;
}

size_t key_index_for_handle(CK_OBJECT_HANDLE hObject)
{
    return (static_cast<size_t>(hObject) - 1) / 2;
}

CK_RV load_private_key_der(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, std::vector<unsigned char>& out)
{
    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->user_logged_in)
        return CKR_USER_NOT_LOGGED_IN;

    try {
        auto keys = hsm_vault_load(session->pin);
        size_t index = key_index_for_handle(hKey);
        if (index >= keys.size())
            return CKR_KEY_HANDLE_INVALID;
        out = keys[index].private_der;
    } catch (...) {
        return CKR_PIN_INCORRECT;
    }

    return CKR_OK;
}

EVP_PKEY* parse_private_key(const std::vector<unsigned char>& der)
{
    const unsigned char* p = der.data();
    return d2i_AutoPrivateKey(nullptr, &p, der.size());
}

CK_RV rsa_output(CK_BYTE_PTR out,
                 CK_ULONG_PTR out_len,
                 const std::vector<unsigned char>& data)
{
    if (!out_len)
        return CKR_ARGUMENTS_BAD;
    if (!out) {
        *out_len = static_cast<CK_ULONG>(data.size());
        return CKR_OK;
    }
    if (*out_len < data.size()) {
        *out_len = static_cast<CK_ULONG>(data.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(out, data.data(), data.size());
    *out_len = static_cast<CK_ULONG>(data.size());
    return CKR_OK;
}
}

extern "C"
CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hKey) {

    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;

    if (!session->user_logged_in)
        return CKR_USER_NOT_LOGGED_IN;

    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;

    if (!is_private_handle(hKey))
        return CKR_KEY_HANDLE_INVALID;

    if (pMechanism->mechanism != CKM_SHA256_RSA_PKCS && pMechanism->mechanism != CKM_RSA_PKCS)
        return CKR_MECHANISM_INVALID;

    CK_RV rv = load_private_key_der(hSession, hKey, session->sign_key_der);
    if (rv != CKR_OK)
        return rv;
    session->sign_key_handle = hKey;
    session->sign_mechanism = pMechanism->mechanism;
    session->sign_active = true;

    return CKR_OK;
}

extern "C"
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_RSA_PKCS)
        return CKR_MECHANISM_INVALID;
    if (!is_public_handle(hKey))
        return CKR_KEY_HANDLE_INVALID;

    CK_RV rv = load_private_key_der(hSession, hKey, session->encrypt_key_der);
    if (rv != CKR_OK)
        return rv;

    session->encrypt_mechanism = pMechanism->mechanism;
    session->encrypt_active = true;
    return CKR_OK;
}

extern "C"
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData,
                CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen)
{
    if (!pulEncryptedDataLen || (!pData && ulDataLen != 0))
        return CKR_ARGUMENTS_BAD;

    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->user_logged_in)
        return CKR_USER_NOT_LOGGED_IN;
    if (!session->encrypt_active)
        return CKR_OPERATION_NOT_INITIALIZED;

    EVP_PKEY* pkey = parse_private_key(session->encrypt_key_der);
    if (!pkey)
        return CKR_GENERAL_ERROR;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return CKR_HOST_MEMORY;
    }

    size_t out_len = 0;
    int ok = EVP_PKEY_encrypt_init(ctx);
    if (ok == 1)
        ok = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    if (ok == 1)
        ok = EVP_PKEY_encrypt(ctx, nullptr, &out_len, pData, ulDataLen);

    std::vector<unsigned char> encrypted(out_len);
    if (ok == 1)
        ok = EVP_PKEY_encrypt(ctx, encrypted.data(), &out_len, pData, ulDataLen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (ok != 1)
        return CKR_GENERAL_ERROR;

    encrypted.resize(out_len);
    return rsa_output(pEncryptedData, pulEncryptedDataLen, encrypted);
}

extern "C"
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR,
                      CK_ULONG,
                      CK_BYTE_PTR,
                      CK_ULONG_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR,
                     CK_ULONG_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_RSA_PKCS)
        return CKR_MECHANISM_INVALID;
    if (!is_private_handle(hKey))
        return CKR_KEY_HANDLE_INVALID;

    CK_RV rv = load_private_key_der(hSession, hKey, session->decrypt_key_der);
    if (rv != CKR_OK)
        return rv;

    session->decrypt_mechanism = pMechanism->mechanism;
    session->decrypt_active = true;
    return CKR_OK;
}

extern "C"
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen)
{
    if (!pulDataLen || (!pEncryptedData && ulEncryptedDataLen != 0))
        return CKR_ARGUMENTS_BAD;

    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->user_logged_in)
        return CKR_USER_NOT_LOGGED_IN;
    if (!session->decrypt_active)
        return CKR_OPERATION_NOT_INITIALIZED;

    EVP_PKEY* pkey = parse_private_key(session->decrypt_key_der);
    if (!pkey)
        return CKR_GENERAL_ERROR;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return CKR_HOST_MEMORY;
    }

    size_t out_len = 0;
    int ok = EVP_PKEY_decrypt_init(ctx);
    if (ok == 1)
        ok = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    if (ok == 1)
        ok = EVP_PKEY_decrypt(ctx, nullptr, &out_len, pEncryptedData, ulEncryptedDataLen);

    std::vector<unsigned char> decrypted(out_len);
    if (ok == 1)
        ok = EVP_PKEY_decrypt(ctx, decrypted.data(), &out_len, pEncryptedData, ulEncryptedDataLen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (ok != 1)
        return CKR_GENERAL_ERROR;

    decrypted.resize(out_len);
    return rsa_output(pData, pulDataLen, decrypted);
}

extern "C"
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR,
                      CK_ULONG,
                      CK_BYTE_PTR,
                      CK_ULONG_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR,
                     CK_ULONG_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_Sign(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR pData,
             CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen) {

    if (!pulSignatureLen)
        return CKR_ARGUMENTS_BAD;

    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->user_logged_in)
        return CKR_USER_NOT_LOGGED_IN;
    if (!session->sign_active)
        return CKR_OPERATION_NOT_INITIALIZED;
    if (!pData && ulDataLen != 0)
        return CKR_ARGUMENTS_BAD;

    const unsigned char* p = session->sign_key_der.data();

    EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &p, session->sign_key_der.size());
    if (!pkey)
        return CKR_GENERAL_ERROR;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return CKR_HOST_MEMORY;
    }

    int ok = 0;
    size_t sigLen = 0;

    if (session->sign_mechanism == CKM_SHA256_RSA_PKCS) {
        ok = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
        if (ok == 1)
            ok = EVP_DigestSignUpdate(ctx, pData, ulDataLen);
        if (ok == 1)
            ok = EVP_DigestSignFinal(ctx, nullptr, &sigLen);
    } else {
        EVP_PKEY_CTX* pctx = nullptr;
        EVP_MD_CTX_free(ctx);
        ctx = nullptr;
        pctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!pctx) {
            EVP_PKEY_free(pkey);
            return CKR_HOST_MEMORY;
        }
        ok = EVP_PKEY_sign_init(pctx);
        if (ok == 1)
            ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
        if (ok == 1)
            ok = EVP_PKEY_sign(pctx, nullptr, &sigLen, pData, ulDataLen);

        if (ok == 1 && !pSignature) {
            *pulSignatureLen = static_cast<CK_ULONG>(sigLen);
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return CKR_OK;
        }

        if (ok == 1 && *pulSignatureLen < sigLen) {
            *pulSignatureLen = static_cast<CK_ULONG>(sigLen);
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            return CKR_BUFFER_TOO_SMALL;
        }

        if (ok == 1)
            ok = EVP_PKEY_sign(pctx, pSignature, &sigLen, pData, ulDataLen);

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);
        *pulSignatureLen = static_cast<CK_ULONG>(sigLen);
        return ok == 1 ? CKR_OK : CKR_GENERAL_ERROR;
    }

    if (!pSignature) {
        *pulSignatureLen = static_cast<CK_ULONG>(sigLen);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return CKR_OK;
    }

    if (*pulSignatureLen < sigLen) {
        *pulSignatureLen = static_cast<CK_ULONG>(sigLen);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return CKR_BUFFER_TOO_SMALL;
    }

    ok = EVP_DigestSignFinal(ctx, pSignature, &sigLen);
    *pulSignatureLen = static_cast<CK_ULONG>(sigLen);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok == 1 ? CKR_OK : CKR_GENERAL_ERROR;
}
