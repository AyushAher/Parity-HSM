#include "pkcs11_state.h"

#include "parity_hsm/secure_memory.h"
#include "parity_hsm/vault.h"
#include "pkcs11_wrapper.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <cstring>
#include <vector>

namespace
{
bool is_private_handle(CK_OBJECT_HANDLE handle)
{
    return handle > 0 && (handle % 2) == 1;
}

bool is_public_handle(CK_OBJECT_HANDLE handle)
{
    return handle > 0 && (handle % 2) == 0;
}

std::string key_id_from_handle(CK_OBJECT_HANDLE handle)
{
    const auto index = (handle + 1) / 2;
    char buffer[3];
    std::snprintf(buffer, sizeof(buffer), "%02lx", static_cast<unsigned long>(index));
    return buffer;
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

CK_RV load_session_key(std::shared_ptr<Pkcs11SessionState> session,
                       CK_OBJECT_HANDLE handle,
                       std::vector<unsigned char>& key_der)
{
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;

    try {
        key_der = hsm_vault_load_private_key(session->auth_key, session->partition, key_id_from_handle(handle));
        return CKR_OK;
    } catch (...) {
        return CKR_KEY_HANDLE_INVALID;
    }
}
}

extern "C"
CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hKey)
{
    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    if (!is_private_handle(hKey))
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    if (pMechanism->mechanism != CKM_SHA256_RSA_PKCS && pMechanism->mechanism != CKM_RSA_PKCS)
        return CKR_MECHANISM_INVALID;

    session->sign_active = true;
    session->sign_key_handle = hKey;
    session->sign_mechanism = pMechanism->mechanism;
    return CKR_OK;
}

extern "C"
CK_RV C_Sign(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR pData,
             CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature,
             CK_ULONG_PTR pulSignatureLen)
{
    if (!pulSignatureLen)
        return CKR_ARGUMENTS_BAD;
    if (!pData && ulDataLen != 0)
        return CKR_ARGUMENTS_BAD;

    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;
    if (!session->sign_active)
        return CKR_OPERATION_NOT_INITIALIZED;

    std::vector<unsigned char> key_der;
    CK_RV rv = load_session_key(session, session->sign_key_handle, key_der);
    if (rv != CKR_OK)
        return rv;

    EVP_PKEY* pkey = parse_private_key(key_der);
    if (!pkey) {
        secure_clear(key_der);
        return CKR_GENERAL_ERROR;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        secure_clear(key_der);
        return CKR_HOST_MEMORY;
    }

    int ok = 0;
    size_t sig_len = 0;
    if (session->sign_mechanism == CKM_SHA256_RSA_PKCS) {
        ok = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
        if (ok == 1)
            ok = EVP_DigestSignUpdate(ctx, pData, ulDataLen);
        if (ok == 1)
            ok = EVP_DigestSignFinal(ctx, nullptr, &sig_len);
        if (ok != 1) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            secure_clear(key_der);
            return CKR_GENERAL_ERROR;
        }
        if (!pSignature) {
            *pulSignatureLen = static_cast<CK_ULONG>(sig_len);
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            secure_clear(key_der);
            return CKR_OK;
        }
        if (*pulSignatureLen < sig_len) {
            *pulSignatureLen = static_cast<CK_ULONG>(sig_len);
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            secure_clear(key_der);
            return CKR_BUFFER_TOO_SMALL;
        }
        ok = EVP_DigestSignFinal(ctx, pSignature, &sig_len);
    } else {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
        EVP_MD_CTX_free(ctx);
        ctx = nullptr;
        if (!pctx) {
            EVP_PKEY_free(pkey);
            secure_clear(key_der);
            return CKR_HOST_MEMORY;
        }
        ok = EVP_PKEY_sign_init(pctx);
        if (ok == 1)
            ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
        if (ok == 1)
            ok = EVP_PKEY_sign(pctx, nullptr, &sig_len, pData, ulDataLen);
        if (ok != 1) {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            secure_clear(key_der);
            return CKR_GENERAL_ERROR;
        }
        if (!pSignature) {
            *pulSignatureLen = static_cast<CK_ULONG>(sig_len);
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            secure_clear(key_der);
            return CKR_OK;
        }
        if (*pulSignatureLen < sig_len) {
            *pulSignatureLen = static_cast<CK_ULONG>(sig_len);
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            secure_clear(key_der);
            return CKR_BUFFER_TOO_SMALL;
        }
        ok = EVP_PKEY_sign(pctx, pSignature, &sig_len, pData, ulDataLen);
        EVP_PKEY_CTX_free(pctx);
    }

    *pulSignatureLen = static_cast<CK_ULONG>(sig_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    secure_clear(key_der);
    return ok == 1 ? CKR_OK : CKR_GENERAL_ERROR;
}

extern "C"
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    if (!is_public_handle(hKey))
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    if (pMechanism->mechanism != CKM_RSA_PKCS)
        return CKR_MECHANISM_INVALID;

    session->encrypt_active = true;
    session->encrypt_key_handle = hKey;
    session->encrypt_mechanism = pMechanism->mechanism;
    return CKR_OK;
}

extern "C"
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData,
                CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen)
{
    if (!pulEncryptedDataLen)
        return CKR_ARGUMENTS_BAD;
    if (!pData && ulDataLen != 0)
        return CKR_ARGUMENTS_BAD;

    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;
    if (!session->encrypt_active)
        return CKR_OPERATION_NOT_INITIALIZED;

    std::vector<unsigned char> key_der;
    CK_RV rv = load_session_key(session, session->encrypt_key_handle, key_der);
    if (rv != CKR_OK)
        return rv;

    EVP_PKEY* pkey = parse_private_key(key_der);
    if (!pkey) {
        secure_clear(key_der);
        return CKR_GENERAL_ERROR;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        secure_clear(key_der);
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
    secure_clear(key_der);

    if (ok != 1)
        return CKR_GENERAL_ERROR;

    encrypted.resize(out_len);
    rv = rsa_output(pEncryptedData, pulEncryptedDataLen, encrypted);
    secure_clear(encrypted);
    return rv;
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
    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    if (!is_private_handle(hKey))
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    if (pMechanism->mechanism != CKM_RSA_PKCS)
        return CKR_MECHANISM_INVALID;

    session->decrypt_active = true;
    session->decrypt_key_handle = hKey;
    session->decrypt_mechanism = pMechanism->mechanism;
    return CKR_OK;
}

extern "C"
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen)
{
    if (!pulDataLen)
        return CKR_ARGUMENTS_BAD;
    if (!pEncryptedData && ulEncryptedDataLen != 0)
        return CKR_ARGUMENTS_BAD;

    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;
    if (!session->decrypt_active)
        return CKR_OPERATION_NOT_INITIALIZED;

    std::vector<unsigned char> key_der;
    CK_RV rv = load_session_key(session, session->decrypt_key_handle, key_der);
    if (rv != CKR_OK)
        return rv;

    EVP_PKEY* pkey = parse_private_key(key_der);
    if (!pkey) {
        secure_clear(key_der);
        return CKR_GENERAL_ERROR;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        secure_clear(key_der);
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
    secure_clear(key_der);

    if (ok != 1)
        return CKR_GENERAL_ERROR;

    decrypted.resize(out_len);
    rv = rsa_output(pData, pulDataLen, decrypted);
    secure_clear(decrypted);
    return rv;
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
