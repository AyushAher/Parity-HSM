#include "pkcs11_state.h"

#include "parity_hsm/secure_memory.h"
#include "parity_hsm/vault.h"
#include "pkcs11_wrapper.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstring>
#include <sstream>

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

std::vector<unsigned char> id_bytes(const std::string& id_hex)
{
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < id_hex.size(); i += 2) {
        unsigned int value = 0;
        std::istringstream in(id_hex.substr(i, 2));
        in >> std::hex >> value;
        out.push_back(static_cast<unsigned char>(value));
    }
    return out;
}

EVP_PKEY* parse_private_key(const std::vector<unsigned char>& der)
{
    const unsigned char* p = der.data();
    return d2i_AutoPrivateKey(nullptr, &p, der.size());
}
}

extern "C"
{
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    if (!pulSize)
        return CKR_ARGUMENTS_BAD;

    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;

    try {
        auto keys = hsm_vault_view(session->auth_key, session->partition).keys;
        const auto key_index = (hObject + 1) / 2;
        if (hObject == 0 || key_index == 0 || key_index > keys.size())
            return CKR_OBJECT_HANDLE_INVALID;
    } catch (...) {
        return CKR_GENERAL_ERROR;
    }

    *pulSize = 256;
    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;

    session->find_active = true;
    session->find_index = 0;
    session->find_results.clear();
    session->find_match_private = true;
    session->find_match_public = true;

    std::string label_filter;
    std::vector<unsigned char> id_filter;
    bool has_label = false;
    bool has_id = false;

    for (CK_ULONG i = 0; i < ulCount; ++i) {
        const auto& attr = pTemplate[i];
        if (!attr.pValue)
            continue;
        if (attr.type == CKA_CLASS && attr.ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            const auto cls = *static_cast<CK_OBJECT_CLASS*>(attr.pValue);
            session->find_match_private = (cls == CKO_PRIVATE_KEY);
            session->find_match_public = (cls == CKO_PUBLIC_KEY);
        } else if (attr.type == CKA_ID) {
            has_id = true;
            const auto* bytes = static_cast<const unsigned char*>(attr.pValue);
            id_filter.assign(bytes, bytes + attr.ulValueLen);
        } else if (attr.type == CKA_LABEL) {
            has_label = true;
            label_filter.assign(static_cast<const char*>(attr.pValue), attr.ulValueLen);
        }
    }

    try {
        auto keys = hsm_vault_view(session->auth_key, session->partition).keys;
        for (size_t i = 0; i < keys.size(); ++i) {
            const auto& key = keys[i];
            if (has_label && key.label != label_filter)
                continue;
            if (has_id && id_bytes(key.id_hex) != id_filter)
                continue;

            const CK_OBJECT_HANDLE private_handle = static_cast<CK_OBJECT_HANDLE>((i + 1) * 2 - 1);
            const CK_OBJECT_HANDLE public_handle = static_cast<CK_OBJECT_HANDLE>((i + 1) * 2);
            if (session->find_match_public)
                session->find_results.push_back(public_handle);
            if (session->find_match_private)
                session->find_results.push_back(private_handle);
        }
    } catch (...) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
                    CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG max,
                    CK_ULONG_PTR count)
{
    if (!phObject || !count)
        return CKR_ARGUMENTS_BAD;

    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->find_active)
        return CKR_OPERATION_NOT_INITIALIZED;

    *count = 0;
    while (*count < max && session->find_index < session->find_results.size()) {
        phObject[*count] = session->find_results[session->find_index++];
        ++(*count);
    }
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    session->find_active = false;
    session->find_index = 0;
    session->find_results.clear();
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount)
{
    if (!pTemplate)
        return CKR_ARGUMENTS_BAD;

    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated || session->login_type != CKU_USER)
        return CKR_USER_NOT_LOGGED_IN;

    const bool is_public = is_public_handle(hObject);
    const bool is_private = is_private_handle(hObject);
    if (!is_public && !is_private)
        return CKR_OBJECT_HANDLE_INVALID;

    auto keys = hsm_vault_view(session->auth_key, session->partition).keys;
    const auto key_index = (hObject + 1) / 2;
    if (key_index == 0 || key_index > keys.size())
        return CKR_OBJECT_HANDLE_INVALID;
    const auto& key_record = keys[key_index - 1];

    std::vector<unsigned char> private_der;
    EVP_PKEY* pkey = nullptr;
    auto ensure_key = [&]() -> bool {
        if (pkey)
            return true;
        try {
            private_der = hsm_vault_load_private_key(session->auth_key, session->partition, key_record.id_hex);
            pkey = parse_private_key(private_der);
            return pkey != nullptr;
        } catch (...) {
            return false;
        }
    };

    auto set_bytes = [](CK_ATTRIBUTE& attr, const unsigned char* data, CK_ULONG size) -> CK_RV {
        if (!attr.pValue) {
            attr.ulValueLen = size;
            return CKR_OK;
        }
        if (attr.ulValueLen < size) {
            attr.ulValueLen = size;
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(attr.pValue, data, size);
        attr.ulValueLen = size;
        return CKR_OK;
    };

    CK_RV rv = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        auto& attr = pTemplate[i];
        switch (attr.type) {
        case CKA_CLASS: {
            CK_OBJECT_CLASS cls = is_public ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY;
            rv = set_bytes(attr, reinterpret_cast<unsigned char*>(&cls), sizeof(cls));
            break;
        }
        case CKA_KEY_TYPE: {
            CK_KEY_TYPE key_type = CKK_RSA;
            rv = set_bytes(attr, reinterpret_cast<unsigned char*>(&key_type), sizeof(key_type));
            break;
        }
        case CKA_ID: {
            const auto id = id_bytes(key_record.id_hex);
            rv = set_bytes(attr, id.data(), static_cast<CK_ULONG>(id.size()));
            break;
        }
        case CKA_LABEL:
            rv = set_bytes(attr,
                           reinterpret_cast<const unsigned char*>(key_record.label.data()),
                           static_cast<CK_ULONG>(key_record.label.size()));
            break;
        case CKA_MODULUS_BITS: {
            CK_ULONG bits = static_cast<CK_ULONG>(key_record.bits);
            rv = set_bytes(attr, reinterpret_cast<unsigned char*>(&bits), sizeof(bits));
            break;
        }
        case CKA_ENCRYPT:
        case CKA_VERIFY: {
            CK_BBOOL value = is_public ? CK_TRUE : CK_FALSE;
            rv = set_bytes(attr, reinterpret_cast<unsigned char*>(&value), sizeof(value));
            break;
        }
        case CKA_SIGN:
        case CKA_DECRYPT: {
            CK_BBOOL value = is_private ? CK_TRUE : CK_FALSE;
            rv = set_bytes(attr, reinterpret_cast<unsigned char*>(&value), sizeof(value));
            break;
        }
        case CKA_MODULUS:
        case CKA_PUBLIC_EXPONENT: {
            if (!is_public || !ensure_key()) {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                break;
            }
            RSA* rsa = EVP_PKEY_get1_RSA(pkey);
            if (!rsa) {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                break;
            }
            const BIGNUM *n = nullptr, *e = nullptr;
            RSA_get0_key(rsa, &n, &e, nullptr);
            const BIGNUM* target = (attr.type == CKA_MODULUS) ? n : e;
            if (!target) {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                RSA_free(rsa);
                break;
            }
            const auto bn_len = static_cast<CK_ULONG>(BN_num_bytes(target));
            if (!attr.pValue) {
                attr.ulValueLen = bn_len;
                RSA_free(rsa);
                break;
            }
            if (attr.ulValueLen < bn_len) {
                attr.ulValueLen = bn_len;
                RSA_free(rsa);
                rv = CKR_BUFFER_TOO_SMALL;
                break;
            }
            BN_bn2bin(target, static_cast<unsigned char*>(attr.pValue));
            attr.ulValueLen = bn_len;
            RSA_free(rsa);
            break;
        }
        case CKA_VALUE: {
            if (!is_public || !ensure_key()) {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                break;
            }
            const int der_len = i2d_PUBKEY(pkey, nullptr);
            if (der_len <= 0) {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                break;
            }
            if (!attr.pValue) {
                attr.ulValueLen = static_cast<CK_ULONG>(der_len);
                break;
            }
            if (attr.ulValueLen < static_cast<CK_ULONG>(der_len)) {
                attr.ulValueLen = static_cast<CK_ULONG>(der_len);
                rv = CKR_BUFFER_TOO_SMALL;
                break;
            }
            unsigned char* out = static_cast<unsigned char*>(attr.pValue);
            i2d_PUBKEY(pkey, &out);
            attr.ulValueLen = static_cast<CK_ULONG>(der_len);
            break;
        }
        default:
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            break;
        }

        if (rv != CKR_OK)
            break;
    }

    if (pkey)
        EVP_PKEY_free(pkey);
    secure_clear(private_der);
    return rv;
}
}
