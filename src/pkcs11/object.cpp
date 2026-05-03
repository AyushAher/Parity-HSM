#include "pkcs11_wrapper.h"
#include "pkcs11_state.h"
#include "parity_hsm/vault.h"

#include <storage/disk.h>
#include <crypto/aes.h>
#include <crypto/xor.h>
#include <crypto/rsa.h>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sstream>

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

bool attr_matches_bytes(const CK_ATTRIBUTE& attr, const std::vector<unsigned char>& expected)
{
    return attr.ulValueLen == expected.size() &&
           memcmp(attr.pValue, expected.data(), expected.size()) == 0;
}
}

extern "C"
{

    CK_RV C_GetObjectSize(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ULONG_PTR pulSize)
    {
        if (!pulSize)
            return CKR_ARGUMENTS_BAD;

        auto* session = pkcs11_get_session(hSession);
        if (!session)
            return CKR_SESSION_HANDLE_INVALID;

        try {
            auto keys = hsm_vault_load(session->pin);
            if (key_index_for_handle(hObject) >= keys.size())
                return CKR_OBJECT_HANDLE_INVALID;
        } catch (...) {
            return CKR_OBJECT_HANDLE_INVALID;
        }

        *pulSize = 256; // dummy size (RSA key size)
        return CKR_OK;
    }
    // ================= ENUM =================

    CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulCount)
    {
        auto* session = pkcs11_get_session(hSession);
        if (!session)
            return CKR_SESSION_HANDLE_INVALID;

        session->find_active = true;
        session->find_index = 0;
        session->find_match_private = true;
        session->find_match_public = true;
        session->find_results.clear();

        std::string label_filter;
        std::vector<unsigned char> id_filter;
        bool has_label_filter = false;
        bool has_id_filter = false;

        for (CK_ULONG i = 0; i < ulCount; ++i)
        {
            const CK_ATTRIBUTE &attr = pTemplate[i];

            if (!attr.pValue)
                continue;

            if (attr.type == CKA_CLASS && attr.ulValueLen == sizeof(CK_OBJECT_CLASS))
            {
                CK_OBJECT_CLASS cls = *static_cast<CK_OBJECT_CLASS *>(attr.pValue);
                session->find_match_private = (cls == CKO_PRIVATE_KEY);
                session->find_match_public = (cls == CKO_PUBLIC_KEY);
            }
            else if (attr.type == CKA_ID)
            {
                has_id_filter = true;
                const auto* bytes = static_cast<const unsigned char*>(attr.pValue);
                id_filter.assign(bytes, bytes + attr.ulValueLen);
            }
            else if (attr.type == CKA_LABEL)
            {
                has_label_filter = true;
                label_filter.assign(static_cast<const char*>(attr.pValue), attr.ulValueLen);
            }
        }

        try {
            auto keys = hsm_vault_load(session->pin);
            for (size_t i = 0; i < keys.size(); ++i) {
                const auto& key = keys[i];
                bool matches = true;
                if (has_label_filter)
                    matches = matches && key.label == label_filter;
                if (has_id_filter)
                    matches = matches && id_bytes(key.id_hex) == id_filter;

                if (!matches)
                    continue;

                CK_OBJECT_HANDLE private_handle = static_cast<CK_OBJECT_HANDLE>((i + 1) * 2 - 1);
                CK_OBJECT_HANDLE public_handle = static_cast<CK_OBJECT_HANDLE>((i + 1) * 2);
                if (session->find_match_public)
                    session->find_results.push_back(public_handle);
                if (session->find_match_private)
                    session->find_results.push_back(private_handle);
            }
        } catch (...) {
            return CKR_USER_NOT_LOGGED_IN;
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

        auto* session = pkcs11_get_session(hSession);
        if (!session)
            return CKR_SESSION_HANDLE_INVALID;
        if (!session->find_active)
            return CKR_OPERATION_NOT_INITIALIZED;

        *count = 0;
        while (*count < max && static_cast<size_t>(session->find_index) < session->find_results.size()) {
            phObject[*count] = session->find_results[session->find_index++];
            ++(*count);
        }
        return CKR_OK;
    }

    CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
    {
        auto* session = pkcs11_get_session(hSession);
        if (!session)
            return CKR_SESSION_HANDLE_INVALID;
        session->find_active = false;
        session->find_index = 0;
        session->find_results.clear();
        return CKR_OK;
    }

    CK_RV C_GetAttributeValue(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount)
    {
        try
        {
            if (!pTemplate)
                return CKR_ARGUMENTS_BAD;
            auto* session = pkcs11_get_session(hSession);
            if (!session)
                return CKR_SESSION_HANDLE_INVALID;
            auto pin = session->pin;
            auto keys = hsm_vault_load(pin);
            size_t key_index = key_index_for_handle(hObject);
            if (key_index >= keys.size())
                return CKR_OBJECT_HANDLE_INVALID;
            const auto& key_record = keys[key_index];
            const bool is_public = is_public_handle(hObject);
            const bool is_private = is_private_handle(hObject);

            EVP_PKEY *pkey = nullptr;
            bool key_loaded = false;
            bool key_failed = false;
            auto ensure_key = [&]() -> bool
            {
                if (key_loaded)
                    return pkey != nullptr;
                if (key_failed)
                    return false;
                key_loaded = true;

                if (!pkcs11_session_logged_in(hSession))
                {
                    std::cerr << "[HSM] ensure_key: not logged in\n";
                    key_failed = true;
                    return false;
                }

                try
                {
                    const unsigned char *p = key_record.private_der.data();
                    pkey = d2i_AutoPrivateKey(nullptr, &p, key_record.private_der.size());
                    if (!pkey)
                    {
                        unsigned long err;
                        while ((err = ERR_get_error()))
                            std::cerr << "[HSM] OpenSSL: " << ERR_error_string(err, nullptr) << "\n";
                        key_failed = true;
                        return false;
                    }

                    return true;
                }
                catch (const std::exception &ex)
                {
                    std::cerr << "[HSM] exception: " << ex.what() << "\n";
                    key_failed = true;
                    return false;
                }
                catch (...)
                {
                    std::cerr << "[HSM] unknown exception\n";
                    key_failed = true;
                    return false;
                }
            };

            auto set_bytes = [](CK_ATTRIBUTE &attr, const unsigned char *data, CK_ULONG size) -> CK_RV
            {
                if (!attr.pValue)
                {
                    attr.ulValueLen = size;
                    return CKR_OK;
                }

                if (attr.ulValueLen < size)
                {
                    attr.ulValueLen = size;
                    return CKR_BUFFER_TOO_SMALL;
                }

                memcpy(attr.pValue, data, size);
                attr.ulValueLen = size;
                return CKR_OK;
            };

            auto set_scalar = [&](CK_ATTRIBUTE &attr, const void *data, CK_ULONG size) -> CK_RV
            {
                return set_bytes(attr, static_cast<const unsigned char *>(data), size);
            };

            CK_RV rv = CKR_OK;

            for (CK_ULONG i = 0; i < ulCount; i++)
            {
                CK_ATTRIBUTE &attr = pTemplate[i];
                void *out = attr.pValue;
                CK_ULONG &len = attr.ulValueLen;

                switch (attr.type)
                {

                case CKA_CLASS:
                {
                    CK_OBJECT_CLASS val =
                        is_public ? CKO_PUBLIC_KEY : is_private ? CKO_PRIVATE_KEY : 0;
                    rv = set_scalar(attr, &val, sizeof(val));
                    break;
                }

                case CKA_KEY_TYPE:
                {
                    CK_KEY_TYPE val = CKK_RSA;
                    rv = set_scalar(attr, &val, sizeof(val));
                    break;
                }

                case CKA_ID:
                {
                    auto id = id_bytes(key_record.id_hex);
                    rv = set_bytes(attr, id.data(), static_cast<CK_ULONG>(id.size()));
                    break;
                }

                case CKA_LABEL:
                {
                    rv = set_bytes(attr,
                                   reinterpret_cast<const unsigned char *>(key_record.label.data()),
                                   static_cast<CK_ULONG>(key_record.label.size()));
                    break;
                }

                case CKA_MODULUS_BITS:
                {
                    CK_ULONG bits = static_cast<CK_ULONG>(key_record.bits);
                    if (ensure_key())
                    {
                        RSA *rsa = EVP_PKEY_get1_RSA(pkey);
                        if (rsa)
                        {
                            bits = static_cast<CK_ULONG>(RSA_bits(rsa));
                            RSA_free(rsa);
                        }
                    }
                    rv = set_scalar(attr, &bits, sizeof(bits));
                    break;
                }

                case CKA_ENCRYPT:
                case CKA_VERIFY:
                {
                    CK_BBOOL val = is_public ? CK_TRUE : CK_FALSE;
                    rv = set_scalar(attr, &val, sizeof(val));
                    break;
                }

                case CKA_SIGN:
                case CKA_DECRYPT:
                {
                    CK_BBOOL val = is_private ? CK_TRUE : CK_FALSE;
                    rv = set_scalar(attr, &val, sizeof(val));
                    break;
                }
                case CKA_MODULUS:
                case CKA_PUBLIC_EXPONENT:
                {
                    if (!is_public || !ensure_key())
                    {
                        len = CK_UNAVAILABLE_INFORMATION;
                        break;
                    }

                    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
                    if (!rsa)
                    {
                        len = CK_UNAVAILABLE_INFORMATION;
                        break;
                    }

                    const BIGNUM *n = nullptr;
                    const BIGNUM *e = nullptr;
                    RSA_get0_key(rsa, &n, &e, nullptr);

                    const BIGNUM *target = (attr.type == CKA_MODULUS) ? n : e;
                    if (!target)
                    {
                        len = CK_UNAVAILABLE_INFORMATION;
                        RSA_free(rsa);
                        break;
                    }

                    const int bn_len = BN_num_bytes(target);
                    if (!out)
                    {
                        len = static_cast<CK_ULONG>(bn_len);
                        RSA_free(rsa);
                        break;
                    }

                    if (len < static_cast<CK_ULONG>(bn_len))
                    {
                        len = static_cast<CK_ULONG>(bn_len);
                        RSA_free(rsa);
                        return CKR_BUFFER_TOO_SMALL;
                    }

                    BN_bn2bin(target, static_cast<unsigned char *>(out));
                    len = static_cast<CK_ULONG>(bn_len);
                    RSA_free(rsa);
                    break;
                }
                case CKA_VALUE:
                {
                    if (!is_public || !ensure_key())
                    {
                        len = CK_UNAVAILABLE_INFORMATION;
                        break;
                    }

                    const int der_len = i2d_PUBKEY(pkey, nullptr);
                    if (der_len <= 0)
                    {
                        len = CK_UNAVAILABLE_INFORMATION;
                        break;
                    }

                    if (!out)
                    {
                        len = static_cast<CK_ULONG>(der_len);
                        break;
                    }

                    if (len < static_cast<CK_ULONG>(der_len))
                    {
                        len = static_cast<CK_ULONG>(der_len);
                        return CKR_BUFFER_TOO_SMALL;
                    }

                    unsigned char *der_out = static_cast<unsigned char *>(out);
                    i2d_PUBKEY(pkey, &der_out);
                    len = static_cast<CK_ULONG>(der_len);
                    break;
                }

                default:
                    len = CK_UNAVAILABLE_INFORMATION;
                    break;
                }

                if (rv != CKR_OK)
                    break;
            }

            if (pkey)
                EVP_PKEY_free(pkey);
            return rv;
        }
        catch (...)
        {
            return CKR_GENERAL_ERROR;
        }
    }
}
