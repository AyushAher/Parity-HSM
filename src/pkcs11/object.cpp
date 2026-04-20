#include "pkcs11_wrapper.h"
#include "pkcs11_state.h"

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

// Handles
static CK_OBJECT_HANDLE priv_handle = 1;
static CK_OBJECT_HANDLE pub_handle  = 2;

static int obj_index = 0;

extern "C" {

    CK_RV C_GetObjectSize(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize
) {
    if (!pulSize)
        return CKR_ARGUMENTS_BAD;

    if (hObject != 1 && hObject != 2)
        return CKR_OBJECT_HANDLE_INVALID;

    *pulSize = 256; // dummy size (RSA key size)
    return CKR_OK;
}
// ================= SESSION =================

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->state = CKS_RW_USER_FUNCTIONS;
    pInfo->flags = CKF_SERIAL_SESSION;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE,
              CK_USER_TYPE,
              CK_UTF8CHAR_PTR pPin,
              CK_ULONG ulPinLen) {

    g_pin = std::string((char*)pPin, ulPinLen);
    logged_in = true;

    std::cout << "[PKCS11] Login\n";
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE) {
    return CKR_OK;
}

// ================= ENUM =================

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE,
                        CK_ATTRIBUTE_PTR,
                        CK_ULONG) {
    obj_index = 0;
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE,
                    CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG max,
                    CK_ULONG_PTR count) {

    if (!phObject || !count)
        return CKR_ARGUMENTS_BAD;

    if (obj_index == 0 && max > 0) {
        phObject[0] = priv_handle;
        *count = 1;
        obj_index++;
        return CKR_OK;
    }

    if (obj_index == 1 && max > 0) {
        phObject[0] = pub_handle;
        *count = 1;
        obj_index++;
        return CKR_OK;
    }

    *count = 0;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE) {
    obj_index = 0;
    return CKR_OK;
}

CK_RV C_GetAttributeValue(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
) {
    if (!pTemplate) return CKR_ARGUMENTS_BAD;

    // Helper: load and reconstruct the private key once per call if needed
    // (cache it for the loop so we don't decrypt on every attribute)
    EVP_PKEY* pkey = nullptr;
    bool key_loaded = false;
    bool key_failed = false;
// Temporary: replace your ensure_key lambda with this verbose version
auto ensure_key = [&]() -> bool {
    if (key_loaded) return pkey != nullptr;
    if (key_failed) return false;
    key_loaded = true;

    if (!logged_in) {
        std::cerr << "[HSM] ensure_key: not logged in\n";
        key_failed = true;
        return false;
    }

    std::cerr << "[HSM] g_pin length = " << g_pin.size() << "\n";
    std::cerr << "[HSM] g_pin bytes:";
    for (unsigned char c : g_pin) std::cerr << " " << (int)c;
    std::cerr << "\n";

    try {
        std::cerr << "[HSM] loading B.enc...\n";
        auto B_enc = load_file("B.enc");
        std::cerr << "[HSM] B.enc size = " << B_enc.size() << "\n";

        std::cerr << "[HSM] loading C.enc...\n";
        auto C_enc = load_file("C.enc");
        std::cerr << "[HSM] C.enc size = " << C_enc.size() << "\n";

        std::cerr << "[HSM] decrypting B...\n";
        auto B = aes_decrypt(B_enc, g_pin);
        std::cerr << "[HSM] B decrypted, size = " << B.size() << "\n";

        std::cerr << "[HSM] decrypting C...\n";
        auto C = aes_decrypt(C_enc, g_pin);
        std::cerr << "[HSM] C decrypted, size = " << C.size() << "\n";

        auto A = xor_data(B, C);
        std::cerr << "[HSM] A xor'd, size = " << A.size() << "\n";
        std::cerr << "[HSM] A first 8 bytes:";
        for (int i = 0; i < std::min((int)A.size(), 8); i++)
            std::cerr << " " << std::hex << (int)A[i];
        std::cerr << std::dec << "\n";

        const unsigned char* p = A.data();
        pkey = d2i_AutoPrivateKey(nullptr, &p, A.size());
        if (!pkey) {
            std::cerr << "[HSM] d2i_AutoPrivateKey FAILED (bad DER or wrong key type)\n";
            unsigned long err;
            while ((err = ERR_get_error()))
                std::cerr << "[HSM] OpenSSL: " << ERR_error_string(err, nullptr) << "\n";
            key_failed = true;
            return false;
        }

        std::cerr << "[HSM] pkey loaded, type = " << EVP_PKEY_base_id(pkey) << "\n";
        return true;

    } catch (const std::exception& ex) {
        std::cerr << "[HSM] exception: " << ex.what() << "\n";
        key_failed = true;
        return false;
    } catch (...) {
        std::cerr << "[HSM] unknown exception\n";
        key_failed = true;
        return false;
    }
};

    CK_RV rv = CKR_OK;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE& attr = pTemplate[i];
        void*     out = attr.pValue;
        CK_ULONG& len = attr.ulValueLen;

        std::cerr << "ATTR REQ: " << attr.type << std::endl;

        switch (attr.type) {

        case CKA_CLASS: {
            CK_OBJECT_CLASS val =
                (hObject == pub_handle)  ? CKO_PUBLIC_KEY  :
                (hObject == priv_handle) ? CKO_PRIVATE_KEY : 0;
            if (!out) len = sizeof(val);
            else { memcpy(out, &val, sizeof(val)); len = sizeof(val); }
            break;
        }

        case CKA_KEY_TYPE: {
            CK_KEY_TYPE val = CKK_RSA;
            if (!out) len = sizeof(val);
            else { memcpy(out, &val, sizeof(val)); len = sizeof(val); }
            break;
        }

        case CKA_ID: {
            unsigned char id[] = {0x01};
            if (!out) len = sizeof(id);
            else { memcpy(out, id, sizeof(id)); len = sizeof(id); }
            break;
        }

        case CKA_LABEL: {
            const char label[] = "ParityKey";
            if (!out) len = strlen(label);
            else { memcpy(out, label, strlen(label)); len = strlen(label); }
            break;
        }

        case CKA_MODULUS_BITS: {
            CK_ULONG bits = 2048;
            if (!out) len = sizeof(bits);
            else { memcpy(out, &bits, sizeof(bits)); len = sizeof(bits); }
            break;
        }

        case CKA_ENCRYPT:
        case CKA_VERIFY: {
            CK_BBOOL val = (hObject == pub_handle) ? CK_TRUE : CK_FALSE;
            if (!out) len = sizeof(val);
            else { memcpy(out, &val, sizeof(val)); len = sizeof(val); }
            break;
        }

        case CKA_SIGN:
        case CKA_DECRYPT: {
            CK_BBOOL val = (hObject == priv_handle) ? CK_TRUE : CK_FALSE;
            if (!out) len = sizeof(val);
            else { memcpy(out, &val, sizeof(val)); len = sizeof(val); }
            break;
        }
case CKA_MODULUS:
case CKA_PUBLIC_EXPONENT: {
    if (hObject != pub_handle) { len = CK_UNAVAILABLE_INFORMATION; break; }

    try {
        FILE* f = fopen("/Users/ayushaher/Projects/Parity HSM/pub.pem", "r");
        if (!f) {
            std::cerr << "[HSM] cannot open pub.pem, CWD=";
            char cwd[512]; getcwd(cwd, sizeof(cwd));
            std::cerr << cwd << "\n";
            len = CK_UNAVAILABLE_INFORMATION;
            break;
        }

        EVP_PKEY* pkey = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
        fclose(f);

        if (!pkey) {
            std::cerr << "[HSM] PEM_read_PUBKEY failed\n";
            len = CK_UNAVAILABLE_INFORMATION;
            break;
        }

        BIGNUM* n = nullptr;
        BIGNUM* e = nullptr;
        EVP_PKEY_get_bn_param(pkey, "n", &n);
        EVP_PKEY_get_bn_param(pkey, "e", &e);

        const BIGNUM* target = (attr.type == CKA_MODULUS) ? n : e;
        if (!target) {
            std::cerr << "[HSM] bn param null — is pub.pem actually RSA?\n";
            BN_free(n); BN_free(e); EVP_PKEY_free(pkey);
            len = CK_UNAVAILABLE_INFORMATION;
            break;
        }

        int bn_len = BN_num_bytes(target);
        if (!out) {
            len = (CK_ULONG)bn_len;
        } else {
            BN_bn2bin(target, (unsigned char*)out);
            len = (CK_ULONG)bn_len;
        }

        BN_free(n); BN_free(e); EVP_PKEY_free(pkey);

    } catch (...) {
        std::cerr << "[HSM] unknown exception in CKA_MODULUS\n";
        len = CK_UNAVAILABLE_INFORMATION;
    }
    break;
}
        case CKA_VALUE: {
            // Return full DER-encoded public key (SubjectPublicKeyInfo)
            if (hObject != pub_handle) {
                len = CK_UNAVAILABLE_INFORMATION;
                break;
            }
            if (!ensure_key()) {
                len = CK_UNAVAILABLE_INFORMATION;
                break;
            }

            int der_len = i2d_PUBKEY(pkey, nullptr);
            if (der_len <= 0) { len = CK_UNAVAILABLE_INFORMATION; break; }

            if (!out) {
                len = (CK_ULONG)der_len;
            } else if (len < (CK_ULONG)der_len) {
                len = (CK_ULONG)der_len;
                rv = CKR_BUFFER_TOO_SMALL;
            } else {
                unsigned char* p = (unsigned char*)out;
                i2d_PUBKEY(pkey, &p);
                len = (CK_ULONG)der_len;
            }
            break;
        }

        default:
            len = CK_UNAVAILABLE_INFORMATION;
            break;
        }

        std::cerr << " attr[" << attr.type << "] → len: " << len << std::endl;
    }

    if (pkey) EVP_PKEY_free(pkey);
    return rv;
}

}