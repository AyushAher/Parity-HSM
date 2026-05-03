#include "pkcs11_wrapper.h"
#include <vector>
#include <cstring>
#include <iostream>

#include "pkcs11_state.h"
#include <parity_hsm/vault.h>

#include <openssl/rand.h>

namespace {
bool g_initialized = false;
}

struct Slot {
    CK_SLOT_ID id;
    std::string path;   // /dev/rdisk5s2
};


extern "C"

CK_RV C_Initialize(void* pInitArgs) {
    if (g_initialized)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;

    g_initialized = true;
    std::cout << "[PKCS11] Initialize\n";
    return CKR_OK;
}

CK_RV C_Finalize(void* pReserved) {
    if (pReserved)
        return CKR_ARGUMENTS_BAD;
    if (!g_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    pkcs11_reset_sessions();
    g_initialized = false;
    return CKR_OK;
}

extern "C"
CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo, ' ', sizeof(*pInfo));
    pInfo->cryptokiVersion = {2, 40};
    pInfo->libraryVersion = {0, 1};
    memcpy(pInfo->manufacturerID, "Parity", 6);
    memcpy(pInfo->libraryDescription, "Parity HSM PKCS11", 17);
    pInfo->flags = 0;

    return CKR_OK;
}
extern "C"
CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;

    // We expose 1 slot for now
    CK_ULONG slot_count = 1;

    // First call: just return count
    if (pSlotList == nullptr) {
        *pulCount = slot_count;
        return CKR_OK;
    }

    // If buffer too small
    if (*pulCount < slot_count) {
        *pulCount = slot_count;
        return CKR_BUFFER_TOO_SMALL;
    }

    // Fill slots
    pSlotList[0] = 1;

    *pulCount = slot_count;

    return CKR_OK;
}

extern "C"
CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{
    if (!pulCount)
        return CKR_ARGUMENTS_BAD;

    if (slotID != 1)
        return CKR_SLOT_ID_INVALID;

    const CK_MECHANISM_TYPE mechanisms[] = {
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
    };
    const CK_ULONG mechanism_count = sizeof(mechanisms) / sizeof(mechanisms[0]);

    if (!pMechanismList) {
        *pulCount = mechanism_count;
        return CKR_OK;
    }

    if (*pulCount < mechanism_count) {
        *pulCount = mechanism_count;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pMechanismList, mechanisms, sizeof(mechanisms));
    *pulCount = mechanism_count;
    return CKR_OK;
}

extern "C"
CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    if (slotID != 1)
        return CKR_SLOT_ID_INVALID;

    if (type != CKM_RSA_PKCS_KEY_PAIR_GEN && type != CKM_RSA_PKCS && type != CKM_SHA256_RSA_PKCS)
        return CKR_MECHANISM_INVALID;

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->ulMinKeySize = 2048;
    pInfo->ulMaxKeySize = 2048;
    pInfo->flags = (type == CKM_RSA_PKCS_KEY_PAIR_GEN) ? CKF_GENERATE_KEY_PAIR : (CKF_SIGN | CKF_VERIFY | CKF_ENCRYPT | CKF_DECRYPT);

    return CKR_OK;
}

extern "C"
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) 
{
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;
    if (slotID != 1)
        return CKR_SLOT_ID_INVALID;

    memset(pInfo, 0, sizeof(CK_SLOT_INFO));

    std::string desc = "Parity HSM Slot";
    std::string manuf = "Parity";

    memcpy(pInfo->slotDescription, desc.c_str(), desc.size());
    memcpy(pInfo->manufacturerID, manuf.c_str(), manuf.size());

    pInfo->flags = CKF_TOKEN_PRESENT;

    return CKR_OK;
}

extern "C"
CK_RV C_GetTokenInfo(
    CK_SLOT_ID slotID,
    CK_TOKEN_INFO_PTR pInfo
) {
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;
    if (slotID != 1)
        return CKR_SLOT_ID_INVALID;

    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));

    std::string label = "ParityHSM";
    std::string manuf = "Parity";
    std::string model = "v1";
    std::string serial = "0001";

    memcpy(pInfo->label, label.c_str(), label.size());
    memcpy(pInfo->manufacturerID, manuf.c_str(), manuf.size());
    memcpy(pInfo->model, model.c_str(), model.size());
    memcpy(pInfo->serialNumber, serial.c_str(), serial.size());

    pInfo->flags =
    CKF_TOKEN_INITIALIZED |
    CKF_LOGIN_REQUIRED |
    CKF_USER_PIN_INITIALIZED;

    return CKR_OK;
}

extern "C"
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR)
{
    if (!pSlot)
        return CKR_ARGUMENTS_BAD;

    if ((flags & CKF_DONT_BLOCK) == 0)
        return CKR_FUNCTION_NOT_SUPPORTED;

    return CKR_NO_EVENT;
}

extern "C"
CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    if (slotID != 1)
        return CKR_SLOT_ID_INVALID;
    if (!pPin || ulPinLen == 0)
        return CKR_PIN_INVALID;

    std::string pin(reinterpret_cast<char*>(pPin), ulPinLen);
    std::string label = "ParityHSM";
    if (pLabel)
        label.assign(reinterpret_cast<char*>(pLabel), 32);

    try {
        hsm_vault_initialize(pin, label);
        pkcs11_reset_sessions();
    } catch (...) {
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

extern "C"
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR, CK_ULONG)
{
    return pkcs11_get_session(hSession) ? CKR_ACTION_PROHIBITED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG)
{
    return pkcs11_get_session(hSession) ? CKR_ACTION_PROHIBITED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                     CK_ATTRIBUTE_PTR,
                     CK_ULONG,
                     CK_OBJECT_HANDLE_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_ACTION_PROHIBITED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
                   CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR,
                   CK_ULONG,
                   CK_OBJECT_HANDLE_PTR)
{
    if (!pkcs11_get_session(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    if (hObject == 0)
        return CKR_OBJECT_HANDLE_INVALID;
    return CKR_ACTION_PROHIBITED;
}

extern "C"
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    if (!pkcs11_get_session(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    if (hObject == 0)
        return CKR_OBJECT_HANDLE_INVALID;
    return CKR_ACTION_PROHIBITED;
}

extern "C"
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR,
                          CK_ULONG)
{
    if (!pkcs11_get_session(hSession))
        return CKR_SESSION_HANDLE_INVALID;
    if (hObject == 0)
        return CKR_OBJECT_HANDLE_INVALID;
    return CKR_ATTRIBUTE_READ_ONLY;
}

extern "C"
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR,
                    CK_ATTRIBUTE_PTR,
                    CK_ULONG,
                    CK_OBJECT_HANDLE_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->user_logged_in)
        return CKR_USER_NOT_LOGGED_IN;
    if (!pMechanism)
        return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN)
        return CKR_MECHANISM_INVALID;
    if (!phPublicKey || !phPrivateKey)
        return CKR_ARGUMENTS_BAD;

    std::string id_hex;
    std::string label;
    int bits = 2048;

    auto read_template = [&](CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
        for (CK_ULONG i = 0; attrs && i < count; ++i) {
            const auto& attr = attrs[i];
            if (attr.type == CKA_ID && attr.pValue && attr.ulValueLen > 0) {
                static const char hex[] = "0123456789abcdef";
                const auto* bytes = static_cast<const unsigned char*>(attr.pValue);
                id_hex.clear();
                for (CK_ULONG j = 0; j < attr.ulValueLen; ++j) {
                    id_hex.push_back(hex[(bytes[j] >> 4) & 0x0f]);
                    id_hex.push_back(hex[bytes[j] & 0x0f]);
                }
            } else if (attr.type == CKA_LABEL && attr.pValue) {
                label.assign(static_cast<const char*>(attr.pValue), attr.ulValueLen);
            } else if (attr.type == CKA_MODULUS_BITS && attr.pValue && attr.ulValueLen == sizeof(CK_ULONG)) {
                bits = static_cast<int>(*static_cast<CK_ULONG*>(attr.pValue));
            }
        }
    };

    read_template(pPublicKeyTemplate, ulPublicKeyAttributeCount);
    read_template(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);

    try {
        auto record = hsm_vault_generate_rsa_key(session->pin, id_hex, label, bits);
        auto keys = hsm_vault_load(session->pin);
        CK_ULONG index = 1;
        for (CK_ULONG i = 0; i < keys.size(); ++i) {
            if (keys[i].id_hex == record.id_hex) {
                index = i + 1;
                break;
            }
        }
        *phPrivateKey = (index * 2) - 1;
        *phPublicKey = index * 2;
    } catch (...) {
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

extern "C"
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR,
                  CK_OBJECT_HANDLE,
                  CK_ATTRIBUTE_PTR,
                  CK_ULONG,
                  CK_OBJECT_HANDLE_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
                CK_MECHANISM_PTR,
                CK_OBJECT_HANDLE,
                CK_OBJECT_HANDLE,
                CK_BYTE_PTR,
                CK_ULONG_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_SESSION_HANDLE_INVALID;
}

extern "C"
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR,
                  CK_OBJECT_HANDLE,
                  CK_BYTE_PTR,
                  CK_ULONG,
                  CK_ATTRIBUTE_PTR,
                  CK_ULONG,
                  CK_OBJECT_HANDLE_PTR)
{
    return pkcs11_get_session(hSession) ? CKR_FUNCTION_NOT_SUPPORTED : CKR_SESSION_HANDLE_INVALID;
}

CK_FUNCTION_LIST function_list = {
    .version = {2, 40},

    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,

    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,

    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = nullptr,
    .C_SetOperationState = nullptr,

    .C_Login = C_Login,
    .C_Logout = C_Logout,

    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,

    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,

    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,

    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,

    .C_DigestInit = nullptr,
    .C_Digest = nullptr,
    .C_DigestUpdate = nullptr,
    .C_DigestFinal = nullptr,

    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = nullptr,
    .C_SignFinal = nullptr,

    .C_VerifyInit = nullptr,
    .C_Verify = nullptr,
    .C_VerifyUpdate = nullptr,
    .C_VerifyFinal = nullptr,

    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,

    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,

    .C_SeedRandom = nullptr,
    .C_GenerateRandom = nullptr,

    .C_GetFunctionStatus = nullptr,
    .C_CancelFunction = nullptr,

    .C_WaitForSlotEvent = C_WaitForSlotEvent
};

extern "C"
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (!ppFunctionList)
        return CKR_ARGUMENTS_BAD;

    *ppFunctionList = &function_list;
    return CKR_OK;
}
