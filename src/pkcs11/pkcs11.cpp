#include "pkcs11_wrapper.h"
#include <vector>
#include <cstring>
#include <iostream>

#include "pkcs11_state.h"

std::string g_pin = "";
bool logged_in = false;

struct Slot {
    CK_SLOT_ID id;
    std::string path;   // /dev/rdisk5s2
};


extern "C"

CK_RV C_Initialize(void* pInitArgs) {
    std::cout << "[PKCS11] Initialize\n";
    return CKR_OK;
}

CK_RV C_Finalize(void* pReserved) {
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

// --- SESSION ---
CK_RV C_OpenSession(CK_SLOT_ID slotID,
                    CK_FLAGS flags,
                    void* pApplication,
                    void* Notify,
                    CK_SESSION_HANDLE_PTR phSession) {

    *phSession = 1;
    return CKR_OK;
}


extern "C"
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) 
{
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

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

CK_FUNCTION_LIST function_list = {
    .version = {2, 40},

    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = nullptr,
    .C_GetFunctionList = C_GetFunctionList,

    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = nullptr,
    .C_GetMechanismInfo = nullptr,
    .C_InitToken = nullptr,
    .C_InitPIN = nullptr,
    .C_SetPIN = nullptr,

    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = nullptr,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = nullptr,
    .C_SetOperationState = nullptr,

    .C_Login = C_Login,
    .C_Logout = nullptr,

    .C_CreateObject = nullptr,
    .C_CopyObject = nullptr,
    .C_DestroyObject = nullptr,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = nullptr,

    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,

    .C_EncryptInit = nullptr,
    .C_Encrypt = nullptr,
    .C_EncryptUpdate = nullptr,
    .C_EncryptFinal = nullptr,

    .C_DecryptInit = nullptr,
    .C_Decrypt = nullptr,
    .C_DecryptUpdate = nullptr,
    .C_DecryptFinal = nullptr,

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

    .C_GenerateKey = nullptr,
    .C_GenerateKeyPair = nullptr,

    .C_WrapKey = nullptr,
    .C_UnwrapKey = nullptr,
    .C_DeriveKey = nullptr,

    .C_SeedRandom = nullptr,
    .C_GenerateRandom = nullptr,

    .C_GetFunctionStatus = nullptr,
    .C_CancelFunction = nullptr,

    .C_WaitForSlotEvent = nullptr
};

extern "C"
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    *ppFunctionList = &function_list;
    return CKR_OK;
}

extern "C"
CK_RV C_OpenSession(
    CK_SLOT_ID slotID,
    CK_FLAGS flags,
    void* pApplication,
    CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession
) {
    *phSession = 1;
    return CKR_OK;
}