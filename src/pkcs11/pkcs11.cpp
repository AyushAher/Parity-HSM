#include "pkcs11_wrapper.h"
#include <vector>
#include <cstring>
#include <iostream>

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

// --- SLOT LIST ---
CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                    CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount) {

    if (!pulCount) return CKR_ARGUMENTS_BAD;

    if (!pSlotList) {
        *pulCount = 1;
        return CKR_OK;
    }

    pSlotList[0] = 0;
    *pulCount = 1;

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

CK_RV C_Login(CK_SESSION_HANDLE session,
              CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin,
              CK_ULONG ulPinLen) {

    std::cout << "[PKCS11] Login\n";
    return CKR_OK;
}CK_FUNCTION_LIST function_list = {
    .version = {2, 40},

    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = nullptr,
    .C_GetFunctionList = C_GetFunctionList,

    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = nullptr,
    .C_GetTokenInfo = nullptr,
    .C_GetMechanismList = nullptr,
    .C_GetMechanismInfo = nullptr,
    .C_InitToken = nullptr,
    .C_InitPIN = nullptr,
    .C_SetPIN = nullptr,

    .C_OpenSession = C_OpenSession,
    .C_CloseSession = nullptr,
    .C_CloseAllSessions = nullptr,
    .C_GetSessionInfo = nullptr,
    .C_GetOperationState = nullptr,
    .C_SetOperationState = nullptr,

    .C_Login = C_Login,
    .C_Logout = nullptr,

    .C_CreateObject = nullptr,
    .C_CopyObject = nullptr,
    .C_DestroyObject = nullptr,
    .C_GetObjectSize = nullptr,
    .C_GetAttributeValue = nullptr,
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