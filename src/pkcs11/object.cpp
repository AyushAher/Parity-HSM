#include "pkcs11_wrapper.h"
#include <cstring>

static CK_OBJECT_HANDLE key_handle = 1;
static bool object_returned = false;

extern "C"
CK_RV C_GetSessionInfo(
    CK_SESSION_HANDLE,
    CK_SESSION_INFO_PTR pInfo
) {
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(CK_SESSION_INFO));
    pInfo->state = CKS_RW_USER_FUNCTIONS;
    pInfo->flags = CKF_SERIAL_SESSION;

    return CKR_OK;
}

extern "C"
CK_RV C_CloseSession(CK_SESSION_HANDLE session) {
    return CKR_OK;
}

extern "C"
CK_RV C_GetObjectSize(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize
) {
    if (!pulSize)
        return CKR_ARGUMENTS_BAD;

    if (hObject != 1)
        return CKR_OBJECT_HANDLE_INVALID;

    *pulSize = 256; // fake size (RSA key)
    return CKR_OK;
}


extern "C" {

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE,
                        CK_ATTRIBUTE_PTR,
                        CK_ULONG) {
    object_returned = false;
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE,
                    CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount,
                    CK_ULONG_PTR pulObjectCount) {

    if (!phObject || !pulObjectCount)
        return CKR_ARGUMENTS_BAD;

    if (object_returned) {
        *pulObjectCount = 0;
        return CKR_OK;
    }

    if (ulMaxObjectCount > 0) {
        phObject[0] = key_handle;
        *pulObjectCount = 1;
        object_returned = true;
    } else {
        *pulObjectCount = 0;
    }

    return CKR_OK;
}
}
extern "C"
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session) {
    // reset state safely
    object_returned = false;
    return CKR_OK;
}


extern "C"
CK_RV C_GetAttributeValue(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
) {
    if (!pTemplate)
        return CKR_ARGUMENTS_BAD;
    if (hObject != key_handle)
        return CKR_OBJECT_HANDLE_INVALID;
    for (CK_ULONG i = 0; i < ulCount; i++) {

        void* out = pTemplate[i].pValue;
        CK_ULONG* len = &pTemplate[i].ulValueLen;

        switch (pTemplate[i].type) {

        case CKA_CLASS: {
            CK_OBJECT_CLASS val = CKO_PRIVATE_KEY;
            if (!out) {
                *len = sizeof(val);
            } else if (*len >= sizeof(val)) {
                memcpy(out, &val, sizeof(val));
                *len = sizeof(val);
            } else return CKR_BUFFER_TOO_SMALL;
            break;
        }

        case CKA_KEY_TYPE: {
            CK_KEY_TYPE val = CKK_RSA;
            if (!out) {
                *len = sizeof(val);
            } else if (*len >= sizeof(val)) {
                memcpy(out, &val, sizeof(val));
                *len = sizeof(val);
            } else return CKR_BUFFER_TOO_SMALL;
            break;
        }

        case CKA_ID: {
            const char val[] = "01";
            size_t sz = sizeof(val) - 1;

            if (!out) {
                *len = sz;
            } else if (*len >= sz) {
                memcpy(out, val, sz);
                *len = sz;
            } else return CKR_BUFFER_TOO_SMALL;
            break;
        }

        case CKA_LABEL: {
            const char val[] = "ParityKey";
            size_t sz = sizeof(val) - 1;

            if (!out) {
                *len = sz;
            } else if (*len >= sz) {
                memcpy(out, val, sz);
                *len = sz;
            } else return CKR_BUFFER_TOO_SMALL;
            break;
        }
        case CKA_TOKEN: {
            CK_BBOOL val = CK_TRUE;
            if (!out) *len = sizeof(val);
            else if (*len >= sizeof(val)) {
                memcpy(out, &val, sizeof(val));
                *len = sizeof(val);
            } else return CKR_BUFFER_TOO_SMALL;
            break;
        }

        case CKA_PRIVATE: {
            CK_BBOOL val = CK_TRUE;
            if (!out) *len = sizeof(val);
            else if (*len >= sizeof(val)) {
                memcpy(out, &val, sizeof(val));
                *len = sizeof(val);
            } else return CKR_BUFFER_TOO_SMALL;
            break;
        }

        case CKA_SIGN: {
            CK_BBOOL val = CK_TRUE;
            if (!out) *len = sizeof(val);
            else if (*len >= sizeof(val)) {
                memcpy(out, &val, sizeof(val));
                *len = sizeof(val);
            } else return CKR_BUFFER_TOO_SMALL;
            break;
        }

        default:
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            break;
        }
    }

    return CKR_OK;
}