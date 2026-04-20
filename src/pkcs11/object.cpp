#include "pkcs11_wrapper.h"
#include <vector>
#include <cstring>

static CK_OBJECT_HANDLE fake_key = 1;

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session,
                        CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount) {
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount,
                    CK_ULONG_PTR pulObjectCount) {

    if (ulMaxObjectCount > 0) {
        phObject[0] = fake_key;
        *pulObjectCount = 1;
    }

    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session) {
    return CKR_OK;
}