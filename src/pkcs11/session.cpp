#include "pkcs11_state.h"

#include <crypto/aes.h>
#include <crypto/xor.h>
#include <storage/disk.h>

#include <map>
#include <mutex>

#include <openssl/evp.h>

namespace {
constexpr CK_SLOT_ID kSlotId = 1;

std::mutex g_sessions_mutex;
std::map<CK_SESSION_HANDLE, Pkcs11SessionState> g_sessions;
CK_SESSION_HANDLE g_next_session = 1;
bool g_token_user_logged_in = false;
std::string g_token_pin;

bool pin_unlocks_private_key(const std::string& pin)
{
    auto B_enc = load_file("B.enc");
    auto C_enc = load_file("C.enc");
    auto B = aes_decrypt(B_enc, pin);
    auto C = aes_decrypt(C_enc, pin);
    auto private_der = xor_data(B, C);

    const unsigned char* p = private_der.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, private_der.size());
    if (!pkey)
        return false;

    EVP_PKEY_free(pkey);
    return true;
}
}

Pkcs11SessionState* pkcs11_get_session(CK_SESSION_HANDLE handle)
{
    auto it = g_sessions.find(handle);
    if (it == g_sessions.end())
        return nullptr;
    return &it->second;
}

bool pkcs11_session_logged_in(CK_SESSION_HANDLE handle)
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto* session = pkcs11_get_session(handle);
    return session && session->user_logged_in;
}

std::string pkcs11_session_pin(CK_SESSION_HANDLE handle)
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto* session = pkcs11_get_session(handle);
    return session ? session->pin : std::string();
}

void pkcs11_reset_sessions()
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    g_sessions.clear();
    g_next_session = 1;
    g_token_user_logged_in = false;
    g_token_pin.clear();
}

extern "C" {

CK_RV C_OpenSession(CK_SLOT_ID slotID,
                    CK_FLAGS flags,
                    CK_VOID_PTR,
                    CK_NOTIFY,
                    CK_SESSION_HANDLE_PTR phSession)
{
    if (!phSession)
        return CKR_ARGUMENTS_BAD;

    if (slotID != kSlotId)
        return CKR_SLOT_ID_INVALID;

    if ((flags & CKF_SERIAL_SESSION) == 0)
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    std::lock_guard<std::mutex> lock(g_sessions_mutex);

    CK_SESSION_HANDLE handle = g_next_session++;
    Pkcs11SessionState session;
    session.handle = handle;
    session.slot_id = slotID;
    session.flags = flags;
    session.user_logged_in = g_token_user_logged_in;
    session.pin = g_token_pin;

    g_sessions.emplace(handle, std::move(session));
    *phSession = handle;

    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto erased = g_sessions.erase(hSession);
    return erased ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (slotID != kSlotId)
        return CKR_SLOT_ID_INVALID;

    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    for (auto it = g_sessions.begin(); it != g_sessions.end();) {
        if (it->second.slot_id == slotID)
            it = g_sessions.erase(it);
        else
            ++it;
    }
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->slotID = session->slot_id;
    pInfo->flags = session->flags;

    const bool rw = (session->flags & CKF_RW_SESSION) != 0;
    if (session->user_logged_in)
        pInfo->state = rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    else
        pInfo->state = rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;

    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,
              CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin,
              CK_ULONG ulPinLen)
{
    if (userType != CKU_USER)
        return CKR_USER_TYPE_INVALID;

    if (!pPin && ulPinLen != 0)
        return CKR_ARGUMENTS_BAD;

    std::string pin(reinterpret_cast<char*>(pPin), ulPinLen);

    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        auto* session = pkcs11_get_session(hSession);
        if (!session)
            return CKR_SESSION_HANDLE_INVALID;
        if (g_token_user_logged_in)
            return CKR_USER_ALREADY_LOGGED_IN;
    }

    try {
        if (!pin_unlocks_private_key(pin))
            return CKR_PIN_INCORRECT;
    } catch (...) {
        return CKR_PIN_INCORRECT;
    }

    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    if (!pkcs11_get_session(hSession))
        return CKR_SESSION_HANDLE_INVALID;

    g_token_user_logged_in = true;
    g_token_pin = pin;
    for (auto& item : g_sessions) {
        item.second.user_logged_in = true;
        item.second.pin = pin;
    }
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto* session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!g_token_user_logged_in)
        return CKR_USER_NOT_LOGGED_IN;

    g_token_user_logged_in = false;
    g_token_pin.clear();
    for (auto& item : g_sessions) {
        item.second.user_logged_in = false;
        item.second.pin.clear();
        item.second.sign_active = false;
        item.second.sign_key_der.clear();
        item.second.encrypt_active = false;
        item.second.encrypt_key_der.clear();
        item.second.decrypt_active = false;
        item.second.decrypt_key_der.clear();
    }
    return CKR_OK;
}

}
