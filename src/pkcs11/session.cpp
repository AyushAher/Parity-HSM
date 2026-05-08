#include "pkcs11_state.h"

#include "parity_hsm/secure_memory.h"
#include "parity_hsm/vault.h"

#include <mutex>
#include <unordered_map>

std::mutex g_sessions_mutex;
std::unordered_map<CK_SESSION_HANDLE, std::shared_ptr<Pkcs11SessionState>> g_sessions;

namespace
{
constexpr CK_SLOT_ID kSlotId = 1;
CK_SESSION_HANDLE g_next_session = 1;
bool g_token_authenticated = false;
CK_USER_TYPE g_token_login_type = CK_UNAVAILABLE_INFORMATION;
std::vector<unsigned char> g_token_auth_key;

std::string current_partition()
{
    if (const char* env = std::getenv("PARITY_HSM_PARTITION"); env && *env)
        return env;
    return "default";
}

std::shared_ptr<Pkcs11SessionState> find_session_unlocked(CK_SESSION_HANDLE handle)
{
    auto it = g_sessions.find(handle);
    if (it == g_sessions.end())
        return nullptr;
    return it->second;
}

bool pin_unlocks_key(CK_USER_TYPE user_type, const std::string& pin)
{
    try {
        auto auth_key = hsm_vault_authenticate(user_type, pin);
        secure_clear(auth_key);
        return true;
    } catch (...) {
        return false;
    }
}
}

std::shared_ptr<Pkcs11SessionState> pkcs11_get_session(CK_SESSION_HANDLE handle)
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    return find_session_unlocked(handle);
}

void pkcs11_clear_session_state(Pkcs11SessionState& session)
{
    session.authenticated = false;
    session.login_type = CK_UNAVAILABLE_INFORMATION;
    secure_clear(session.auth_key);
    session.sign_active = false;
    session.sign_key_handle = 0;
    session.sign_mechanism = 0;
    session.encrypt_active = false;
    session.encrypt_key_handle = 0;
    session.encrypt_mechanism = 0;
    session.decrypt_active = false;
    session.decrypt_key_handle = 0;
    session.decrypt_mechanism = 0;
    session.find_active = false;
    session.find_index = 0;
    session.find_results.clear();
}

void pkcs11_reset_sessions()
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    for (auto& [_, session] : g_sessions)
        pkcs11_clear_session_state(*session);
    g_sessions.clear();
    g_next_session = 1;
    g_token_authenticated = false;
    g_token_login_type = CK_UNAVAILABLE_INFORMATION;
    secure_clear(g_token_auth_key);
}

extern "C"
{
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
    auto session = std::make_shared<Pkcs11SessionState>();
    session->handle = g_next_session++;
    session->slot_id = slotID;
    session->flags = flags;
    session->partition = current_partition();
    if (g_token_authenticated) {
        session->authenticated = true;
        session->login_type = g_token_login_type;
        session->auth_key = g_token_auth_key;
    }

    g_sessions.emplace(session->handle, session);
    *phSession = session->handle;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto it = g_sessions.find(hSession);
    if (it == g_sessions.end())
        return CKR_SESSION_HANDLE_INVALID;
    pkcs11_clear_session_state(*it->second);
    g_sessions.erase(it);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (slotID != kSlotId)
        return CKR_SLOT_ID_INVALID;

    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    for (auto it = g_sessions.begin(); it != g_sessions.end();) {
        pkcs11_clear_session_state(*it->second);
        it = g_sessions.erase(it);
    }
    g_token_authenticated = false;
    g_token_login_type = CK_UNAVAILABLE_INFORMATION;
    secure_clear(g_token_auth_key);
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!pInfo)
        return CKR_ARGUMENTS_BAD;

    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->slotID = session->slot_id;
    pInfo->flags = session->flags;

    const bool rw = (session->flags & CKF_RW_SESSION) != 0;
    if (!session->authenticated)
        pInfo->state = rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    else if (session->login_type == CKU_SO)
        pInfo->state = CKS_RW_SO_FUNCTIONS;
    else
        pInfo->state = rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;

    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,
              CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin,
              CK_ULONG ulPinLen)
{
    if (userType != CKU_USER && userType != CKU_SO)
        return CKR_USER_TYPE_INVALID;
    if (!pPin && ulPinLen != 0)
        return CKR_ARGUMENTS_BAD;

    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;

    std::string pin(reinterpret_cast<char*>(pPin), ulPinLen);
    if (!hsm_vault_exists()) {
        if (userType == CKU_USER)
            hsm_vault_import_legacy_if_needed(pin);
        else
            return CKR_PIN_INCORRECT;
    }

    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        if (g_token_authenticated) {
            if (g_token_login_type == userType)
                return CKR_USER_ALREADY_LOGGED_IN;
            return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
        }
    }

    if (!pin_unlocks_key(userType, pin))
        return CKR_PIN_INCORRECT;

    auto auth_key = hsm_vault_authenticate(userType, pin);
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        g_token_authenticated = true;
        g_token_login_type = userType;
        g_token_auth_key = auth_key;
        for (auto& [_, item] : g_sessions) {
            pkcs11_clear_session_state(*item);
            item->authenticated = true;
            item->login_type = userType;
            item->auth_key = auth_key;
        }
    }

    secure_clear(pin);
    secure_clear(auth_key);
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    auto session = pkcs11_get_session(hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;
    if (!session->authenticated)
        return CKR_USER_NOT_LOGGED_IN;

    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    g_token_authenticated = false;
    g_token_login_type = CK_UNAVAILABLE_INFORMATION;
    secure_clear(g_token_auth_key);
    for (auto& [_, item] : g_sessions)
        pkcs11_clear_session_state(*item);
    return CKR_OK;
}
}
