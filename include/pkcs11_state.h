#pragma once

#include "pkcs11_wrapper.h"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct Pkcs11SessionState
{
    CK_SESSION_HANDLE handle = 0;
    CK_SLOT_ID slot_id = 0;
    CK_FLAGS flags = 0;
    bool authenticated = false;
    CK_USER_TYPE login_type = CK_UNAVAILABLE_INFORMATION;
    std::vector<unsigned char> auth_key;
    std::string partition = "default";
    bool sign_active = false;
    CK_OBJECT_HANDLE sign_key_handle = 0;
    CK_MECHANISM_TYPE sign_mechanism = 0;
    bool encrypt_active = false;
    CK_OBJECT_HANDLE encrypt_key_handle = 0;
    CK_MECHANISM_TYPE encrypt_mechanism = 0;
    bool decrypt_active = false;
    CK_OBJECT_HANDLE decrypt_key_handle = 0;
    CK_MECHANISM_TYPE decrypt_mechanism = 0;
    bool find_active = false;
    size_t find_index = 0;
    bool find_match_private = true;
    bool find_match_public = true;
    std::vector<CK_OBJECT_HANDLE> find_results;
};

extern std::mutex g_sessions_mutex;
extern std::unordered_map<CK_SESSION_HANDLE, std::shared_ptr<Pkcs11SessionState>> g_sessions;

std::shared_ptr<Pkcs11SessionState> pkcs11_get_session(CK_SESSION_HANDLE handle);
void pkcs11_reset_sessions();
void pkcs11_clear_session_state(Pkcs11SessionState& session);
