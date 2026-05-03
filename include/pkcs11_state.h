#pragma once
#include "pkcs11_wrapper.h"

#include <string>
#include <vector>

struct Pkcs11SessionState
{
    CK_SESSION_HANDLE handle = 0;
    CK_SLOT_ID slot_id = 0;
    CK_FLAGS flags = 0;
    bool user_logged_in = false;
    std::string pin;
    bool sign_active = false;
    CK_OBJECT_HANDLE sign_key_handle = 0;
    CK_MECHANISM_TYPE sign_mechanism = 0;
    std::vector<unsigned char> sign_key_der;
    bool encrypt_active = false;
    CK_MECHANISM_TYPE encrypt_mechanism = 0;
    std::vector<unsigned char> encrypt_key_der;
    bool decrypt_active = false;
    CK_MECHANISM_TYPE decrypt_mechanism = 0;
    std::vector<unsigned char> decrypt_key_der;
    bool find_active = false;
    int find_index = 0;
    bool find_match_private = true;
    bool find_match_public = true;
    std::vector<CK_OBJECT_HANDLE> find_results;
};

Pkcs11SessionState *pkcs11_get_session(CK_SESSION_HANDLE handle);
bool pkcs11_session_logged_in(CK_SESSION_HANDLE handle);
std::string pkcs11_session_pin(CK_SESSION_HANDLE handle);
void pkcs11_reset_sessions();
